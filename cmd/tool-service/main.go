package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	tsauth "github.com/tailscale-portfolio/identity-agent-poc/internal/auth0"
)

type accessRecord struct {
	UserID      string    `json:"user_id"`
	Permissions []string  `json:"permissions"`
	GrantedAt   time.Time `json:"granted_at"`
	GrantedBy   string    `json:"granted_by"`
}

type memoryStore struct {
	mu      sync.RWMutex
	records []accessRecord
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		records: make([]accessRecord, 0),
	}
}

type authConfig struct {
	Domain      string
	Audience    string
	Scope       string
	RolesClaim  string
	HTTPTimeout time.Duration
}

func loadAuthConfig() (authConfig, error) {
	cfg := authConfig{
		Domain:      os.Getenv("AUTH0_DOMAIN"),
		Audience:    os.Getenv("AUTH0_AUDIENCE"),
		Scope:       envOrDefault("AUTH0_TOOL_SCOPE", "tool.access:grant"),
		RolesClaim:  os.Getenv("AUTH0_ROLES_CLAIM"),
		HTTPTimeout: 10 * time.Second,
	}
	if cfg.Domain == "" || cfg.Audience == "" {
		return cfg, errors.New("AUTH0_DOMAIN and AUTH0_AUDIENCE are required")
	}
	return cfg, nil
}

func (s *memoryStore) grant(userID string, perms []string, by string) accessRecord {
	perms = dedupePermissions(perms)
	rec := accessRecord{
		UserID:      userID,
		Permissions: perms,
		GrantedAt:   time.Now().UTC(),
		GrantedBy:   by,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return rec
}

func (s *memoryStore) list() []accessRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]accessRecord, len(s.records))
	copy(out, s.records)
	return out
}

type ctxKeyClaims struct{}

type authMiddleware struct {
	validator *tsauth.Validator
	scope     []string
	logger    *slog.Logger
}

func newAuthMiddleware(cfg authConfig, logger *slog.Logger) (*authMiddleware, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTPTimeout)
	defer cancel()
	validator, err := tsauth.NewValidator(ctx, cfg.Domain, cfg.Audience, tsauth.WithRolesClaim(cfg.RolesClaim))
	if err != nil {
		return nil, err
	}
	var scope []string
	if cfg.Scope != "" {
		scope = []string{cfg.Scope}
	}
	return &authMiddleware{validator: validator, scope: scope, logger: logger}, nil
}

func (a *authMiddleware) Close() {
	if a.validator != nil {
		a.validator.Close()
	}
}

func (a *authMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := tsauth.ParseBearer(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		claims, err := a.validator.ValidateToken(r.Context(), token, a.scope)
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyClaims{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func principalFromContext(ctx context.Context) string {
	v, ok := ctx.Value(ctxKeyClaims{}).(*tsauth.Claims)
	if !ok || v == nil {
		return "unknown"
	}
	if v.Subject != "" {
		return v.Subject
	}
	return "unknown"
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	authConfig, err := loadAuthConfig()
	if err != nil {
		logger.Error("auth configuration error", "error", err)
		os.Exit(1)
	}
	authMW, err := newAuthMiddleware(authConfig, logger)
	if err != nil {
		logger.Error("failed to initialise auth0 validator", "error", err)
		os.Exit(1)
	}
	listenAddr := envOrDefault("TOOL_LISTEN_ADDR", ":8090")
	store := newMemoryStore()
	defer authMW.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("POST /access/grant", authMW.Handler(grantHandler(store, logger)))
	mux.Handle("GET /access/list", authMW.Handler(listHandler(store, logger)))

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      loggingMiddleware(logger)(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("tool service listening", "addr", listenAddr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("clean shutdown failed", "error", err)
	}
}

func grantHandler(store *memoryStore, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID      string   `json:"user_id"`
			Permission  string   `json:"permission"`
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		perms := req.Permissions
		if len(perms) == 0 && req.Permission != "" {
			perms = []string{req.Permission}
		}
		if req.UserID == "" || len(perms) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("user_id and permissions are required"))
			return
		}
		principal := principalFromContext(r.Context())
		rec := store.grant(req.UserID, perms, principal)
		logger.Info("granted access", "user_id", rec.UserID, "permissions", rec.Permissions, "granted_by", rec.GrantedBy)
		writeJSON(w, http.StatusCreated, rec)
	})
}

func listHandler(store *memoryStore, _ *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.list())
	})
}

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Info("request complete",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(payload); err != nil {
		log.Printf("error encoding response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func dedupePermissions(perms []string) []string {
	if len(perms) == 0 {
		return perms
	}
	seen := make(map[string]struct{}, len(perms))
	var out []string
	for _, perm := range perms {
		perm = strings.TrimSpace(perm)
		if perm == "" {
			continue
		}
		if _, ok := seen[perm]; ok {
			continue
		}
		seen[perm] = struct{}{}
		out = append(out, perm)
	}
	return out
}
