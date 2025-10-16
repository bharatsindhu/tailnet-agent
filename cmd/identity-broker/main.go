package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale-portfolio/identity-agent-poc/internal/auth0"
	"github.com/tailscale-portfolio/identity-agent-poc/internal/identity"
)

type config struct {
	ListenAddr       string
	Auth0Domain      string
	Auth0Audience    string
	Auth0RolesClaim  string
	IdentityDataPath string
}

func loadConfig() (config, error) {
	cfg := config{
		ListenAddr:       envOrDefault("IDENTITY_BROKER_LISTEN_ADDR", ":8080"),
		Auth0Domain:      os.Getenv("AUTH0_DOMAIN"),
		Auth0Audience:    os.Getenv("AUTH0_AUDIENCE"),
		Auth0RolesClaim:  os.Getenv("AUTH0_ROLES_CLAIM"),
		IdentityDataPath: envOrDefault("IDENTITY_DATA_PATH", filepath.Join("infra", "sample-users.json")),
	}
	if cfg.Auth0Domain == "" {
		return cfg, errors.New("AUTH0_DOMAIN is required")
	}
	if cfg.Auth0Audience == "" {
		return cfg, errors.New("AUTH0_AUDIENCE is required")
	}
	return cfg, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	logger.Info("starting identity broker",
		"listen", cfg.ListenAddr,
		"auth0_audience", cfg.Auth0Audience,
		"roles_claim", cfg.Auth0RolesClaim,
	)

	data, err := os.ReadFile(cfg.IdentityDataPath)
	if err != nil {
		logger.Error("failed to read identity data", "error", err, "path", cfg.IdentityDataPath)
		os.Exit(1)
	}
	provider, err := identity.NewStaticProvider(data)
	if err != nil {
		logger.Error("failed to load identity data", "error", err)
		os.Exit(1)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	validator, err := auth0.NewValidator(ctxTimeout, cfg.Auth0Domain, cfg.Auth0Audience, auth0.WithRolesClaim(cfg.Auth0RolesClaim))
	if err != nil {
		logger.Error("failed to initialise auth0 validator", "error", err)
		os.Exit(1)
	}
	defer validator.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("/v1/identity/users", requireScopes(validator, "identity:search")(http.HandlerFunc(searchUsersHandler(provider))))
	mux.Handle("/v1/identity/users/", requireScopes(validator, "identity:read")(http.HandlerFunc(getUserHandler(provider))))

	handler := requestLogger(logger)(recoveryHandler(mux))

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", "error", err)
		}
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

type ctxKey string

const claimsKey ctxKey = "auth0Claims"
const requestIDKey ctxKey = "requestID"

var requestCounter uint64

func requireScopes(validator *auth0.Validator, scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken, err := auth0.ParseBearer(r.Header.Get("Authorization"))
			if err != nil {
				writeError(w, http.StatusUnauthorized, err)
				return
			}

			claims, err := validator.ValidateToken(r.Context(), rawToken, scopes)
			if err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func claimsFromContext(ctx context.Context) *auth0.Claims {
	if val := ctx.Value(claimsKey); val != nil {
		if claims, ok := val.(*auth0.Claims); ok {
			return claims
		}
	}
	return nil
}

func searchUsersHandler(provider identity.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query().Get("q")
		users, err := provider.SearchUsers(r.Context(), query)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		response := map[string]any{
			"query":       query,
			"resultCount": len(users),
			"users":       users,
			"actor":       actorFromContext(r.Context()),
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func getUserHandler(provider identity.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		const prefix = "/v1/identity/users/"
		id := strings.TrimPrefix(r.URL.Path, prefix)
		id = strings.Trim(id, "/")
		if id == "" || id == "users" {
			writeError(w, http.StatusBadRequest, errors.New("user id required"))
			return
		}

		user, err := provider.GetUser(r.Context(), id)
		if err != nil {
			if errors.Is(err, identity.ErrNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		response := map[string]any{
			"user":  user,
			"actor": actorFromContext(r.Context()),
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	payload := map[string]string{"error": err.Error()}
	writeJSON(w, status, payload)
}

func actorFromContext(ctx context.Context) map[string]any {
	claims := claimsFromContext(ctx)
	if claims == nil {
		return nil
	}

	var scopes []string
	for _, scope := range strings.Split(claims.Scope, " ") {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		scopes = append(scopes, scope)
	}

	return map[string]any{
		"subject": claims.Subject,
		"scopes":  scopes,
		"roles":   claims.Roles,
	}
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := fmt.Sprintf("req-%d", atomic.AddUint64(&requestCounter, 1))
			rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()

			ctx := context.WithValue(r.Context(), requestIDKey, id)
			next.ServeHTTP(rr, r.WithContext(ctx))

			logger.Info("request complete",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rr.status,
				"bytes", rr.size,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
				"request_id", id,
			)
		})
	}
}

func recoveryHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("panic: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if rr.status == 0 {
		rr.status = http.StatusOK
	}
	n, err := rr.ResponseWriter.Write(b)
	rr.size += n
	return n, err
}
