package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"

	"github.com/tailscale-portfolio/identity-agent-poc/internal/auth0"
	"github.com/tailscale-portfolio/identity-agent-poc/internal/identity"
)

func uniqueFields(input string) []string {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return fields
	}
	seen := make(map[string]struct{}, len(fields))
	var out []string
	for _, f := range fields {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

const (
	stateCookieName   = "_oauth_state"
	sessionCookieName = "_session"
)

type appConfig struct {
	Domain           string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Audience         string
	M2MClientID      string
	M2MClientSecret  string
	BrokerURL        string
	ToolServiceURL   string
	SessionSecret    string
	GroupTarget      string
	GrantPermissions []string
	Scopes           []string
	HTTPTimeout      time.Duration
}

type sessionData struct {
	Subject string
	Email   string
}

type app struct {
	cfg          appConfig
	logger       *slog.Logger
	oauthConfig  *oauth2.Config
	idVerifier   *oidc.IDTokenVerifier
	secureCookie *securecookie.SecureCookie
	httpClient   *http.Client
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("admin-ui configuration error", "error", err)
		os.Exit(1)
	}

	application, err := newApp(cfg, logger)
	if err != nil {
		logger.Error("failed to initialise admin ui", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    envOrDefault("ADMIN_UI_LISTEN_ADDR", ":8100"),
		Handler: application.routes(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("admin-ui listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin-ui server error", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin-ui clean shutdown failed", "error", err)
	}
}

func newApp(cfg appConfig, logger *slog.Logger) (*app, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTPTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{"openid", "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	hashKey := []byte(cfg.SessionSecret)
	blockKey := hashKey
	if len(blockKey) > 32 {
		blockKey = blockKey[:32]
	}
	secure := securecookie.New(hashKey, blockKey)
	secure.SetSerializer(securecookie.JSONEncoder{})

	client := &http.Client{Timeout: cfg.HTTPTimeout}

	return &app{
		cfg:          cfg,
		logger:       logger,
		oauthConfig:  oauthCfg,
		idVerifier:   verifier,
		secureCookie: secure,
		httpClient:   client,
	}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("GET /logout", a.handleLogout)
	mux.Handle("GET /", a.withSession(a.handleHome))
	mux.Handle("POST /grant", a.withSession(a.handleGrant))
	return loggingMiddleware(a.logger)(mux)
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request, session *sessionData) {
	status := r.URL.Query().Get("status")
	data := struct {
		Email       string
		Status      string
		Group       string
		Permissions []string
	}{
		Email:       session.Email,
		Status:      status,
		Group:       a.cfg.GroupTarget,
		Permissions: a.cfg.GrantPermissions,
	}

	if err := homeTemplate.Execute(w, data); err != nil {
		a.logger.Error("render template", "error", err)
	}
}

func (a *app) handleGrant(w http.ResponseWriter, r *http.Request, session *sessionData) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.HTTPTimeout)
	defer cancel()

	token, err := a.fetchM2MToken(ctx)
	if err != nil {
		a.logger.Error("fetch m2m token", "error", err)
		http.Redirect(w, r, "/?status=error", http.StatusSeeOther)
		return
	}

	if err := a.grantGroup(ctx, token); err != nil {
		a.logger.Error("grant group failed", "error", err)
		http.Redirect(w, r, "/?status=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?status=granted", http.StatusSeeOther)
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	if err := a.setStateCookie(w, state); err != nil {
		http.Error(w, "failed to set state", http.StatusInternalServerError)
		return
	}

	authURL := a.oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}
	var expected string
	if err := a.secureCookie.Decode("oauth_state", cookie.Value, &expected); err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != expected {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code missing", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.HTTPTimeout)
	defer cancel()

	token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "id_token missing", http.StatusInternalServerError)
		return
	}
	idToken, err := a.idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token invalid", http.StatusInternalServerError)
		return
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Sub   string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "decode claims", http.StatusInternalServerError)
		return
	}

	session := sessionData{Subject: claims.Sub, Email: claims.Email}
	if err := a.setSessionCookie(w, session); err != nil {
		http.Error(w, "failed to set session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) withSession(next func(http.ResponseWriter, *http.Request, *sessionData)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := a.sessionFromCookie(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, session)
	})
}

func (a *app) sessionFromCookie(r *http.Request) (*sessionData, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	var session sessionData
	if err := a.secureCookie.Decode("session", cookie.Value, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (a *app) setSessionCookie(w http.ResponseWriter, session sessionData) error {
	encoded, err := a.secureCookie.Encode("session", session)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Add(8 * time.Hour),
	})
	return nil
}

func (a *app) setStateCookie(w http.ResponseWriter, state string) error {
	encoded, err := a.secureCookie.Encode("oauth_state", state)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Add(5 * time.Minute),
	})
	return nil
}

func (a *app) fetchM2MToken(ctx context.Context) (string, error) {
	client := &auth0.Client{
		Domain:       a.cfg.Domain,
		Audience:     a.cfg.Audience,
		ClientID:     a.cfg.M2MClientID,
		ClientSecret: a.cfg.M2MClientSecret,
	}
	res, err := client.ClientCredentials(ctx, a.cfg.Scopes)
	if err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

func (a *app) grantGroup(ctx context.Context, token string) error {
	groupQuery := fmt.Sprintf("group:%s", a.cfg.GroupTarget)
	users, err := fetchUsers(ctx, a.httpClient, a.cfg.BrokerURL, groupQuery, token)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}

	endpoint := strings.TrimSuffix(a.cfg.ToolServiceURL, "/") + "/access/grant"
	for _, user := range users {
		payload := toolGrantRequest{UserID: user.ID, Permissions: a.cfg.GrantPermissions}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		res, err := a.httpClient.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode >= 300 {
			return fmt.Errorf("tool service returned %d", res.StatusCode)
		}
	}
	return nil
}

func loadConfig() (appConfig, error) {
	cfg := appConfig{
		Domain:          strings.TrimSpace(os.Getenv("AUTH0_DOMAIN")),
		ClientID:        strings.TrimSpace(os.Getenv("AUTH0_CLIENT_ID")),
		ClientSecret:    strings.TrimSpace(os.Getenv("AUTH0_CLIENT_SECRET")),
		RedirectURI:     strings.TrimSpace(os.Getenv("AUTH0_REDIRECT_URI")),
		Audience:        strings.TrimSpace(os.Getenv("AUTH0_AUDIENCE")),
		M2MClientID:     strings.TrimSpace(os.Getenv("AUTH0_M2M_CLIENT_ID")),
		M2MClientSecret: strings.TrimSpace(os.Getenv("AUTH0_M2M_CLIENT_SECRET")),
		BrokerURL:       strings.TrimSpace(os.Getenv("BROKER_URL")),
		ToolServiceURL:  strings.TrimSpace(os.Getenv("TOOL_SERVICE_URL")),
		SessionSecret:   strings.TrimSpace(os.Getenv("SESSION_SECRET")),
		GroupTarget:     strings.TrimSpace(os.Getenv("TARGET_GROUP")),
		HTTPTimeout:     15 * time.Second,
	}
	if cfg.Domain == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return cfg, errors.New("AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_REDIRECT_URI are required")
	}
	if cfg.Audience == "" || cfg.M2MClientID == "" || cfg.M2MClientSecret == "" {
		return cfg, errors.New("AUTH0_AUDIENCE, AUTH0_M2M_CLIENT_ID, AUTH0_M2M_CLIENT_SECRET are required")
	}
	if cfg.BrokerURL == "" || cfg.ToolServiceURL == "" {
		return cfg, errors.New("BROKER_URL and TOOL_SERVICE_URL are required")
	}
	if cfg.SessionSecret == "" {
		return cfg, errors.New("SESSION_SECRET is required")
	}
	scopeEnv := strings.TrimSpace(os.Getenv("AUTH0_SCOPES"))
	if scopeEnv == "" {
		scopeEnv = "identity:read identity:search tool.access:grant"
	}
	cfg.Scopes = strings.Fields(scopeEnv)
	if cfg.GroupTarget == "" {
		cfg.GroupTarget = "developers"
	}
	permsEnv := strings.TrimSpace(os.Getenv("AGENT_GRANT_PERMISSIONS"))
	if permsEnv == "" {
		permsEnv = strings.TrimSpace(os.Getenv("AGENT_GRANT_PERMISSION"))
	}
	if permsEnv == "" {
		permsEnv = "toolx:read toolx:write toolx:update"
	}
	cfg.GrantPermissions = uniqueFields(permsEnv)
	return cfg, nil
}

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Info("request complete", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "duration_ms", time.Since(start).Milliseconds())
		})
	}
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Helper types reused from agent implementation.

type toolGrantRequest struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

func fetchUsers(ctx context.Context, httpClient *http.Client, baseURL, query, token string) ([]identity.User, error) {
	reqURL, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("admin-ui: parse broker url: %w", err)
	}
	reqURL.Path = strings.TrimSuffix(reqURL.Path, "/") + "/v1/identity/users"
	q := reqURL.Query()
	q.Set("q", query)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("admin-ui: build search request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin-ui: call broker: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin-ui: broker returned %d", res.StatusCode)
	}

	var payload struct {
		Users []identity.User `json:"users"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("admin-ui: decode search response: %w", err)
	}
	return payload.Users, nil
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tailnet Access Admin</title>
    <style>
        body { font-family: sans-serif; margin: 2rem; }
        .card { max-width: 480px; margin: auto; padding: 1.5rem; border: 1px solid #ccc; border-radius: 8px; }
        button { padding: 0.6rem 1rem; font-size: 1rem; }
        .status { margin-bottom: 1rem; color: #2f855a; }
        .status.error { color: #c53030; }
    </style>
</head>
<body>
<div class="card">
    <h2>Tailnet Access Admin</h2>
    <p>Signed in as <strong>{{.Email}}</strong></p>
    {{if eq .Status "granted"}}
        <div class="status">Tool X permissions granted for group {{.Group}}.</div>
    {{else if eq .Status "error"}}
        <div class="status error">Failed to grant access. Check service logs.</div>
    {{end}}
    <form method="POST" action="/grant">
        <p>Grant the following Tool X permissions to all members of <strong>{{.Group}}</strong>:</p>
        <ul>
            {{range .Permissions}}
            <li>{{.}}</li>
            {{end}}
        </ul>
        <button type="submit">Grant Access</button>
    </form>
    <p style="margin-top:1rem;"><a href="/logout">Sign out</a></p>
</div>
</body>
</html>`))
