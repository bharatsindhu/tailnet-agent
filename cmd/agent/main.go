package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale-portfolio/identity-agent-poc/internal/agent"
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

type config struct {
	BrokerURL        string
	Auth0Domain      string
	Auth0Audience    string
	Auth0ClientID    string
	Auth0Secret      string
	Scopes           []string
	ToolServiceURL   string
	OpenAIKey        string
	OpenAIModel      string
	OpenAIBaseURL    string
	SystemPrompt     string
	Temperature      float64
	GrantGroup       string
	GrantPermissions []string
}

func loadConfig() (config, error) {
	cfg := config{
		BrokerURL:      strings.TrimSpace(os.Getenv("BROKER_URL")),
		Auth0Domain:    strings.TrimSpace(os.Getenv("AUTH0_DOMAIN")),
		Auth0Audience:  strings.TrimSpace(os.Getenv("AUTH0_AUDIENCE")),
		Auth0ClientID:  strings.TrimSpace(os.Getenv("AUTH0_CLIENT_ID")),
		Auth0Secret:    strings.TrimSpace(os.Getenv("AUTH0_CLIENT_SECRET")),
		ToolServiceURL: strings.TrimSpace(os.Getenv("TOOL_SERVICE_URL")),
		OpenAIKey:      strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIModel:    strings.TrimSpace(os.Getenv("OPENAI_MODEL")),
		OpenAIBaseURL:  strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		SystemPrompt:   strings.TrimSpace(os.Getenv("AGENT_SYSTEM_PROMPT")),
	}
	if cfg.BrokerURL == "" {
		return cfg, errors.New("BROKER_URL is required (use the tailnet IP e.g. https://100.x.y.z:8080)")
	}
	if cfg.Auth0Domain == "" || cfg.Auth0Audience == "" || cfg.Auth0ClientID == "" || cfg.Auth0Secret == "" {
		return cfg, errors.New("AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET are required")
	}
	scopeEnv := strings.TrimSpace(os.Getenv("AUTH0_SCOPES"))
	if scopeEnv == "" {
		scopeEnv = "identity:read identity:search tool.access:grant"
	}
	cfg.Scopes = strings.Fields(scopeEnv)

	permsEnv := strings.TrimSpace(os.Getenv("AGENT_GRANT_PERMISSIONS"))
	if permsEnv == "" {
		// Backwards compatibility
		permsEnv = strings.TrimSpace(os.Getenv("AGENT_GRANT_PERMISSION"))
	}
	if permsEnv == "" {
		permsEnv = "toolx:read toolx:write toolx:update"
	}
	cfg.GrantPermissions = uniqueFields(permsEnv)

	if temp := strings.TrimSpace(os.Getenv("OPENAI_TEMPERATURE")); temp != "" {
		if v, err := strconv.ParseFloat(temp, 32); err == nil {
			cfg.Temperature = v
		}
	}

	return cfg, nil
}

func main() {
	var (
		userID               = flag.String("user", "", "User ID or email to fetch")
		query                = flag.String("query", "", "Free-text search query")
		noLLM                = flag.Bool("no-llm", false, "Disable LLM summarisation, even if credentials are present")
		timeout              = flag.Duration("timeout", 20*time.Second, "Timeout for Auth0 and broker requests")
		retries              = flag.Int("retries", 8, "Number of times to retry broker contact on startup")
		toolURL              = flag.String("tool-url", "", "Tailnet URL of the tool service (e.g. http://tool-service.tail.ts.net:8090)")
		grantGroup           = flag.String("grant-group", "", "Grant access to every identity in the specified group")
		grantPermissionsFlag = flag.String("grant-permissions", "", "Space-separated permissions to grant via the tool service")
	)
	flag.Parse()

	if *userID == "" && *query == "" && *grantGroup == "" {
		fmt.Println("Provide --user, --query, or --grant-group to execute an action.")
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("configuration error:", err)
		os.Exit(1)
	}
	if *toolURL != "" {
		cfg.ToolServiceURL = strings.TrimSpace(*toolURL)
	}
	cfg.GrantGroup = strings.TrimSpace(*grantGroup)
	if perms := strings.TrimSpace(*grantPermissionsFlag); perms != "" {
		cfg.GrantPermissions = uniqueFields(perms)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	authClient := &auth0.Client{
		Domain:       cfg.Auth0Domain,
		Audience:     cfg.Auth0Audience,
		ClientID:     cfg.Auth0ClientID,
		ClientSecret: cfg.Auth0Secret,
	}
	token, err := authClient.ClientCredentials(ctx, cfg.Scopes)
	if err != nil {
		logger.Error("failed to exchange Auth0 client credentials", "error", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: *timeout}

	if cfg.GrantGroup != "" {
		if cfg.ToolServiceURL == "" {
			logger.Error("grant-group requested but TOOL_SERVICE_URL is not configured")
			os.Exit(1)
		}
		if err := runGrantGroup(ctx, client, cfg, token.AccessToken, logger); err != nil {
			logger.Error("grant-group operation failed", "error", err)
			os.Exit(1)
		}
	}

	summarizer := agent.Summarizer(agent.StaticSummarizer{})
	if cfg.OpenAIKey != "" && !*noLLM {
		openaiSummarizer, err := agent.NewOpenAISummarizer(agent.OpenAIConfig{
			APIKey:       cfg.OpenAIKey,
			BaseURL:      cfg.OpenAIBaseURL,
			Model:        cfg.OpenAIModel,
			Temperature:  float32(cfg.Temperature),
			SystemPrompt: cfg.SystemPrompt,
		})
		if err != nil {
			logger.Warn("failed to initialise OpenAI summariser, falling back to static output", "error", err)
		} else {
			summarizer = openaiSummarizer
		}
	}

	if err := waitForBroker(ctx, client, cfg.BrokerURL, *retries, 2*time.Second); err != nil {
		logger.Error("broker readiness check failed", "error", err)
		os.Exit(1)
	}

	if *userID != "" {
		if err := runGetUser(ctx, client, cfg.BrokerURL, strings.TrimSpace(*userID), token.AccessToken, summarizer); err != nil {
			logger.Error("user lookup failed", "error", err)
			os.Exit(1)
		}
	}

	if *query != "" {
		if err := runSearch(ctx, client, cfg.BrokerURL, strings.TrimSpace(*query), token.AccessToken, summarizer); err != nil {
			logger.Error("search failed", "error", err)
			os.Exit(1)
		}
	}
}

func runGetUser(ctx context.Context, httpClient *http.Client, baseURL, identifier, token string, summarizer agent.Summarizer) error {
	reqURL, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return fmt.Errorf("agent: parse broker url: %w", err)
	}
	reqURL.Path = strings.TrimSuffix(reqURL.Path, "/") + "/v1/identity/users/" + url.PathEscape(identifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return fmt.Errorf("agent: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent: call broker: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: broker returned %d", res.StatusCode)
	}

	var payload struct {
		User identity.User `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return fmt.Errorf("agent: decode broker response: %w", err)
	}

	printUserSummary(ctx, payload.User, summarizer)
	return nil
}

func runSearch(ctx context.Context, httpClient *http.Client, baseURL, query, token string, summarizer agent.Summarizer) error {
	reqURL, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return fmt.Errorf("agent: parse broker url: %w", err)
	}
	reqURL.Path = strings.TrimSuffix(reqURL.Path, "/") + "/v1/identity/users"
	q := reqURL.Query()
	q.Set("q", query)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return fmt.Errorf("agent: build search request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent: call broker: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: broker returned %d", res.StatusCode)
	}

	var payload struct {
		Users []identity.User `json:"users"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return fmt.Errorf("agent: decode search response: %w", err)
	}

	for _, user := range payload.Users {
		printUserSummary(ctx, user, summarizer)
	}
	return nil
}

type toolGrantRequest struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

func runGrantGroup(ctx context.Context, httpClient *http.Client, cfg config, token string, logger *slog.Logger) error {
	groupQuery := fmt.Sprintf("group:%s", cfg.GrantGroup)
	users, err := fetchUsers(ctx, httpClient, cfg.BrokerURL, groupQuery, token)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Printf("No identities found in group %s\n", cfg.GrantGroup)
		return nil
	}

	toolEndpoint := strings.TrimSuffix(cfg.ToolServiceURL, "/") + "/access/grant"
	fmt.Printf("Granting %s to %d identity(ies) in group %s via %s\n", strings.Join(cfg.GrantPermissions, ", "), len(users), cfg.GrantGroup, toolEndpoint)

	success := 0
	for _, user := range users {
		payload := toolGrantRequest{UserID: user.ID, Permissions: cfg.GrantPermissions}
		body, err := json.Marshal(payload)
		if err != nil {
			logger.Error("marshal grant payload failed", "user_id", user.ID, "error", err)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, toolEndpoint, bytes.NewReader(body))
		if err != nil {
			logger.Error("build tool request failed", "user_id", user.ID, "error", err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			logger.Error("tool request failed", "user_id", user.ID, "error", err)
			continue
		}
		respBody, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode >= 300 {
			logger.Error("tool service returned error", "user_id", user.ID, "status", res.StatusCode, "response", strings.TrimSpace(string(respBody)))
			continue
		}
		success++
		fmt.Printf(" - granted %s (%s)\n", user.DisplayName, user.Email)
	}

	fmt.Printf("Grant operation complete: %d/%d succeeded\n", success, len(users))
	return nil
}

func fetchUsers(ctx context.Context, httpClient *http.Client, baseURL, query, token string) ([]identity.User, error) {
	reqURL, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("agent: parse broker url: %w", err)
	}
	reqURL.Path = strings.TrimSuffix(reqURL.Path, "/") + "/v1/identity/users"
	q := reqURL.Query()
	q.Set("q", query)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("agent: build search request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: call broker: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: broker returned %d", res.StatusCode)
	}

	var payload struct {
		Users []identity.User `json:"users"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("agent: decode search response: %w", err)
	}
	return payload.Users, nil
}

func printUserSummary(ctx context.Context, user identity.User, summarizer agent.Summarizer) {
	summary, err := summarizer.Summarize(ctx, user)
	if err != nil {
		fmt.Printf("ID: %s  email: %s  roles: %v  devices: %d\n", user.ID, user.Email, user.Roles, len(user.Devices))
		fmt.Println("summary error:", err)
		return
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(summary)
	fmt.Printf("User ID: %s\nEmail: %s\nRoles: %v\nDevices: %d\n", user.ID, user.Email, user.Roles, len(user.Devices))
}

func waitForBroker(ctx context.Context, client *http.Client, baseURL string, attempts int, backoff time.Duration) error {
	if attempts <= 0 {
		attempts = 1
	}
	healthURL, err := brokerHealthURL(baseURL)
	if err != nil {
		return err
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return fmt.Errorf("agent: build health request: %w", err)
		}
		res, err := client.Do(req)
		if err == nil && res.StatusCode < 500 {
			res.Body.Close()
			return nil
		}
		if err == nil {
			res.Body.Close()
			err = fmt.Errorf("healthz returned %d", res.StatusCode)
		}
		lastErr = err
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("unknown broker readiness error")
	}
	return fmt.Errorf("agent: broker not ready: %w", lastErr)
}

func brokerHealthURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("agent: parse broker url: %w", err)
	}
	u.Path = "/healthz"
	u.RawQuery = ""
	return u.String(), nil
}
