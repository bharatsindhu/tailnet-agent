package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

type config struct {
	BrokerURL     string
	Auth0Domain   string
	Auth0Audience string
	Auth0ClientID string
	Auth0Secret   string
	Scopes        []string
	OpenAIKey     string
	OpenAIModel   string
	OpenAIBaseURL string
	SystemPrompt  string
	Temperature   float64
}

func loadConfig() (config, error) {
	cfg := config{
		BrokerURL:     strings.TrimSpace(os.Getenv("BROKER_URL")),
		Auth0Domain:   strings.TrimSpace(os.Getenv("AUTH0_DOMAIN")),
		Auth0Audience: strings.TrimSpace(os.Getenv("AUTH0_AUDIENCE")),
		Auth0ClientID: strings.TrimSpace(os.Getenv("AUTH0_CLIENT_ID")),
		Auth0Secret:   strings.TrimSpace(os.Getenv("AUTH0_CLIENT_SECRET")),
		OpenAIKey:     strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIModel:   strings.TrimSpace(os.Getenv("OPENAI_MODEL")),
		OpenAIBaseURL: strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		SystemPrompt:  strings.TrimSpace(os.Getenv("AGENT_SYSTEM_PROMPT")),
	}
	if cfg.BrokerURL == "" {
		return cfg, errors.New("BROKER_URL is required (use the tailnet IP e.g. https://100.x.y.z:8080)")
	}
	if cfg.Auth0Domain == "" || cfg.Auth0Audience == "" || cfg.Auth0ClientID == "" || cfg.Auth0Secret == "" {
		return cfg, errors.New("AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET are required")
	}
	scopeEnv := strings.TrimSpace(os.Getenv("AUTH0_SCOPES"))
	if scopeEnv == "" {
		scopeEnv = "identity:read identity:search"
	}
	cfg.Scopes = strings.Fields(scopeEnv)

	if temp := strings.TrimSpace(os.Getenv("OPENAI_TEMPERATURE")); temp != "" {
		if v, err := strconv.ParseFloat(temp, 32); err == nil {
			cfg.Temperature = v
		}
	}

	return cfg, nil
}

func main() {
	var (
		userID  = flag.String("user", "", "User ID or email to fetch")
		query   = flag.String("query", "", "Free-text search query")
		noLLM   = flag.Bool("no-llm", false, "Disable LLM summarisation, even if credentials are present")
		timeout = flag.Duration("timeout", 20*time.Second, "Timeout for Auth0 and broker requests")
	)
	flag.Parse()

	if *userID == "" && *query == "" {
		fmt.Println("Provide --user or --query to execute an identity lookup.")
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("configuration error:", err)
		os.Exit(1)
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

	client := &http.Client{Timeout: *timeout}

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
