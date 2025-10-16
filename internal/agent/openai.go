package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tailscale-portfolio/identity-agent-poc/internal/identity"
)

// OpenAIConfig configures an OpenAI-compatible chat completion endpoint.
type OpenAIConfig struct {
	APIKey       string
	BaseURL      string
	Model        string
	Temperature  float32
	HTTPClient   *http.Client
	SystemPrompt string
}

// OpenAISummarizer implements Summarizer using the Chat Completions API.
type OpenAISummarizer struct {
	cfg        OpenAIConfig
	httpClient *http.Client
}

// NewOpenAISummarizer validates configuration and constructs a client.
func NewOpenAISummarizer(cfg OpenAIConfig) (*OpenAISummarizer, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("agent: openai api key missing")
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com"
	}
	if cfg.SystemPrompt == "" {
		cfg.SystemPrompt = "You are a Tailscale solutions engineer describing tailnet identities to other humans."
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	return &OpenAISummarizer{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

func (s *OpenAISummarizer) Summarize(ctx context.Context, user identity.User) (string, error) {
	payload := struct {
		Model       string      `json:"model"`
		Temperature float32     `json:"temperature,omitempty"`
		Messages    []chatEntry `json:"messages"`
	}{
		Model:       s.cfg.Model,
		Temperature: s.cfg.Temperature,
		Messages: []chatEntry{
			{Role: "system", Content: s.cfg.SystemPrompt},
			{Role: "user", Content: buildPrompt(user)},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("agent: marshal openai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.cfg.BaseURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("agent: new openai request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agent: openai call failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent: openai returned status %d", res.StatusCode)
	}

	var reply chatCompletionResponse
	if err := json.NewDecoder(res.Body).Decode(&reply); err != nil {
		return "", fmt.Errorf("agent: decode openai response: %w", err)
	}
	if len(reply.Choices) == 0 || reply.Choices[0].Message.Content == "" {
		return "", errors.New("agent: openai response missing content")
	}

	return strings.TrimSpace(reply.Choices[0].Message.Content), nil
}

type chatEntry struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func buildPrompt(user identity.User) string {
	payload, _ := json.MarshalIndent(user, "", "  ")
	return fmt.Sprintf("Summarize the following tailnet identity record in 3 sentences or fewer:\n\n%s", payload)
}
