package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client exchanges Auth0 client credentials for access tokens.
type Client struct {
	Domain       string
	Audience     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

// TokenResponse is the response from Auth0's /oauth/token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// ClientCredentials issues a client credential exchange with the provided scopes.
func (c *Client) ClientCredentials(ctx context.Context, scopes []string) (*TokenResponse, error) {
	if c.Domain == "" || c.Audience == "" || c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("auth0: client credentials config incomplete")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", c.Audience)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	endpoint := strings.TrimSuffix(c.Domain, "/") + "/oauth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth0: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth0: token exchange failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth0: token exchange unexpected status %d", res.StatusCode)
	}

	var payload TokenResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("auth0: decode token response: %w", err)
	}

	if payload.AccessToken == "" {
		return nil, errors.New("auth0: empty access token in response")
	}

	return &payload, nil
}
