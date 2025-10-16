package auth0

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Claims represents the subset of Auth0 access-token claims the broker cares about.
type Claims struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	ExpiresAt   int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
	NotBefore   int64    `json:"nbf"`

	raw map[string]any
}

// HasScopes returns true when every scope in required is present in the claim.
func (c *Claims) HasScopes(required []string) bool {
	if len(required) == 0 {
		return true
	}

	available := map[string]struct{}{}
	if c.Scope != "" {
		for _, scope := range strings.Split(c.Scope, " ") {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			available[scope] = struct{}{}
		}
	}
	for _, perm := range c.Permissions {
		available[perm] = struct{}{}
	}

	for _, s := range required {
		if _, ok := available[s]; !ok {
			return false
		}
	}

	return true
}

func (c *Claims) setRaw(raw map[string]any) {
	c.raw = raw
}

func (c *Claims) audienceContains(expected string) bool {
	if c.raw == nil {
		return false
	}
	aud, ok := c.raw["aud"]
	if !ok {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func (c *Claims) expired(now time.Time) bool {
	if c.ExpiresAt == 0 {
		return false
	}
	return now.Unix() > c.ExpiresAt
}

func (c *Claims) beforeNow(now time.Time) bool {
	if c.NotBefore == 0 {
		return false
	}
	return now.Unix() < c.NotBefore
}

// Option configures the Validator.
type Option func(v *Validator)

// WithRolesClaim configures a custom claim key that should be interpreted as roles in the token.
func WithRolesClaim(claim string) Option {
	return func(v *Validator) {
		v.rolesClaim = claim
	}
}

// WithHTTPClient configures a custom HTTP client used for JWKS retrieval.
func WithHTTPClient(c *http.Client) Option {
	return func(v *Validator) {
		v.httpClient = c
	}
}

// WithCacheTTL adjusts how long JWKS keys are cached locally.
func WithCacheTTL(ttl time.Duration) Option {
	return func(v *Validator) {
		v.cacheTTL = ttl
	}
}

// Validator verifies Auth0-issued JWT access tokens.
type Validator struct {
	audience string
	issuer   string
	jwksURL  string

	httpClient *http.Client
	rolesClaim string
	cacheTTL   time.Duration

	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	lastReload time.Time
}

// NewValidator instantiates a Validator and primes a JWKS cache. Domain must be the Auth0 tenant
// base URL (e.g. https://tenant.region.auth0.com).
func NewValidator(ctx context.Context, domain, audience string, opts ...Option) (*Validator, error) {
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" || !strings.HasPrefix(domain, "http") {
		return nil, fmt.Errorf("auth0: invalid domain %q", domain)
	}
	if audience == "" {
		return nil, errors.New("auth0: audience is required")
	}

	val := &Validator{
		audience: audience,
		issuer:   fmt.Sprintf("%s/", domain),
		jwksURL:  fmt.Sprintf("%s/.well-known/jwks.json", domain),
		cacheTTL: 15 * time.Minute,
	}
	for _, opt := range opts {
		opt(val)
	}

	if val.httpClient == nil {
		val.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	if err := val.refreshKeys(ctx); err != nil {
		return nil, err
	}

	return val, nil
}

// Close releases resources held by the validator.
func (v *Validator) Close() {}

// ValidateToken parses and validates a JWT access token. It enforces audience, issuer, expiry, and scopes.
func (v *Validator) ValidateToken(ctx context.Context, token string, requiredScopes []string) (*Claims, error) {
	if token == "" {
		return nil, errors.New("auth0: token is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth0: token format invalid")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth0: decode header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth0: decode payload: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth0: decode signature: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth0: parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("auth0: unsupported alg %q", header.Alg)
	}
	if header.Kid == "" {
		return nil, errors.New("auth0: header missing kid")
	}

	key, err := v.lookupKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
		return nil, fmt.Errorf("auth0: signature verification failed: %w", err)
	}

	raw := map[string]any{}
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, fmt.Errorf("auth0: parse claims: %w", err)
	}
	claims := &Claims{}
	if err := json.Unmarshal(payloadJSON, claims); err != nil {
		return nil, fmt.Errorf("auth0: decode claims: %w", err)
	}
	claims.setRaw(raw)

	now := time.Now().UTC()
	if !strings.HasPrefix(claims.Issuer, v.issuer) {
		return nil, fmt.Errorf("auth0: issuer mismatch %q", claims.Issuer)
	}
	if !claims.audienceContains(v.audience) {
		return nil, fmt.Errorf("auth0: missing audience %q", v.audience)
	}
	if claims.expired(now) {
		return nil, errors.New("auth0: token expired")
	}
	if claims.beforeNow(now) {
		return nil, errors.New("auth0: token not yet valid")
	}

	if v.rolesClaim != "" {
		if value, ok := raw[v.rolesClaim]; ok {
			claims.Roles = append(claims.Roles, extractStrings(value)...)
			slices.Sort(claims.Roles)
			claims.Roles = slices.Compact(claims.Roles)
		}
	}

	if !claims.HasScopes(requiredScopes) {
		return nil, fmt.Errorf("auth0: missing required scope(s) %v", requiredScopes)
	}

	return claims, nil
}

func (v *Validator) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Since(v.lastReload) < v.cacheTTL
	v.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("auth0: jwk %q not found", kid)
	}
	return key, nil
}

func (v *Validator) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("auth0: build jwks request: %w", err)
	}

	res, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth0: fetch jwks: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("auth0: jwks returned status %d", res.StatusCode)
	}

	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return fmt.Errorf("auth0: decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, k := range payload.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" {
			continue
		}
		if k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		pubKey, err := buildKey(k.N, k.E)
		if err != nil {
			return fmt.Errorf("auth0: build rsa key: %w", err)
		}
		keys[k.Kid] = pubKey
	}

	v.mu.Lock()
	v.keys = keys
	v.lastReload = time.Now()
	v.mu.Unlock()

	return nil
}

func buildKey(modulus, exponent string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	if len(eBytes) == 0 {
		return nil, errors.New("empty exponent")
	}
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

func extractStrings(value any) []string {
	var out []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	case string:
		out = append(out, v)
	}
	return out
}

// ParseBearer extracts the token from the standard Authorization header value.
func ParseBearer(header string) (string, error) {
	if header == "" {
		return "", errors.New("auth0: missing Authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("auth0: invalid Authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}
