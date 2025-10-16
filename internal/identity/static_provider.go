package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// StaticProvider loads user records from a YAML document for local development.
type StaticProvider struct {
	mu    sync.RWMutex
	users []User
}

// NewStaticProvider parses the provided JSON payload and stores users in memory.
func NewStaticProvider(data []byte) (*StaticProvider, error) {
	type doc struct {
		Users []User `json:"users"`
	}
	var parsed doc
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("identity: parse fixture: %w", err)
	}

	provider := &StaticProvider{
		users: make([]User, 0, len(parsed.Users)),
	}
	for _, u := range parsed.Users {
		if u.ID == "" {
			return nil, errors.New("identity: fixture contains user without id")
		}
		provider.users = append(provider.users, u)
	}
	return provider, nil
}

// GetUser returns the first user whose ID or email matches the identifier.
func (p *StaticProvider) GetUser(_ context.Context, id string) (*User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	idLower := strings.ToLower(strings.TrimSpace(id))
	for _, user := range p.users {
		if strings.EqualFold(user.ID, idLower) || strings.EqualFold(user.Email, idLower) {
			copy := user
			return &copy, nil
		}
	}
	return nil, ErrNotFound
}

// SearchUsers performs a case-insensitive substring match across email, name, and roles.
func (p *StaticProvider) SearchUsers(_ context.Context, query string) ([]User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		result := make([]User, len(p.users))
		for i := range p.users {
			result[i] = p.users[i]
		}
		return result, nil
	}

	var matches []User
	for _, user := range p.users {
		if strings.HasPrefix(q, "group:") {
			groupName := strings.TrimPrefix(q, "group:")
			if belongsToGroup(user, groupName) {
				matches = append(matches, user)
			}
			continue
		}
		if containsIdentity(user, q) {
			matches = append(matches, user)
		}
	}
	slices.SortFunc(matches, func(a, b User) int {
		return strings.Compare(a.DisplayName, b.DisplayName)
	})
	return matches, nil
}

func containsIdentity(user User, query string) bool {
	if strings.Contains(strings.ToLower(user.ID), query) {
		return true
	}
	if strings.Contains(strings.ToLower(user.Email), query) {
		return true
	}
	if strings.Contains(strings.ToLower(user.DisplayName), query) {
		return true
	}
	for _, role := range user.Roles {
		if strings.Contains(strings.ToLower(role), query) {
			return true
		}
	}
	for _, group := range user.Groups {
		if strings.Contains(strings.ToLower(group), query) {
			return true
		}
	}
	return false
}

func belongsToGroup(user User, group string) bool {
	group = strings.ToLower(strings.TrimSpace(group))
	if group == "" {
		return false
	}
	for _, g := range user.Groups {
		if strings.EqualFold(g, group) {
			return true
		}
	}
	return false
}
