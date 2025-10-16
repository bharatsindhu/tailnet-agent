package identity

import (
	"context"
	"errors"
)

// Provider abstracts user retrieval for the broker. Implementations can call Auth0 Management APIs
// or maintain static fixtures when offline.
type Provider interface {
	GetUser(ctx context.Context, id string) (*User, error)
	SearchUsers(ctx context.Context, query string) ([]User, error)
}

var (
	// ErrNotFound is returned when a user cannot be located.
	ErrNotFound = errors.New("identity: user not found")
)
