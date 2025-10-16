package identity

import (
	"context"
	"testing"
)

const sampleData = `{"users": [{"id": "auth0|1", "email": "dana@example.com", "displayName": "Dana", "roles": ["alpha"], "groups": ["developers"]}, {"id": "auth0|2", "email": "lee@example.com", "displayName": "Lee", "roles": ["beta"], "groups": ["security"]}]}`

func TestStaticProviderSearch(t *testing.T) {
	provider, err := NewStaticProvider([]byte(sampleData))
	if err != nil {
		t.Fatalf("NewStaticProvider error: %v", err)
	}

	users, err := provider.SearchUsers(context.Background(), "dana")
	if err != nil {
		t.Fatalf("SearchUsers error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Email != "dana@example.com" {
		t.Fatalf("unexpected user %+v", users[0])
	}
}

func TestStaticProviderSearchGroup(t *testing.T) {
	provider, err := NewStaticProvider([]byte(sampleData))
	if err != nil {
		t.Fatalf("NewStaticProvider error: %v", err)
	}
	users, err := provider.SearchUsers(context.Background(), "group:developers")
	if err != nil {
		t.Fatalf("SearchUsers error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 developer, got %d", len(users))
	}
	if users[0].Email != "dana@example.com" {
		t.Fatalf("unexpected user %s", users[0].Email)
	}
}

func TestStaticProviderGetUser(t *testing.T) {
	provider, err := NewStaticProvider([]byte(sampleData))
	if err != nil {
		t.Fatalf("NewStaticProvider error: %v", err)
	}
	user, err := provider.GetUser(context.Background(), "auth0|2")
	if err != nil {
		t.Fatalf("GetUser error: %v", err)
	}
	if user.DisplayName != "Lee" {
		t.Fatalf("unexpected display name %s", user.DisplayName)
	}
}
