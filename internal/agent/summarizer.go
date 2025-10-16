package agent

import (
	"context"
	"fmt"

	"github.com/tailscale-portfolio/identity-agent-poc/internal/identity"
)

// Summarizer turns identity records into a natural language description.
type Summarizer interface {
	Summarize(ctx context.Context, user identity.User) (string, error)
}

// StaticSummarizer generates a deterministic summary without calling an LLM. Useful for local testing.
type StaticSummarizer struct{}

func (StaticSummarizer) Summarize(_ context.Context, user identity.User) (string, error) {
	if user.ID == "" {
		return "", fmt.Errorf("agent: missing user id")
	}
	template := "%s (%s) is assigned roles %v and has %d device(s) on the tailnet."
	if len(user.Roles) == 0 {
		template = "%s (%s) has %d device(s) on the tailnet."
		return fmt.Sprintf(template, user.DisplayName, user.Email, len(user.Devices)), nil
	}
	return fmt.Sprintf(template, user.DisplayName, user.Email, user.Roles, len(user.Devices)), nil
}
