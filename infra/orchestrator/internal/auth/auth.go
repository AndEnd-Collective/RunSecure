// Package auth defines the credential-provider interface used by the
// orchestrator to obtain GitHub tokens. Abstracting behind Provider allows
// a GitHub App provider to be wired in later without touching call sites.
package auth

import "context"

// Provider returns a valid GitHub API token on demand.
// Implementations must be safe for concurrent use.
type Provider interface {
	Token(ctx context.Context) (string, error)
}
