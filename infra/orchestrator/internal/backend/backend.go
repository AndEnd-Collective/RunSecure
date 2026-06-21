package backend

import (
	"context"
	"time"
)

// SpawnInput is everything a backend needs to create one per-spawn stack.
type SpawnInput struct {
	Scope, Repo, SpawnID string
	RunnerImage, ProxyImage string // digest-pinned
	SeccompProfilePath string
	ResourcesMemory, ResourcesNanoCPUs, ResourcesPIDs int64
	JITConfigB64 string
	EgressConfigDir string // rendered squid/haproxy/dnsmasq dir
	EgressNetwork, EgressVolume string // Compose-specific; kube ignores
	EnableDNSMasq bool
	Labels []string
}

// Handle is a backend-opaque reference to a live spawn.
type Handle struct {
	SpawnID string
	Backend string            // "compose" | "kube"
	Refs    map[string]string // compose: role->containerID + "network"->id; kube: ns/pod refs
}

// Backend is the pluggable spawn mechanism.
type Backend interface {
	Spawn(ctx context.Context, in SpawnInput) (Handle, error)
	WaitForExit(ctx context.Context, h Handle, timeout time.Duration) (exitCode int, timedOut bool)
	Teardown(ctx context.Context, h Handle, force bool) error
	Reconcile(ctx context.Context, scope string) ([]Handle, error)
	Name() string
}
