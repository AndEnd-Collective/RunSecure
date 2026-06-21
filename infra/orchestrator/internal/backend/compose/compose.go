// Package compose implements backend.Backend using Docker Compose-style
// container stacks: one proxy container dual-homed on the internal + egress
// networks and one runner container on the internal network only. Network
// creation, container lifecycle, egress-config cleanup, and cold-start
// reconciliation are handled here; all container-level hardening lives in
// docker.Spawn and is not duplicated.
package compose

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
)

// egressMountPath aliases backend.EgressMountPath for use within this package.
// The canonical definition lives in internal/backend/backend.go — a leaf
// package imported by both orchestrator and backend/compose — to avoid
// duplicating the string literal and to prevent import cycles.
// Do NOT change this value without updating backend.EgressMountPath.
var egressMountPath = backend.EgressMountPath

// pollInterval is the cadence at which WaitForExit re-inspects the runner
// container while waiting for it to transition to "exited".
const pollInterval = 1 * time.Second

// composeBackend implements backend.Backend using Docker containers.
type composeBackend struct {
	c docker.Client
}

// New constructs a compose Backend backed by the given docker.Client.
func New(c docker.Client) backend.Backend {
	return &composeBackend{c: c}
}

// Name returns the backend identifier.
func (b *composeBackend) Name() string { return "compose" }

// Spawn creates the per-spawn internal network and then delegates to
// docker.Spawn to create and start the proxy + runner containers. On any
// failure after network creation the network is deleted before returning the
// error (mirroring the rollback in orchestrator/spawn.go Execute()).
//
// The returned Handle carries:
//
//	Refs["proxy"]        → proxy container ID
//	Refs["runner"]       → runner container ID
//	Refs["network"]      → internal network ID (for teardown)
//	Refs["network_name"] → internal network name "rs-net-<repo>-<spawnID>"
//	                       (the value the runner_created event reports)
func (b *composeBackend) Spawn(ctx context.Context, in backend.SpawnInput) (backend.Handle, error) {
	netName := fmt.Sprintf("rs-net-%s-%s",
		strings.ReplaceAll(in.Repo, "/", "_"), in.SpawnID)
	netID, err := b.c.CreateNetwork(ctx, docker.CreateNetworkRequest{
		Name:       netName,
		Driver:     "bridge",
		Internal:   true,
		Attachable: false,
	})
	if err != nil {
		return backend.Handle{}, fmt.Errorf("compose: create network: %w", err)
	}

	containerIDs, err := docker.Spawn(ctx, b.c, docker.SpawnInputs{
		Scope:              in.Scope,
		Repo:               in.Repo,
		SpawnID:            in.SpawnID,
		NetworkID:          netID,
		EgressNetwork:      in.EgressNetwork,
		RunnerImage:        in.RunnerImage,
		ProxyImage:         in.ProxyImage,
		SeccompProfilePath: in.SeccompProfilePath,
		ResourcesMemory:    in.ResourcesMemory,
		ResourcesNanoCPUs:  in.ResourcesNanoCPUs,
		ResourcesPIDs:      in.ResourcesPIDs,
		JITConfigB64:       in.JITConfigB64,
		EgressVolume:       in.EgressVolume,
		EgressMountPath:    egressMountPath,
		EnableDNSMasq:      in.EnableDNSMasq,
		Labels:             in.Labels,
	})
	if err != nil {
		_ = b.c.DeleteNetwork(ctx, netID)
		return backend.Handle{}, fmt.Errorf("compose: spawn containers: %w", err)
	}

	refs := map[string]string{
		"network":      netID,
		"network_name": netName,
	}
	for role, id := range containerIDs {
		refs[role] = id
	}

	return backend.Handle{
		SpawnID: in.SpawnID,
		Backend: "compose",
		Refs:    refs,
	}, nil
}

// WaitForExit polls InspectContainer on the runner container until it reports
// an "exited" state or the timeout elapses. The initial inspect happens before
// blocking on the tick so an already-exited runner returns immediately.
//
// Returns (exitCode, false) on clean exit, (-1, true) on timeout, and
// (-1, false) if the context is cancelled.
func (b *composeBackend) WaitForExit(ctx context.Context, h backend.Handle, timeout time.Duration) (int, bool) {
	runnerID := h.Refs["runner"]
	deadline := time.After(timeout)
	for {
		ins, err := b.c.InspectContainer(ctx, runnerID)
		if err == nil && ins.State == "exited" {
			return ins.ExitCode, false
		}
		select {
		case <-ctx.Done():
			return -1, false
		case <-deadline:
			return -1, true
		case <-time.After(pollInterval):
			// next iteration: re-inspect.
		}
	}
}

// Teardown deletes every container in h.Refs (by role key, skipping
// "network"), then deletes the internal network, then removes the per-spawn
// egress config subdirectory from the shared volume. Errors from individual
// deletions are tolerated so that cleanup is best-effort — matching the
// semantics of orchestrator/spawn.go tearDown().
func (b *composeBackend) Teardown(ctx context.Context, h backend.Handle, force bool) error {
	for role, id := range h.Refs {
		if role == "network" {
			continue
		}
		_ = b.c.DeleteContainer(ctx, id, force)
	}
	if netID, ok := h.Refs["network"]; ok {
		_ = b.c.DeleteNetwork(ctx, netID)
	}
	// Remove the per-spawn egress config subdir so it does not accumulate.
	// EgressConfigDir is the full path on the volume (<base>/<spawnID>).
	// We reconstruct it from the mount path and SpawnID since the Handle
	// does not carry EgressConfigDir directly — the caller sets it via
	// the SpawnInput. For backwards compat we derive the path the same way
	// as orchestrator/spawn.go: egressMountPath + "/" + spawnID.
	//
	// Note: if the egress directory does not exist os.RemoveAll is a no-op.
	egressDir := egressMountPath + "/" + h.SpawnID
	_ = os.RemoveAll(egressDir)
	return nil
}

// Reconcile lists all containers for scope, groups them by runsecure.spawn_id
// label, and returns one Handle per spawn-id. Each handle carries the
// container IDs keyed by their runsecure.role label, plus "network" set to
// the empty string (network IDs are not recoverable from container labels
// alone after a restart).
func (b *composeBackend) Reconcile(ctx context.Context, scope string) ([]backend.Handle, error) {
	containers, err := b.c.ListContainersForScope(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("compose: reconcile list: %w", err)
	}

	// Group containers by spawn_id.
	bySpawn := map[string]map[string]string{} // spawnID → role → containerID
	for _, c := range containers {
		spawnID := c.Labels["runsecure.spawn_id"]
		role := c.Labels["runsecure.role"]
		if spawnID == "" || role == "" {
			continue
		}
		if bySpawn[spawnID] == nil {
			bySpawn[spawnID] = map[string]string{}
		}
		bySpawn[spawnID][role] = c.ID
	}

	handles := make([]backend.Handle, 0, len(bySpawn))
	for spawnID, refs := range bySpawn {
		// Network ID cannot be recovered from container labels; leave it empty.
		refs["network"] = ""
		handles = append(handles, backend.Handle{
			SpawnID: spawnID,
			Backend: "compose",
			Refs:    refs,
		})
	}
	return handles, nil
}
