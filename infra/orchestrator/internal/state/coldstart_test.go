package state

import (
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/stretchr/testify/require"
)

func TestRebuildFromDocker_CountsRunners(t *testing.T) {
	s := New()
	listed := []docker.Container{
		{ID: "r1", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/a", "runsecure.spawn_id": "s1"}},
		{ID: "r2", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/a", "runsecure.spawn_id": "s2"}},
		{ID: "r3", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/b", "runsecure.spawn_id": "s3"}},
		{ID: "p1", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s1"}},
		{ID: "p2", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s2"}},
		{ID: "p3", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s3"}},
	}
	orphans := RebuildFromDocker(s, listed)
	require.Empty(t, orphans)
	require.Equal(t, 2, s.InFlight("o/a"))
	require.Equal(t, 1, s.InFlight("o/b"))
}

func TestRebuildFromDocker_DetectsOrphans(t *testing.T) {
	s := New()
	listed := []docker.Container{
		{ID: "r1", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/a", "runsecure.spawn_id": "s1"}},
		{ID: "p1", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s1"}}, // matched
		{ID: "p2", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "ORPHAN"}},
	}
	orphans := RebuildFromDocker(s, listed)
	require.Len(t, orphans, 1)
	require.Equal(t, "p2", orphans[0].ContainerID)
	require.Equal(t, "ORPHAN", orphans[0].SpawnID)
}

func TestRebuildFromDocker_EmptyList(t *testing.T) {
	s := New()
	orphans := RebuildFromDocker(s, nil)
	require.Empty(t, orphans)
	require.Equal(t, 0, s.GlobalInFlight())
}

func TestRebuildFromDocker_NewSingleProxyRole(t *testing.T) {
	s := New()
	listed := []docker.Container{
		{ID: "r1", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/a", "runsecure.spawn_id": "s1"}},
		{ID: "p1", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s1"}},
	}
	orphans := RebuildFromDocker(s, listed)
	require.Empty(t, orphans)
	require.Equal(t, 1, s.InFlight("o/a"))
}

func TestRebuildFromDocker_LegacyProxyRolesIgnored(t *testing.T) {
	// Verify that legacy proxy role labels (squid, haproxy, dnsmasq) are NOT recognized as proxies.
	// These roles are no longer used after the unified "proxy" role change. Containers with these
	// labels should be treated as unknown/ignored, not as proxy containers.
	s := New()
	listed := []docker.Container{
		{ID: "r1", Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/a", "runsecure.spawn_id": "s1"}},
		// Legacy proxy roles that should be ignored and NOT matched against runners
		{ID: "old-squid", Labels: map[string]string{"runsecure.role": "squid", "runsecure.spawn_id": "s1"}},
		{ID: "old-haproxy", Labels: map[string]string{"runsecure.role": "haproxy", "runsecure.spawn_id": "s2"}},
		{ID: "old-dnsmasq", Labels: map[string]string{"runsecure.role": "dnsmasq", "runsecure.spawn_id": "s3"}},
		// Only the "proxy" role is recognized
		{ID: "new-proxy", Labels: map[string]string{"runsecure.role": "proxy", "runsecure.spawn_id": "s1"}},
	}
	orphans := RebuildFromDocker(s, listed)
	// No orphans: the new-proxy is matched with r1 (same spawn_id)
	require.Empty(t, orphans)
	// Only the runner is counted
	require.Equal(t, 1, s.InFlight("o/a"))
}
