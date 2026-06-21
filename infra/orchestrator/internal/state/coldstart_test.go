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
		{ID: "p2", Labels: map[string]string{"runsecure.role": "squid", "runsecure.spawn_id": "s2"}},
		{ID: "p3", Labels: map[string]string{"runsecure.role": "haproxy", "runsecure.spawn_id": "s3"}},
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
