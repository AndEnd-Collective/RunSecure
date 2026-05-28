package state

import (
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/stretchr/testify/require"
)

func TestReconcile_NoDrift(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/r")
	listed := []docker.Container{
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
	}
	total, per := Reconcile(s, listed)
	require.Equal(t, 0, total)
	require.Empty(t, per)
	require.Equal(t, 1, s.InFlight("o/r"))
}

func TestReconcile_OverCount_Corrects(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/r")
	s.IncrementInFlight("o/r") // memory says 2
	listed := []docker.Container{
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}}, // docker says 1
	}
	total, per := Reconcile(s, listed)
	require.Equal(t, -1, total)
	require.Len(t, per, 1)
	require.Equal(t, -1, per[0].Delta)
	require.Equal(t, 1, s.InFlight("o/r"))
}

// Cover drift.go:41 — `for i := 0; i < delta; i++ { Increment }` when
// a repo already exists in memory but docker has MORE containers than
// memory recorded. (TestReconcile_UnderCount_AddsMissing hits the other
// loop where the repo is unknown to memory.)
func TestReconcile_PositiveDelta_IncrementsForKnownRepo(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/r") // memory says 1
	listed := []docker.Container{
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
	}
	total, _ := Reconcile(s, listed)
	require.Equal(t, 2, total) // delta = 3 - 1 = 2
	require.Equal(t, 3, s.InFlight("o/r"))
}

func TestReconcile_UnderCount_AddsMissing(t *testing.T) {
	s := New() // memory empty
	listed := []docker.Container{
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
		{Labels: map[string]string{"runsecure.role": "runner", "runsecure.repo": "o/r"}},
	}
	total, per := Reconcile(s, listed)
	require.Equal(t, 2, total)
	require.Equal(t, 2, s.InFlight("o/r"))
	_ = per
}

func TestReconcile_IgnoresNonRunnerContainers(t *testing.T) {
	s := New()
	listed := []docker.Container{
		{Labels: map[string]string{"runsecure.role": "proxy", "runsecure.repo": "o/r"}},
	}
	total, _ := Reconcile(s, listed)
	require.Equal(t, 0, total)
}
