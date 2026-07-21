package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
	"github.com/stretchr/testify/require"
)

func TestDrainAndStopJoinsPollerBeforeClosingIntents(t *testing.T) {
	intents := make(chan orchestrator.SpawnIntent, 1)
	pollDone := make(chan struct{})
	workersDone := make(chan struct{})
	close(workersDone)
	stopping := make(chan struct{})
	resultCh := make(chan shutdownResult, 1)
	var draining atomic.Bool

	go func() {
		resultCh <- drainAndStop(time.Second, func() { close(stopping) }, pollDone,
			intents, &draining, func() {}, workersDone)
	}()

	select {
	case <-stopping:
	case <-time.After(time.Second):
		t.Fatal("poll cancellation was not requested")
	}
	require.True(t, draining.Load())

	// The poller has not joined yet, so its sole output channel must remain
	// open. A buffered send avoids introducing a receiver into the assertion.
	select {
	case intents <- orchestrator.SpawnIntent{SpawnID: "last-poll-intent"}:
	case <-time.After(time.Second):
		t.Fatal("intent channel closed before poller joined")
	}

	close(pollDone)
	result := <-resultCh
	require.False(t, result.Forced)
	require.True(t, result.WorkersStopped)
	require.Equal(t, "last-poll-intent", (<-intents).SpawnID)
	_, open := <-intents
	require.False(t, open, "intent channel must close after the poller joins")
}

func TestDrainAndStopForcesWorkersAfterDeadline(t *testing.T) {
	intents := make(chan orchestrator.SpawnIntent)
	pollDone := make(chan struct{})
	close(pollDone)
	workersDone := make(chan struct{})
	workersCancelled := make(chan struct{})
	var draining atomic.Bool

	result := drainAndStop(time.Millisecond, func() {}, pollDone, intents,
		&draining, func() {
			close(workersCancelled)
			close(workersDone)
		}, workersDone)

	require.True(t, result.Forced)
	require.True(t, result.WorkersStopped)
	select {
	case <-workersCancelled:
	default:
		t.Fatal("worker cancellation was not requested after drain deadline")
	}
}

func TestForcedCleanupGrace(t *testing.T) {
	require.Equal(t, 20*time.Second, forcedCleanupGrace())
}
