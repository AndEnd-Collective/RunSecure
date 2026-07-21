package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
)

// shutdownResult distinguishes a normal drain from a forced cleanup and from
// the exceptional case where cleanup did not finish before Compose's grace.
type shutdownResult struct {
	Forced         bool
	WorkersStopped bool
}

// forcedCleanupGrace is deliberately shorter than compose.scope.yml's 90s
// stop_grace_period: 60s normal drain + 20s cleanup leaves 10s for HTTP server
// shutdown and process scheduling before Docker sends SIGKILL.
func forcedCleanupGrace() time.Duration { return 20 * time.Second }

// drainAndStop enforces the shutdown ownership order:
//
//  1. mark draining so workers discard queued-but-not-started work;
//  2. cancel and JOIN the poll loop (the only intent-channel producer);
//  3. close the intent channel;
//  4. wait for active workers, cancelling them only after the drain deadline.
//
// Joining the producer before closing the channel is the key invariant: it
// makes send-on-closed-channel impossible without hiding the race behind a
// recover. The worker cancellation path performs bounded force teardown.
func drainAndStop(
	drainTimeout time.Duration,
	stopPolling context.CancelFunc,
	pollDone <-chan struct{},
	intents chan orchestrator.SpawnIntent,
	draining *atomic.Bool,
	stopWorkers context.CancelFunc,
	workersDone <-chan struct{},
) shutdownResult {
	draining.Store(true)
	stopPolling()
	<-pollDone
	close(intents)

	if waitForWorkers(workersDone, drainTimeout) {
		return shutdownResult{WorkersStopped: true}
	}

	stopWorkers()
	return shutdownResult{
		Forced:         true,
		WorkersStopped: waitForWorkers(workersDone, forcedCleanupGrace()),
	}
}

func waitForWorkers(done <-chan struct{}, timeout time.Duration) bool {
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
