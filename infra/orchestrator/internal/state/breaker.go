package state

import (
	"sync"
	"time"
)

// BreakerState represents the FSM state of a circuit breaker.
type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

// Breaker is the B4 per-repo circuit breaker.
//
// Defaults (configurable): 5 consecutive failures → open; 5-minute cooldown →
// half-open; one success → closed; one failure in half-open → open again.
type Breaker struct {
	mu                  sync.Mutex
	state               BreakerState
	consecutiveFailures int
	openedAt            time.Time
	threshold           int
	cooldown            time.Duration
	now                 func() time.Time
}

func NewBreaker(threshold int, cooldown time.Duration, now func() time.Time) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: now}
}

// State returns the current FSM state.
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// IsOpen reports whether the breaker is currently denying calls.
// HalfOpen returns false here (a probe IS allowed).
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == BreakerOpen
}

// MaybeHalfOpen transitions Open → HalfOpen if the cooldown has elapsed.
// Returns true if a transition happened.
func (b *Breaker) MaybeHalfOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen && b.now().Sub(b.openedAt) >= b.cooldown {
		b.state = BreakerHalfOpen
		return true
	}
	return false
}

// RecordSuccess closes the breaker (whatever state it was in).
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = BreakerClosed
	b.consecutiveFailures = 0
}

// RecordFailure increments the failure counter; opens the breaker if the
// threshold is reached. From HalfOpen, any failure goes straight to Open.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutiveFailures++
	if b.state == BreakerHalfOpen || b.consecutiveFailures >= b.threshold {
		b.state = BreakerOpen
		b.openedAt = b.now()
	}
}

// ConsecutiveFailures returns the current failure count.
func (b *Breaker) ConsecutiveFailures() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecutiveFailures
}
