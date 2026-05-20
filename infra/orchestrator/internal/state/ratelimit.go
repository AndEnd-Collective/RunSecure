package state

import (
	"sync"
	"time"
)

// TokenBucket is the B1 spawn-rate limiter. Concurrency-safe.
//
// Default: 1 token / second, burst = 1. Configurable.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rate     float64 // tokens per second
	last     time.Time
	now      func() time.Time
}

func NewTokenBucket(ratePerSec, burst float64, now func() time.Time) *TokenBucket {
	if ratePerSec <= 0 {
		ratePerSec = 1.0
	}
	if burst <= 0 {
		burst = 1.0
	}
	if now == nil {
		now = time.Now
	}
	return &TokenBucket{
		tokens:   burst,
		maxBurst: burst,
		rate:     ratePerSec,
		last:     now(),
		now:      now,
	}
}

// TryTake attempts to take 1 token. Returns true if a token was available.
func (b *TokenBucket) TryTake() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.maxBurst {
		b.tokens = b.maxBurst
	}
	b.last = now
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// Available reports the current token count (for test introspection).
func (b *TokenBucket) Available() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}
