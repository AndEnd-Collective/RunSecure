package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenBucket_DrainsThenRefills(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	b := NewTokenBucket(1, 1, clock)

	require.True(t, b.TryTake())
	require.False(t, b.TryTake(), "burst=1 so second take must fail without refill")

	now = now.Add(1100 * time.Millisecond)
	require.True(t, b.TryTake(), "after 1.1s a new token must be available")
}

func TestTokenBucket_BurstHigherThan1(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewTokenBucket(1, 3, func() time.Time { return now })
	require.True(t, b.TryTake())
	require.True(t, b.TryTake())
	require.True(t, b.TryTake())
	require.False(t, b.TryTake())
}

func TestTokenBucket_Defaults(t *testing.T) {
	b := NewTokenBucket(0, 0, nil)
	require.True(t, b.TryTake())
}

// Mutation kill: ratelimit.go:21 — `if ratePerSec <= 0 { ratePerSec = 1 }`.
// Pass rate=0, then verify it actually refills (default 1/sec applied).
// Under the mutation `< 0`, rate would stay 0 → bucket never refills →
// second take fails even after long elapsed time.
func TestTokenBucket_RateZeroDefaultsToOne(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewTokenBucket(0, 1, func() time.Time { return now })
	require.True(t, b.TryTake())
	require.False(t, b.TryTake()) // burst exhausted

	// Advance 1.1s — default rate 1/sec → should have refilled.
	now = now.Add(1100 * time.Millisecond)
	require.True(t, b.TryTake(),
		"rate=0 must default to 1/sec; without the default bucket never refills")
}

// Mutation kill: ratelimit.go:46 — `if b.tokens > b.maxBurst`. Boundary case:
// when tokens exactly equals maxBurst, no clamp needed (the > variant is
// correct). Mutation to >= would erroneously clamp the equal case (no-op),
// while mutation to < would let tokens overflow past burst.
// Mutation kill: ratelimit.go:45 — `b.tokens += elapsed * b.rate`.
// Use rate != burst != 1 so `*` is observably different from `+` or `/`.
//
//	Original: elapsed=0.5s × rate=10 = 5 tokens added.
//	Mutation `/`: 0.5 / 10 = 0.05 → no useful refill.
//	Mutation `+`: 0.5 + 10 = 10.5 → over burst, capped to maxBurst (5 added).
//	Mutation `-`: 0.5 - 10 = -9.5 → negative, no refill.
//
// The exact-5-refill expectation discriminates `*` from `/` and `-`; the
// boundary check after refill discriminates `*` from `+`.
func TestTokenBucket_ArithmeticIsMultiplication(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewTokenBucket(10, 10, func() time.Time { return now })
	// Drain all 10.
	for i := 0; i < 10; i++ {
		require.True(t, b.TryTake())
	}
	require.False(t, b.TryTake())

	now = now.Add(500 * time.Millisecond)
	// Original (*): tokens += 0.5 * 10 = 5 → can take exactly 5 more.
	for i := 0; i < 5; i++ {
		require.True(t, b.TryTake(), "refill of 5 expected at i=%d", i)
	}
	require.False(t, b.TryTake(),
		"after taking 5 refilled tokens, bucket should be empty")
}

func TestTokenBucket_CapsExactlyAtBurst(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewTokenBucket(1, 5, func() time.Time { return now })
	// Already at burst=5. Try drain 5 + verify the 6th fails.
	for i := 0; i < 5; i++ {
		require.True(t, b.TryTake(), "draining initial burst")
	}
	require.False(t, b.TryTake(), "burst exhausted")

	// Refill exactly 5 tokens by advancing 5 seconds at rate=1/sec.
	now = now.Add(5 * time.Second)
	for i := 0; i < 5; i++ {
		require.True(t, b.TryTake())
	}
	require.False(t, b.TryTake(),
		"cap must apply exactly at burst (no overflow under elapsed-based refill)")
}

func TestTokenBucket_AvailableReadsValue(t *testing.T) {
	b := NewTokenBucket(1, 5, nil)
	require.Equal(t, 5.0, b.Available())
}

func TestTokenBucket_CapsAtBurst(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewTokenBucket(10, 2, func() time.Time { return now })
	// Advance way more than burst's worth — but cap at maxBurst.
	now = now.Add(time.Hour)
	require.True(t, b.TryTake())
	require.True(t, b.TryTake())
	require.False(t, b.TryTake(), "cap respected even after long elapsed time")
}
