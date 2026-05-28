package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(3, time.Minute, func() time.Time { return now })

	require.False(t, b.IsOpen())
	b.RecordFailure()
	require.False(t, b.IsOpen())
	b.RecordFailure()
	require.False(t, b.IsOpen())
	b.RecordFailure()
	require.True(t, b.IsOpen())
	require.Equal(t, BreakerOpen, b.State())
}

func TestBreaker_SuccessResetsCounter(t *testing.T) {
	b := NewBreaker(3, time.Minute, nil)
	b.RecordFailure()
	b.RecordFailure()
	b.RecordSuccess()
	require.Equal(t, 0, b.ConsecutiveFailures())
	require.Equal(t, BreakerClosed, b.State())
}

func TestBreaker_HalfOpenAfterCooldown(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(1, time.Minute, func() time.Time { return now })
	b.RecordFailure()
	require.Equal(t, BreakerOpen, b.State())

	// Not yet — cooldown is 1 minute; advance only 30s.
	now = now.Add(30 * time.Second)
	require.False(t, b.MaybeHalfOpen())
	require.Equal(t, BreakerOpen, b.State())

	now = now.Add(31 * time.Second)
	require.True(t, b.MaybeHalfOpen())
	require.Equal(t, BreakerHalfOpen, b.State())
}

func TestBreaker_HalfOpenToClosedOnSuccess(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(1, time.Minute, func() time.Time { return now })
	b.RecordFailure()
	now = now.Add(2 * time.Minute)
	b.MaybeHalfOpen()
	require.Equal(t, BreakerHalfOpen, b.State())
	b.RecordSuccess()
	require.Equal(t, BreakerClosed, b.State())
}

func TestBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(5, time.Minute, func() time.Time { return now })
	// Force open via cheap threshold check
	for i := 0; i < 5; i++ {
		b.RecordFailure()
	}
	now = now.Add(2 * time.Minute)
	b.MaybeHalfOpen()
	require.Equal(t, BreakerHalfOpen, b.State())
	b.RecordFailure()
	require.Equal(t, BreakerOpen, b.State())
}

func TestBreaker_DefaultsWhenZero(t *testing.T) {
	b := NewBreaker(0, 0, nil)
	// Default threshold 5 should not trip until 5 failures.
	for i := 0; i < 4; i++ {
		b.RecordFailure()
	}
	require.False(t, b.IsOpen())
	b.RecordFailure()
	require.True(t, b.IsOpen())
}

// Mutation kill: breaker.go:35 — `if cooldown <= 0 { cooldown = 5 * time.Minute }`.
// Pass cooldown=0 and verify it doesn't half-open before 5 minutes (the
// default). If the <= mutation flipped to <, cooldown=0 would persist and
// MaybeHalfOpen would always transition immediately.
func TestBreaker_CooldownDefaultWhenZero(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(1, 0, func() time.Time { return now })
	b.RecordFailure() // → Open
	require.True(t, b.IsOpen())

	// Advance 1 minute — under default (5 min), no transition yet.
	now = now.Add(1 * time.Minute)
	require.False(t, b.MaybeHalfOpen())
	require.Equal(t, BreakerOpen, b.State())

	// Advance another 5 minutes — total 6 — should now transition.
	now = now.Add(5 * time.Minute)
	require.True(t, b.MaybeHalfOpen())
}

// Mutation kill: breaker.go:64 — `now().Sub(openedAt) >= b.cooldown`.
// Exactly-at-boundary: elapsed == cooldown must trigger half-open.
func TestBreaker_HalfOpenAtExactCooldownBoundary(t *testing.T) {
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	b := NewBreaker(1, 30*time.Second, func() time.Time { return now })
	b.RecordFailure()

	// Advance exactly cooldown duration.
	now = now.Add(30 * time.Second)
	require.True(t, b.MaybeHalfOpen(),
		"exactly-at-boundary must transition (>=, not >)")
}

// RecordFailure return-value tests — added with bug #1 fix so the
// transition signal is now observable.
func TestBreaker_RecordFailure_ReturnsOpenedOnTransition(t *testing.T) {
	b := NewBreaker(3, time.Minute, nil)
	opened, count := b.RecordFailure()
	require.False(t, opened)
	require.Equal(t, 1, count)
	opened, _ = b.RecordFailure()
	require.False(t, opened)
	opened, count = b.RecordFailure()
	require.True(t, opened, "third failure crosses threshold → opened=true")
	require.Equal(t, 3, count)
	// Subsequent failures while Open: NOT a new transition.
	opened, _ = b.RecordFailure()
	require.False(t, opened, "already-Open breaker doesn't re-transition")
}

func TestBreaker_RecordSuccess_ReturnsClosedOnTransition(t *testing.T) {
	b := NewBreaker(1, time.Minute, nil)
	require.False(t, b.RecordSuccess(), "no transition when already Closed")
	b.RecordFailure() // → Open
	require.True(t, b.RecordSuccess(), "Open → Closed transition")
	require.False(t, b.RecordSuccess(), "second success: no transition")
}
