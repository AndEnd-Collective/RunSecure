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
