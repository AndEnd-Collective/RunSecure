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
