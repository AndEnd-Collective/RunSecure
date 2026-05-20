package clock

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFake_NowAdvancesOnlyExplicitly(t *testing.T) {
	c := NewFake(time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC))
	t0 := c.Now()
	t1 := c.Now()
	require.True(t, t0.Equal(t1), "Now() must be stable without Advance")

	c.Advance(15 * time.Second)
	require.Equal(t, 15*time.Second, c.Now().Sub(t0))
}

func TestFake_AfterFiresOnAdvance(t *testing.T) {
	c := NewFake(time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC))
	ch := c.After(10 * time.Second)

	select {
	case <-ch:
		t.Fatal("After must not fire before Advance")
	default:
	}

	c.Advance(9 * time.Second)
	select {
	case <-ch:
		t.Fatal("After must not fire before full duration elapsed")
	default:
	}

	c.Advance(1 * time.Second)
	select {
	case <-ch:
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("After must fire once duration elapses")
	}
}

func TestSystem_NowAndAfter(t *testing.T) {
	c := System()
	t0 := c.Now()
	ch := c.After(10 * time.Millisecond)
	<-ch
	require.True(t, c.Now().After(t0))
}
