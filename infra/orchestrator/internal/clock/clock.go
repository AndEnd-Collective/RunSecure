// Package clock provides a testable time abstraction. Production code uses
// System(); tests use NewFake() and drive time forward with Advance().
package clock

import (
	"sync"
	"time"
)

// Clock is the interface every time-dependent component depends on.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// System returns a Clock backed by the real wall clock.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Fake is a deterministic Clock for tests.
type Fake struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	fireAt time.Time
	ch     chan time.Time
}

// NewFake constructs a Fake at the given initial time.
func NewFake(start time.Time) *Fake {
	return &Fake{now: start}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	f.timers = append(f.timers, &fakeTimer{fireAt: f.now.Add(d), ch: ch})
	return ch
}

// Advance moves the fake clock forward by d, firing any timers whose
// deadline has elapsed.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	remaining := f.timers[:0]
	fire := []*fakeTimer{}
	for _, t := range f.timers {
		if !t.fireAt.After(now) {
			fire = append(fire, t)
		} else {
			remaining = append(remaining, t)
		}
	}
	f.timers = remaining
	f.mu.Unlock()
	for _, t := range fire {
		t.ch <- now
		close(t.ch)
	}
}
