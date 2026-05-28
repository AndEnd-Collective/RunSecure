package cornerstone

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ClockFunc returns the current time in RFC 3339 (ISO 8601) format.
type ClockFunc func() string

// UUIDFunc returns a fresh event UUID.
type UUIDFunc func() string

// SystemClock is the production ClockFunc.
func SystemClock() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// SystemUUID is the production UUIDFunc.
func SystemUUID() string {
	return uuid.NewString()
}

// FixedClock returns a ClockFunc that always returns ts. For tests.
func FixedClock(ts string) ClockFunc {
	return func() string { return ts }
}

// FixedUUID returns a UUIDFunc that always returns id. For tests.
func FixedUUID(id string) UUIDFunc {
	return func() string { return id }
}

// Emitter writes Cornerstone events as newline-terminated JSON to a writer.
// Safe for concurrent use.
type Emitter struct {
	w     io.Writer
	clock ClockFunc
	uid   UUIDFunc
	mu    sync.Mutex
}

// NewEmitter constructs an Emitter. The writer is typically os.Stdout in
// production; tests pass a bytes.Buffer.
func NewEmitter(w io.Writer, clock ClockFunc, uid UUIDFunc) *Emitter {
	return &Emitter{w: w, clock: clock, uid: uid}
}

// Emit writes one event. Validates first; on validation failure, nothing is
// written and the error is returned.
func (e *Emitter) Emit(ev Event) error {
	if ev.EventUUID == "" {
		ev.EventUUID = e.uid()
	}
	if ev.EventSignature == "" {
		ev.EventSignature = ProjectSignature
	}
	if ev.TimeStamp == "" {
		ev.TimeStamp = e.clock()
	}
	if err := ev.EventDetails.Validate(); err != nil {
		return err
	}

	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("cornerstone: marshal: %w", err)
	}
	b = append(b, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(b); err != nil {
		return fmt.Errorf("cornerstone: write: %w", err)
	}
	return nil
}
