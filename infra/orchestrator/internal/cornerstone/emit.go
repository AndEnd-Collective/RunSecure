package cornerstone

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/telemetry"
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
	w           io.Writer
	clock       ClockFunc
	uid         UUIDFunc
	mu          sync.Mutex
	identity    telemetry.Identity
	diagnostics io.Writer
	backend     string
}

// NewEmitter constructs an Emitter. The writer is typically os.Stdout in
// production; tests pass a bytes.Buffer.
func NewEmitter(w io.Writer, clock ClockFunc, uid UUIDFunc) *Emitter {
	return &Emitter{w: w, clock: clock, uid: uid, identity: telemetry.FromEnv(), diagnostics: os.Stderr}
}

// SetDiagnosticWriter selects the separate failure sink before concurrent use.
// Production uses stderr; events remain on stdout. It never receives raw errors.
func (e *Emitter) SetDiagnosticWriter(w io.Writer) { e.diagnostics = w }

// SetBackend identifies the validated spawn backend before concurrent use.
func (e *Emitter) SetBackend(backend string) { e.backend = backend }

// Emit writes one event. Validates first; on validation failure, nothing is
// written and the error is returned.
func (e *Emitter) Emit(ev Event) (emitErr error) {
	reason := "validation_failed"
	defer func() {
		if emitErr != nil {
			e.reportFailure(reason)
		}
	}()
	if ev.EventUUID == "" {
		ev.EventUUID = e.uid()
	}
	if ev.EventSignature == "" {
		ev.EventSignature = ProjectSignature
	}
	if ev.TimeStamp == "" {
		ev.TimeStamp = e.clock()
	}
	definition, ok := eventDefinitions[ev.EventSubType]
	if !ok || (ev.EventDefinitionUUID != "" && ev.EventDefinitionUUID != definition) {
		return fmt.Errorf("cornerstone: unregistered or mismatched event definition")
	}
	ev.EventDefinitionUUID = definition
	if e.backend == "kube" && ev.ContainerContext != nil {
		context := *ev.ContainerContext
		context.Runtime = "" // Kubernetes does not identify the node's CRI engine.
		ev.ContainerContext = &context
		ev.NetworkContext = nil // No Docker bridge exists in the Kubernetes backend.
		data := make(map[string]any, len(ev.EventDetails.ErrorData)+1)
		for key, value := range ev.EventDetails.ErrorData {
			data[key] = value
		}
		data["backend"] = "kube"
		ev.EventDetails.ErrorData = data
	}
	if err := ev.EventDetails.Validate(); err != nil {
		return err
	}

	reason = "marshal_failed"
	b, err := telemetry.Marshal(ev, e.identity)
	if err != nil {
		return fmt.Errorf("cornerstone: marshal: %w", err)
	}
	reason = "write_failed"
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := telemetry.Write(e.w, b); err != nil {
		return fmt.Errorf("cornerstone: write: %w", err)
	}
	return nil
}

func (e *Emitter) reportFailure(reason string) {
	if e.diagnostics == nil {
		return
	}
	ev := Event{EventUUID: e.uid(), EventDefinitionUUID: eventDefinitions[EventTelemetryFailed], EventSignature: ProjectSignature, EventSubType: EventTelemetryFailed, EventType: EventTypeActivity, TimeStamp: e.clock(), EventDetails: EventDetails{Summary: "Cornerstone event could not be emitted", Severity: 3, Result: ResultFailure, FailureReason: reason}}
	encoded, err := telemetry.Marshal(ev, e.identity)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = telemetry.Write(e.diagnostics, encoded)
}
