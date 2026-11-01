package cornerstone

// EmitProcessStarted records initialization, not readiness or job delivery.
func (e *Emitter) EmitProcessStarted(version, revision, backend string) error {
	return e.Emit(Event{EventSubType: EventProcessStarted, EventType: EventTypeActivity, EventDetails: EventDetails{Summary: "controller initialization started", Severity: 6, Result: ResultSuccess, Status: StatusStarted, ErrorData: map[string]any{"version": version, "revision": revision, "backend": backend}}})
}
func (e *Emitter) EmitProcessStopping(reason string) error {
	return e.Emit(Event{EventSubType: EventProcessStopping, EventType: EventTypeActivity, EventDetails: EventDetails{Summary: "controller draining admitted work", Severity: 5, Result: ResultSuccess, Status: StatusInProgress, ErrorData: map[string]any{"reason": reason}}})
}

// EmitProcessFailed deliberately receives only a stable code, never the raw
// configuration/authentication error or its potentially sensitive payload.
func (e *Emitter) EmitProcessFailed(reason string) error {
	return e.Emit(Event{EventSubType: EventProcessFailed, EventType: EventTypeActivity, EventDetails: EventDetails{Summary: "controller process failed", Severity: 3, Result: ResultFailure, Status: StatusFailed, FailureReason: reason}})
}
func (e *Emitter) EmitProcessMessage(message string) error {
	return e.Emit(Event{EventSubType: EventProcessMessage, EventType: EventTypeActivity, EventDetails: EventDetails{Summary: "controller operational diagnostic", Message: message, Severity: 4, Result: ResultSuccess}})
}

// Write is the standard-library HTTP server diagnostic adapter. Remote-derived
// text is deliberately excluded instead of promoted to controller provenance.
func (e *Emitter) Write(p []byte) (int, error) {
	if err := e.EmitProcessMessage("HTTP server diagnostic"); err != nil {
		return 0, err
	}
	return len(p), nil
}
