// Package cornerstone emits typed socket-proxy control-plane events. It never
// accepts a request body, URL, header, JIT value or arbitrary application log.
package cornerstone

import (
	"crypto/rand"
	"fmt"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/telemetry"
	"io"
	"os"
	"sync"
	"time"
)

const ProjectSignature = "runsecure-socket-proxy-v1"

type Kind string

const (
	Started         Kind = "runsecure.socket_proxy.started"
	Denied          Kind = "runsecure.socket_proxy.request.denied"
	UpstreamFailed  Kind = "runsecure.socket_proxy.upstream.failed"
	Stopped         Kind = "runsecure.socket_proxy.stopped"
	ProcessFailed   Kind = "runsecure.socket_proxy.process.failed"
	ProcessMessage  Kind = "runsecure.socket_proxy.process.message"
	TelemetryFailed Kind = "runsecure.socket_proxy.telemetry.failed"
)

type Fields struct {
	Reason                string
	Status                int
	ImageAllowlistEntries int
	TLS                   bool
}
type Emitter struct {
	w           io.Writer
	diagnostics io.Writer
	identity    telemetry.Identity
	mu          sync.Mutex
}

func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{w: w, diagnostics: os.Stderr, identity: telemetry.FromEnv()}
}
func (e *Emitter) SetDiagnosticWriter(w io.Writer) { e.diagnostics = w }

func newUUID() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

func record(kind Kind, fields Fields) map[string]any {
	details := map[string]any{"summary": "socket-proxy operational event", "severity": 6, "result": "success"}
	switch kind {
	case Started:
		details["summary"] = "socket-proxy listener starting"
		details["status"] = "Started"
		details["error.data"] = map[string]any{"tls_enabled": fields.TLS, "image_allowlist_entries": fields.ImageAllowlistEntries}
	case Denied, UpstreamFailed, ProcessFailed, TelemetryFailed:
		details["summary"] = "socket-proxy request or process failure"
		details["severity"] = 3
		details["result"] = "failure"
		reason := fields.Reason
		if reason == "" {
			reason = "operation_failed"
		}
		details["failure.reason"] = reason
		details["error.data"] = map[string]any{"http_status": fields.Status}
	case Stopped:
		details["summary"] = "socket-proxy listener stopped"
		details["status"] = "Completed"
	case ProcessMessage:
		details["summary"] = "socket-proxy HTTP server diagnostic"
	}
	return map[string]any{"event.uuid": newUUID(), "event.definition.uuid": definitions[kind], "event.signature": ProjectSignature, "event.sub.type": kind, "event.type": "Activity", "time.stamp": time.Now().UTC().Format(time.RFC3339Nano), "event.details": details}
}

// Emit serializes one registered operational event. Sink errors are returned and
// a separate stderr event exposes the failure without including the raw error.
func (e *Emitter) Emit(kind Kind, fields Fields) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := definitions[kind]; !ok {
		e.reportFailure("unregistered_event")
		return fmt.Errorf("cornerstone: unregistered socket-proxy event")
	}
	encoded, err := telemetry.Marshal(record(kind, fields), e.identity)
	if err == nil {
		err = telemetry.Write(e.w, encoded)
	}
	if err != nil {
		e.reportFailure("event_write_failed")
		return fmt.Errorf("cornerstone: emit: %w", err)
	}
	return nil
}
func (e *Emitter) reportFailure(reason string) {
	if e.diagnostics == nil {
		return
	}
	encoded, _ := telemetry.Marshal(record(TelemetryFailed, Fields{Reason: reason}), e.identity)
	_ = telemetry.Write(e.diagnostics, encoded)
}

// Write implements an http.Server ErrorLog sink. Its potentially remote-derived
// text is deliberately discarded; collectors capture lower-trust raw streams.
func (e *Emitter) Write(p []byte) (int, error) {
	err := e.Emit(ProcessMessage, Fields{})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
