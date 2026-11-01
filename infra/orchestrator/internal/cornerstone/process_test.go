package cornerstone

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"
)

func TestProcessEventsPreserveSignatureAndRegisteredDefinitions(t *testing.T) {
	var out bytes.Buffer
	em := NewEmitter(&out, SystemClock, SystemUUID)
	require.NoError(t, em.EmitProcessStarted("dev", "fixture", "kube"))
	require.NoError(t, em.EmitProcessStopping("signal_received"))
	require.NoError(t, em.EmitProcessFailed("startup_failed"))
	require.NoError(t, em.EmitProcessMessage("legacy configuration warning"))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4)
	for _, line := range lines {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		require.Equal(t, ProjectSignature, event["event.signature"])
		require.Equal(t, eventDefinitions[event["event.sub.type"].(string)], event["event.definition.uuid"])
	}
}

type shortWriteSink struct{}

func (shortWriteSink) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestEmitterShortWriteAndInvalidDefinitionHaveSafeDiagnostics(t *testing.T) {
	var diagnostic bytes.Buffer
	em := NewEmitter(shortWriteSink{}, SystemClock, SystemUUID)
	em.SetDiagnosticWriter(&diagnostic)
	require.ErrorIs(t, em.EmitHealthProbe(), io.ErrShortWrite)
	require.Contains(t, diagnostic.String(), `"failure.reason":"write_failed"`)
	for _, event := range []Event{
		{EventSubType: "unregistered-private-value"},
		{EventSubType: EventHealthProbe, EventDefinitionUUID: "mismatched-private-value"},
		{EventSubType: EventHealthProbe, EventDetails: EventDetails{Summary: "private-value", Severity: 90, Result: ResultSuccess}},
	} {
		diagnostic.Reset()
		require.Error(t, em.Emit(event))
		require.Contains(t, diagnostic.String(), EventTelemetryFailed)
		require.NotContains(t, diagnostic.String(), "private-value")
	}
	em.SetDiagnosticWriter(nil)
	require.Error(t, em.Emit(Event{}))
}

func TestHTTPServerDiagnosticsDiscardRemoteDerivedText(t *testing.T) {
	var out bytes.Buffer
	em := NewEmitter(&out, SystemClock, SystemUUID)
	raw := []byte("remote-controlled privatevalue")
	n, err := em.Write(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), n)
	require.Contains(t, out.String(), EventProcessMessage)
	require.NotContains(t, out.String(), "privatevalue")
	failed := NewEmitter(shortWriteSink{}, SystemClock, SystemUUID)
	failed.SetDiagnosticWriter(nil)
	n, err = failed.Write(raw)
	require.Error(t, err)
	require.Zero(t, n)
}
