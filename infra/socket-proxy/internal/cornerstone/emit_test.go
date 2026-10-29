package cornerstone

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLifecycleAndDenialsAreRegisteredCornerstoneEvents(t *testing.T) {
	var out bytes.Buffer
	emitter := NewEmitter(&out)
	for _, kind := range []Kind{Started, Denied, UpstreamFailed, Stopped, ProcessFailed, ProcessMessage, TelemetryFailed} {
		require.NoError(t, emitter.Emit(kind, Fields{Reason: "fixture_reason", Status: 403, ImageAllowlistEntries: 3, TLS: true}))
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 7)
	seen := map[string]bool{}
	for _, line := range lines {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		require.Equal(t, ProjectSignature, event["event.signature"])
		id := event["event.uuid"].(string)
		require.Len(t, id, 36)
		require.False(t, seen[id])
		seen[id] = true
		name := event["event.sub.type"].(string)
		root := filepath.Join("..", "..", "..", "..")
		raw, err := os.ReadFile(filepath.Join(root, ".cornerstone", "events", name+".yaml"))
		require.NoError(t, err)
		require.Contains(t, string(raw), "uuid: "+event["event.definition.uuid"].(string))
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestWriteFailureUsesSeparateSafeDiagnosticSink(t *testing.T) {
	var diagnostic bytes.Buffer
	emitter := NewEmitter(failedWriter{})
	emitter.SetDiagnosticWriter(&diagnostic)
	require.Error(t, emitter.Emit(Denied, Fields{Reason: "fixture_reason", Status: 403}))
	require.Contains(t, diagnostic.String(), "runsecure.socket_proxy.telemetry.failed")
	require.NotContains(t, diagnostic.String(), "closed pipe")
}

func TestUnknownKindsFailVisibly(t *testing.T) {
	var out, diagnostic bytes.Buffer
	emitter := NewEmitter(&out)
	emitter.SetDiagnosticWriter(&diagnostic)
	require.Error(t, emitter.Emit(Kind("unregistered"), Fields{}))
	require.Empty(t, out.String())
	require.Contains(t, diagnostic.String(), "unregistered_event")
}

func TestConcurrentEventsRemainWholeJSONLines(t *testing.T) {
	var out bytes.Buffer
	emitter := NewEmitter(&out)
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			require.NoError(t, emitter.Emit(Denied, Fields{Reason: "policy_denied"}))
		}()
	}
	workers.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 20)
	for _, line := range lines {
		require.True(t, json.Valid([]byte(line)))
	}
}

func TestHTTPDiagnosticDoesNotPromoteRawMessage(t *testing.T) {
	var out bytes.Buffer
	emitter := NewEmitter(&out)
	raw := []byte("hostile request body github_pat_privatevalue")
	n, err := emitter.Write(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), n)
	require.NotContains(t, out.String(), "hostile")
	require.NotContains(t, out.String(), "privatevalue")
	require.NoError(t, emitter.Emit(Denied, Fields{}))
	require.Contains(t, out.String(), "operation_failed")
	failed := NewEmitter(failedWriter{})
	failed.SetDiagnosticWriter(nil)
	n, err = failed.Write(raw)
	require.Error(t, err)
	require.Zero(t, n)
}
