package cornerstone

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmitter_WritesOneLineJSON(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("2026-05-19T10:00:00Z"), FixedUUID("abc"))

	ev := Event{
		EventSubType: EventSpawnCompleted,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{Summary: "done", Severity: 6, Result: ResultSuccess},
	}
	require.NoError(t, em.Emit(ev))

	out := buf.String()
	require.Equal(t, 1, strings.Count(out, "\n"), "must be exactly one newline-terminated line")
	require.True(t, strings.HasSuffix(out, "\n"))

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &got))
	require.Equal(t, "abc", got["event.uuid"])
	require.Equal(t, "runsecure-orchestrator-v1", got["event.signature"])
	require.Equal(t, "2026-05-19T10:00:00Z", got["time.stamp"])
}

func TestEmitter_RejectsInvalidEvent(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("2026-05-19T10:00:00Z"), FixedUUID("abc"))

	ev := Event{
		EventSubType: EventSpawnFailed,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{Summary: "boom", Severity: 3, Result: ResultFailure},
		// FailureReason missing — must be rejected.
	}
	require.ErrorIs(t, em.Emit(ev), ErrFailureReasonRequired)
	require.Empty(t, buf.String(), "must not write a partial event")
}

func TestEmitter_FillsAutoFields(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("2026-05-19T10:00:00Z"), FixedUUID("uuid-1"))

	ev := Event{
		EventSubType: EventPollTick,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{Summary: "tick", Severity: 7, Result: ResultSuccess},
	}
	require.NoError(t, em.Emit(ev))

	var got Event
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got))
	require.Equal(t, "uuid-1", got.EventUUID)
	require.Equal(t, ProjectSignature, got.EventSignature)
	require.Equal(t, "2026-05-19T10:00:00Z", got.TimeStamp)
}

func TestSystemClockAndUUID(t *testing.T) {
	require.NotEmpty(t, SystemClock())
	require.Len(t, SystemUUID(), 36) // canonical UUID string length
}

// erroringWriter always returns an error on Write — covers emit.go's
// e.w.Write error branch.
type erroringWriter struct{}

func (erroringWriter) Write(_ []byte) (int, error) {
	return 0, errBoom
}

var errBoom = simulatedErr{}

type simulatedErr struct{}

func (simulatedErr) Error() string { return "simulated write failure" }

func TestEmitter_WriteError_PropagatesAsError(t *testing.T) {
	em := NewEmitter(erroringWriter{}, FixedClock("t"), FixedUUID("u"))
	err := em.Emit(Event{
		EventSubType: EventPollTick,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{Summary: "x", Severity: 6, Result: ResultSuccess},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cornerstone: write")
}
