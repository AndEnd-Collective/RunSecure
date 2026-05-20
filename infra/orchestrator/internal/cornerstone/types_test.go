package cornerstone

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvent_MarshalsWithDotNotationKeys(t *testing.T) {
	e := Event{
		EventUUID:      "01HXG9K3MZ4T8V1WPF2R6YB7CD",
		EventSignature: "runsecure-orchestrator-v1",
		EventSubType:   "runsecure.orchestrator.spawn.started",
		EventType:      EventTypeChange,
		TimeStamp:      "2026-05-19T10:00:00Z",
		EventDetails: EventDetails{
			Summary:  "spawn intent acquired semaphores",
			Severity: 6,
			Result:   ResultSuccess,
			Status:   StatusStarted,
		},
	}
	b, err := json.Marshal(e)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))

	require.Equal(t, "01HXG9K3MZ4T8V1WPF2R6YB7CD", m["event.uuid"])
	require.Equal(t, "runsecure-orchestrator-v1", m["event.signature"])
	require.Equal(t, "runsecure.orchestrator.spawn.started", m["event.sub.type"])
	require.Equal(t, "Change", m["event.type"])
	require.Equal(t, "2026-05-19T10:00:00Z", m["time.stamp"])
	details := m["event.details"].(map[string]any)
	require.Equal(t, "spawn intent acquired semaphores", details["summary"])
	require.EqualValues(t, 6, details["severity"])
	require.Equal(t, "success", details["result"])
	require.Equal(t, "Started", details["status"])
}

func TestEventDetails_FailureRequiresReason(t *testing.T) {
	d := EventDetails{
		Summary:       "spawn failed",
		Severity:      3,
		Result:        ResultFailure,
		FailureReason: "socket_proxy_403_capadd_denied",
	}
	require.NoError(t, d.Validate())

	d2 := EventDetails{Summary: "x", Severity: 3, Result: ResultFailure}
	require.ErrorIs(t, d2.Validate(), ErrFailureReasonRequired)
}

func TestEventDetails_SeverityRange(t *testing.T) {
	require.Error(t, EventDetails{Summary: "x", Severity: -1, Result: ResultSuccess}.Validate())
	require.Error(t, EventDetails{Summary: "x", Severity: 8, Result: ResultSuccess}.Validate())
}

func TestEventDetails_SummaryRequired(t *testing.T) {
	require.Error(t, EventDetails{Severity: 6, Result: ResultSuccess}.Validate())
}
