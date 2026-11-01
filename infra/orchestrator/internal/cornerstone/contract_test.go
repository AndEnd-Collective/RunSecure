package cornerstone

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEmitter_DefinitionUUIDMatchesEveryRegistryRecord(t *testing.T) {
	for _, name := range AllEventNames() {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".cornerstone", "events", name+".yaml"))
			require.NoError(t, err)
			var record struct {
				Metadata struct {
					UUID string `yaml:"uuid"`
				} `yaml:"metadata"`
			}
			require.NoError(t, yaml.Unmarshal(raw, &record))
			var out bytes.Buffer
			em := NewEmitter(&out, FixedClock("2026-10-29T00:00:00Z"), FixedUUID("00000000-0000-4000-8000-000000000001"))
			require.NoError(t, em.Emit(Event{EventSubType: name, EventType: EventTypeActivity, EventDetails: EventDetails{Summary: "fixture", Severity: 6, Result: ResultSuccess}}))
			var event map[string]any
			require.NoError(t, json.Unmarshal(out.Bytes(), &event))
			require.Equal(t, record.Metadata.UUID, event["event.definition.uuid"])
		})
	}
}

func TestEmitter_UsesOnlyExplicitProcessIdentity(t *testing.T) {
	for key, value := range map[string]string{
		"RUNSECURE_K8S_CLUSTER": "fixture-cluster", "RUNSECURE_POD_NAMESPACE": "management",
		"RUNSECURE_POD_NAME": "controller-pod", "RUNSECURE_POD_UID": "pod-uid", "RUNSECURE_NODE_NAME": "node-1",
		"RUNSECURE_CLOUD_PROVIDER": "aws", "RUNSECURE_CLOUD_ACCOUNT_ID": "123456789012", "RUNSECURE_CLOUD_REGION": "us-east-2",
		"CORNERSTONE_ENV": "Production", "AWS_SECRET_ACCESS_KEY": "must-never-appear",
	} {
		t.Setenv(key, value)
	}
	var out bytes.Buffer
	em := NewEmitter(&out, FixedClock("2026-10-29T00:00:00Z"), FixedUUID("00000000-0000-4000-8000-000000000001"))
	require.NoError(t, em.EmitHealthProbe())
	var event map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &event))
	require.Equal(t, "Production", event["deployment.environment"])
	k8s, ok := event["k8s.context"].(map[string]any)
	require.True(t, ok, "explicit Downward API identity must be present")
	require.Equal(t, "controller-pod", k8s["k8s.pod.name"])
	require.Equal(t, "management", k8s["k8s.namespace.name"])
	require.Equal(t, "node-1", k8s["k8s.node.name"])
	cloud, ok := event["cloud.context"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "aws", cloud["cloud.provider"])
	require.Equal(t, "123456789012", cloud["cloud.account.id"])
	require.NotContains(t, out.String(), "must-never-appear")
}

func TestEmitter_RedactsNestedCredentialsWithoutMutatingCaller(t *testing.T) {
	data := map[string]any{
		"authorization": "Bearer opaque-private-value",
		"nested":        []any{map[string]any{"JITConfigB64": "encoded-private-value", "safe": "retained"}},
		"detail":        "GET https://example.invalid/path?X-Amz-Signature=signed-private-value Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz1234567890",
	}
	var out bytes.Buffer
	em := NewEmitter(&out, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitSpawnFailed(SpawnFailedFields{Scope: "s", Repo: "o/r", SpawnID: "i", FailureReason: "fixture_failure", ExtraErrorData: data}))
	for _, secret := range []string{"opaque-private-value", "encoded-private-value", "signed-private-value", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"} {
		require.NotContains(t, out.String(), secret)
	}
	require.Contains(t, out.String(), "retained")
	require.Equal(t, "Bearer opaque-private-value", data["authorization"], "sanitizing must not mutate shared caller data")
	require.Equal(t, 1, strings.Count(out.String(), "\n"))
}

func TestKubernetesSpawnDoesNotClaimDockerRuntimeOrBridgeNetwork(t *testing.T) {
	var out bytes.Buffer
	em := NewEmitter(&out, SystemClock, SystemUUID)
	em.SetBackend("kube")
	require.NoError(t, em.EmitSpawnRunnerCreated(SpawnRunnerCreatedFields{Scope: "s", Repo: "o/r", SpawnID: "i", ContainerName: "legacy-jit-name", ImageDigest: "image@sha256:fixture"}))
	var event map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &event))
	context := event["container.context"].(map[string]any)
	require.Equal(t, "legacy-jit-name", context["container.name"])
	require.Equal(t, "image@sha256:fixture", context["container.image.digest"])
	require.NotContains(t, context, "container.runtime")
	require.NotContains(t, event, "network.context")
	details := event["event.details"].(map[string]any)
	require.Equal(t, "kube", details["error.data"].(map[string]any)["backend"])
	out.Reset()
	data := map[string]any{"exit_code": 2}
	ev := Event{EventUUID: "existing-id", EventSignature: ProjectSignature, TimeStamp: "existing-time", EventSubType: EventSpawnFailed, EventType: EventTypeChange, ContainerContext: &ContainerContext{Runtime: "docker"}, EventDetails: EventDetails{Summary: "fixture", Severity: 3, Result: ResultFailure, FailureReason: "fixture_failure", ErrorData: data}}
	require.NoError(t, em.Emit(ev))
	require.Equal(t, "docker", ev.ContainerContext.Runtime, "must not mutate caller context")
	require.NotContains(t, data, "backend", "must not mutate caller error data")
	require.Contains(t, out.String(), `"exit_code":2`)
	require.Contains(t, out.String(), `"event.uuid":"existing-id"`)
}
