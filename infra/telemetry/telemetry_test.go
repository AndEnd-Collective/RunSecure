package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestIdentityUsesOnlyExplicitAllowlistedEnvironment(t *testing.T) {
	for _, environment := range []string{"Development", "Testing", "Staging", "Production", "invalid", ""} {
		values := map[string]string{"CORNERSTONE_ENV": environment, "RUNSECURE_K8S_CLUSTER": "cluster", "RUNSECURE_POD_NAMESPACE": "ns", "RUNSECURE_POD_NAME": "pod", "RUNSECURE_POD_UID": "uid", "RUNSECURE_NODE_NAME": "node", "RUNSECURE_CLOUD_PROVIDER": "aws", "RUNSECURE_CLOUD_ACCOUNT_ID": "123456789012", "RUNSECURE_CLOUD_REGION": "region", "RUNSECURE_CLOUD_ZONE": "zone"}
		id := fromEnv(func(key string) string { return values[key] })
		if id.Kubernetes["k8s.pod.name"] != "pod" || id.Cloud["cloud.provider"] != "aws" {
			t.Fatal(id)
		}
		if environment == "invalid" && id.Environment != "" {
			t.Fatal("unknown deployment environment emitted")
		}
	}
	id := fromEnv(func(string) string { return "" })
	if len(id.Kubernetes) != 0 || len(id.Cloud) != 0 {
		t.Fatal(id)
	}
	t.Setenv("RUNSECURE_POD_NAME", "actual-env")
	if FromEnv().Kubernetes["k8s.pod.name"] != "actual-env" {
		t.Fatal("FromEnv not wired")
	}
}

func TestMarshalRedactsTypedCollectionsAndPreservesLargeNumbers(t *testing.T) {
	input := map[string]any{"number": int64(9007199254740993), "authorization": "opaque", "nested": []map[string]string{{"access_key": "opaque", "safe": "retained"}}}
	id := Identity{Environment: "Production", Kubernetes: map[string]string{"k8s.pod.name": "emitter"}, Cloud: map[string]string{"cloud.provider": "aws"}}
	encoded, err := Marshal(input, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`9007199254740993`)) || bytes.Contains(encoded, []byte("opaque")) || !bytes.Contains(encoded, []byte("retained")) {
		t.Fatal(string(encoded))
	}
	if input["authorization"] != "opaque" {
		t.Fatal("caller input mutated")
	}
	if bytes.Count(encoded, []byte("\n")) != 1 {
		t.Fatal("must emit exactly one physical line")
	}
	explicit := map[string]any{"deployment.environment": "Testing", "k8s.context": map[string]string{"k8s.pod.name": "explicit"}, "cloud.context": map[string]string{"cloud.provider": "gcp"}}
	encoded, err = Marshal(explicit, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("Production")) || bytes.Contains(encoded, []byte("emitter")) || bytes.Contains(encoded, []byte("aws")) {
		t.Fatal("explicit context overwritten")
	}
}

func TestMarshalRejectsNonObjectAndUnserializableInput(t *testing.T) {
	for _, input := range []any{nil, []string{"array"}, make(chan int)} {
		if _, err := Marshal(input, Identity{}); err == nil {
			t.Fatalf("accepted %T", input)
		}
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if _, err := Marshal(cyclic, Identity{}); err == nil {
		t.Fatal("accepted cycle")
	}
	nested := any("secret-leaf")
	for range 40 {
		nested = []any{nested}
	}
	encoded, err := Marshal(map[string]any{"deep": nested}, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret-leaf")) || !bytes.Contains(encoded, []byte("DEPTH LIMIT")) {
		t.Fatal(string(encoded))
	}
}

func TestRecognizableCredentialsAndURLsAreRedacted(t *testing.T) {
	for _, input := range []string{
		"Bearer opaque-value", "Basic opaque-value", "github_pat_opaquevalue", "ghp_opaquevalue",
		"eyJhbGciOiJIUzI1NiJ9.opaquevalue.opaquevalue", "token=opaque-value", "password:opaque-value",
		"-----BEGIN PRIVATE KEY-----\nopaque-value\n-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nopaque-value",
		"https://user:opaque-value@example.invalid/path?token=opaque-value#opaque-value",
		"https://example.invalid/%xx?token=opaque-value",
		"api_key=opaque-value", "client_secret=opaque-value",
		`{"JITConfigB64":"opaque-value"}`, `{"encodedJITConfig":"opaque-value"}`,
		`token="opaque-value"`, `password='opaque value'`, `[{"token":"opaque-value"}]`,
		`AWS_SECRET_ACCESS_KEY="opaque-value"`, `AWS_SESSION_TOKEN='opaque value'`,
	} {
		if strings.Contains(RedactString(input), "opaque") {
			t.Errorf("credential leak for %q", input)
		}
	}
	if strings.Contains(RedactString("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"), "AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("AWS access key identifier leaked")
	}
	if !json.Valid([]byte(RedactString(`{"JITConfigB64":"opaque-value"}`))) {
		t.Fatal("redaction broke quoted JSON")
	}
	if RedactString("safe diagnostic") != "safe diagnostic" {
		t.Fatal("safe message changed")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestWriteSurfacesSinkFailureAndShortWrite(t *testing.T) {
	if !errors.Is(Write(shortWriter{}, []byte("x")), io.ErrShortWrite) {
		t.Fatal("short write hidden")
	}
	if !errors.Is(Write(failedWriter{}, []byte("x")), io.ErrClosedPipe) {
		t.Fatal("sink failure hidden")
	}
	var sink bytes.Buffer
	if err := Write(&sink, []byte("x")); err != nil || sink.String() != "x" {
		t.Fatal(err)
	}
}
