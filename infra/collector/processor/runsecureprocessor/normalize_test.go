package runsecureprocessor

import (
	"context"
	"encoding/json"
	"errors"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/processor"
	"math"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
)

func fixture(namespace, container, body string) plog.Logs {
	logs := plog.NewLogs()
	r := logs.ResourceLogs().AppendEmpty()
	r.Resource().Attributes().PutStr("k8s.namespace.name", namespace)
	r.Resource().Attributes().PutStr("k8s.container.name", container)
	r.Resource().Attributes().PutStr("k8s.pod.name", "runsecure-orchestrator-123")
	r.Resource().Attributes().PutStr("k8s.pod.uid", "host-derived-uid")
	r.Resource().Attributes().PutStr("rs.source.class", "cri")
	r.Resource().Attributes().PutStr("attacker", "secret=bad")
	l := r.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	l.Body().SetStr(body)
	l.Attributes().PutStr("cornerstone.event.signature", "forged")
	l.Attributes().PutBool("cornerstone.validation.valid", true)
	return logs
}

func decoded(t *testing.T, logs plog.Logs) (map[string]any, plog.LogRecord) {
	t.Helper()
	l := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	var event map[string]any
	if err := json.Unmarshal([]byte(l.Body().Str()), &event); err != nil {
		t.Fatal(err)
	}
	return event, l
}

func TestWorkloadCannotForgeControllerOrValidation(t *testing.T) {
	logs := fixture("runsecure-execution", "runner", `{"event.signature":"runsecure-orchestrator-v1","event.uuid":"forged","authorization":"Bearer leakedsecret"}`)
	if err := normalizeLogs(context.Background(), logs, &Config{Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	e, l := decoded(t, logs)
	if e["event.signature"] != "runsecure-telemetry-v1" || e["event.definition.uuid"] != "413ad39d-47ae-49c0-beee-aedeab2b73fd" {
		t.Fatalf("forged event promoted: %v", e)
	}
	if strings.Contains(l.Body().Str(), "leakedsecret") {
		t.Fatal("secret survived")
	}
	if _, ok := l.Attributes().Get("cornerstone.validation.valid"); ok {
		t.Fatal("forged validation survived")
	}
	if _, ok := logs.ResourceLogs().At(0).Resource().Attributes().Get("attacker"); ok {
		t.Fatal("uncontrolled resource survived")
	}
}

func TestTrustedEnvelopeAndActorMetadata(t *testing.T) {
	body := `{"event.signature":"runsecure-orchestrator-v1","event.definition.uuid":"d91e6572-4b37-4d96-b963-3becc43e3401","event.uuid":"661a54ed-56f2-4a15-9d38-f6f35f537166","event.type":"Activity","time.stamp":"2026-10-29T01:00:00Z","event.details":{"summary":"received","severity":6,"result":"success"},"k8s.context":{"k8s.pod.uid":"forged"}}`
	logs := fixture("runsecure-system", "orchestrator", body)
	config := &Config{Environment: "Testing", MaxBodyBytes: 4096, TrustedSources: []TrustedSource{{Namespace: "runsecure-system", Container: "orchestrator", PodNamePrefix: "runsecure-orchestrator-", Signature: "runsecure-orchestrator-v1"}}}
	if err := normalizeLogs(context.Background(), logs, config); err != nil {
		t.Fatal(err)
	}
	e, l := decoded(t, logs)
	if e["event.signature"] != "runsecure-orchestrator-v1" {
		t.Fatal("trusted envelope lost")
	}
	if e["k8s.context"].(map[string]any)["k8s.pod.uid"] != "host-derived-uid" {
		t.Fatal("producer actor replaced trusted metadata")
	}
	if v, ok := l.Attributes().Get("cornerstone.event.signature"); !ok || v.Str() != "runsecure-orchestrator-v1" {
		t.Fatal("not mapped into OTEL attributes")
	}
}

func TestRedactionBeforePersistentAgentQueue(t *testing.T) {
	logs := fixture("runsecure-execution", "runner", "token=not-for-disk https://host/path?signature=private")
	if err := normalizeLogs(context.Background(), logs, &Config{RedactOnly: true, Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	l := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if strings.Contains(l.Body().Str(), "not-for-disk") || strings.Contains(l.Body().Str(), "signature=") {
		t.Fatal("queue would persist secret")
	}
	if l.Attributes().Len() != 0 {
		t.Fatal("producer attributes persisted")
	}
	if v, _ := logs.ResourceLogs().At(0).Resource().Attributes().Get("rs.source.class"); v.Str() != "cri" {
		t.Fatal("trusted routing metadata lost")
	}
}

func TestMalformedAndOversizedAreExplicitCaptureEvents(t *testing.T) {
	for _, body := range []string{"{bad", strings.Repeat("x", maxInputBytes+1), "token=" + strings.Repeat("s", 5000)} {
		logs := fixture("runsecure-execution", "runner", body)
		if err := normalizeLogs(context.Background(), logs, &Config{Environment: "Testing", MaxBodyBytes: 256}); err != nil {
			t.Fatal(err)
		}
		e, l := decoded(t, logs)
		if e["event.details"].(map[string]any)["result"] != "success" {
			t.Fatal("capture result wrong")
		}
		if len(l.Body().Str()) > 4096 {
			t.Fatal("unbounded body")
		}
	}
}

func TestSecretsAndMalformedSuffixNeverEnterQueue(t *testing.T) {
	for _, body := range []string{`token="opaque-value"`, `password='opaque value'`, `[{"token":"opaque-value"}]`, `{"message":"token=\"opaque-value\""}`} {
		t.Run(body, func(t *testing.T) {
			logs := fixture("execution", "runner", body)
			if err := normalizeLogs(context.Background(), logs, &Config{RedactOnly: true, Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
				t.Fatal(err)
			}
			got := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
			if strings.Contains(got, "opaque") {
				t.Fatalf("credential enters queue: %s", got)
			}
		})
	}
	logs := fixture("execution", "runner", `{"safe":"first"} trailing-diagnostic`)
	if err := normalizeLogs(context.Background(), logs, &Config{Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	e, _ := decoded(t, logs)
	if !strings.Contains(e["event.details"].(map[string]any)["message"].(string), "trailing-diagnostic") {
		t.Fatal("trailing diagnostic silently lost")
	}
}
func TestByteBodiesAreRedactedOrExplicitlyRejected(t *testing.T) {
	for _, raw := range [][]byte{[]byte("token=opaque-value"), {255, 254, 253}} {
		logs := fixture("execution", "runner", "")
		body := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body()
		body.SetEmptyBytes().FromRaw(raw)
		if err := normalizeLogs(context.Background(), logs, &Config{RedactOnly: true, Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.Str(), "opaque") || strings.Contains(body.Str(), "dG9rZW49b3BhcXVlLXZhbHVl") {
			t.Fatal("recoverable encoded secret persisted")
		}
	}
}
func TestConfigurationRejectsUnsafeIdentities(t *testing.T) {
	good := Config{Environment: "Testing", MaxBodyBytes: 256, TrustedSources: []TrustedSource{{Namespace: "management", Container: "orchestrator", PodNamePrefix: "runsecure-", Signature: "runsecure-orchestrator-v1"}}}
	for _, env := range []string{"Development", "Testing", "Staging", "Production"} {
		c := good
		c.Environment = env
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*Config){func(c *Config) { c.Environment = "testing" }, func(c *Config) { c.MaxBodyBytes = 255 }, func(c *Config) { c.MaxBodyBytes = 65537 }, func(c *Config) { c.TrustedSources[0].Namespace = "bad ns" }, func(c *Config) { c.TrustedSources[0].Container = "UPPER" }, func(c *Config) { c.TrustedSources[0].PodNamePrefix = "*" }, func(c *Config) { c.TrustedSources[0].Signature = "forged" }} {
		c := good
		c.TrustedSources = append([]TrustedSource(nil), good.TrustedSources...)
		change(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	good.MaxBodyBytes = 65536
	good.TrustedSources[0].Signature = "runsecure-socket-proxy-v1"
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestFactoryLifecycleAndDeliveryFailure(t *testing.T) {
	f := NewFactory()
	cfg := f.CreateDefaultConfig().(*Config)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("destination unavailable")
	calls := 0
	next, err := consumer.NewLogs(func(_ context.Context, logs plog.Logs) error {
		calls++
		e, l := decoded(t, logs)
		if e["event.signature"] != "runsecure-telemetry-v1" || strings.Contains(l.Body().Str(), "private-value") {
			t.Fatal("unsafe record forwarded")
		}
		return wantErr
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.CreateLogs(context.Background(), processor.Settings{ID: component.NewID(f.Type())}, cfg, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !p.Capabilities().MutatesData {
		t.Fatal("mutation capability not advertised")
	}
	if err := p.ConsumeLogs(context.Background(), fixture("execution", "runner", "token=private-value")); !errors.Is(err, wantErr) {
		t.Fatalf("downstream failure hidden: %v", err)
	}
	if calls != 1 {
		t.Fatal("unexpected forwarding count")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := createLogs(context.Background(), processor.Settings{}, &struct{}{}, next); err == nil {
		t.Fatal("wrong config accepted")
	}
	bad := *cfg
	bad.Environment = "invalid"
	if _, err := createLogs(context.Background(), processor.Settings{}, &bad, next); err == nil {
		t.Fatal("invalid config accepted")
	}
}
func validFixtureEvent() map[string]any {
	return map[string]any{"event.signature": "runsecure-orchestrator-v1", "event.uuid": "661a54ed-56f2-4a15-9d38-f6f35f537166", "event.definition.uuid": "d91e6572-4b37-4d96-b963-3becc43e3401", "event.type": "Change", "time.stamp": "2026-10-29T00:00:00Z", "event.details": map[string]any{"summary": "fixture", "severity": json.Number("6"), "result": "success"}}
}
func TestMalformedTrustedInputsBecomeReceipts(t *testing.T) {
	c := &Config{Environment: "Production", MaxBodyBytes: 4096, TrustedSources: []TrustedSource{{Namespace: "management", Container: "orchestrator", PodNamePrefix: "runsecure-", Signature: "runsecure-orchestrator-v1"}}}
	changes := []func(map[string]any){func(e map[string]any) { e["event.signature"] = "bad" }, func(e map[string]any) { e["event.uuid"] = 1 }, func(e map[string]any) { e["event.definition.uuid"] = "bad" }, func(e map[string]any) { e["event.type"] = "Audit" }, func(e map[string]any) { e["time.stamp"] = false }, func(e map[string]any) { e["time.stamp"] = "yesterday" }, func(e map[string]any) { e["event.details"] = "bad" }, func(e map[string]any) { e["event.details"].(map[string]any)["summary"] = false }, func(e map[string]any) { e["event.details"].(map[string]any)["summary"] = "" }, func(e map[string]any) { e["event.details"].(map[string]any)["severity"] = "6" }, func(e map[string]any) { e["event.details"].(map[string]any)["severity"] = json.Number("1.5") }, func(e map[string]any) { e["event.details"].(map[string]any)["severity"] = json.Number("-1") }, func(e map[string]any) { e["event.details"].(map[string]any)["severity"] = json.Number("8") }, func(e map[string]any) { e["event.details"].(map[string]any)["result"] = "bad" }, func(e map[string]any) { e["event.details"].(map[string]any)["result"] = "failure" }}
	for i, change := range changes {
		e := validFixtureEvent()
		change(e)
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		logs := fixture("management", "orchestrator", string(raw))
		if err := normalizeLogs(context.Background(), logs, c); err != nil {
			t.Fatal(err)
		}
		got, _ := decoded(t, logs)
		if got["event.signature"] != "runsecure-telemetry-v1" {
			t.Fatalf("malformed variant %d promoted", i)
		}
	}
	e := validFixtureEvent()
	e["event.details"].(map[string]any)["result"] = "failure"
	e["event.details"].(map[string]any)["failure.reason"] = "expected_failure"
	raw, _ := json.Marshal(e)
	logs := fixture("management", "orchestrator", string(raw))
	if err := normalizeLogs(context.Background(), logs, c); err != nil {
		t.Fatal(err)
	}
	got, _ := decoded(t, logs)
	if got["event.signature"] != "runsecure-orchestrator-v1" {
		t.Fatal("valid Change/failure lost")
	}
	for _, key := range []string{"rs.source.class", "k8s.namespace.name", "k8s.container.name", "k8s.pod.name"} {
		logs := fixture("management", "orchestrator", string(raw))
		logs.ResourceLogs().At(0).Resource().Attributes().PutStr(key, "untrusted")
		if err := normalizeLogs(context.Background(), logs, c); err != nil {
			t.Fatal(err)
		}
		got, _ := decoded(t, logs)
		if got["event.signature"] != "runsecure-telemetry-v1" {
			t.Fatal("mismatched source promoted")
		}
	}
}
func TestCaptureClassTimeAndResourceAllowlist(t *testing.T) {
	for _, class := range []string{"host", "collector", "cri"} {
		logs := fixture("kube-system", "platform", "raw")
		r := logs.ResourceLogs().At(0)
		r.Resource().Attributes().PutStr("rs.source.class", class)
		r.Resource().Attributes().PutStr("cloud.provider", "aws")
		r.Resource().Attributes().PutStr("host.name", strings.Repeat("x", 257))
		r.Resource().Attributes().PutInt("cloud.account.id", 12)
		l := r.ScopeLogs().At(0).LogRecords().At(0)
		l.SetTimestamp(pcommon.NewTimestampFromTime(time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)))
		if err := normalizeLogs(context.Background(), logs, &Config{Environment: "Testing", MaxBodyBytes: 4096}); err != nil {
			t.Fatal(err)
		}
		got, _ := decoded(t, logs)
		want := "728f38f1-ac65-4dc5-8591-fcdb8325437c"
		if class == "host" {
			want = "57a837ff-4190-467b-b32b-0832d53430f5"
		}
		if got["event.definition.uuid"] != want || got["time.stamp"] != "2026-10-29T00:00:00Z" {
			t.Fatal("classification/time lost")
		}
		if _, ok := r.Resource().Attributes().Get("host.name"); ok {
			t.Fatal("unbounded attr survived")
		}
		if got["cloud.context"].(map[string]any)["cloud.provider"] != "aws" {
			t.Fatal("cloud identity lost")
		}
		if attr, ok := l.Attributes().Get("cornerstone.cloud.context.cloud.provider"); !ok || attr.Str() != "aws" {
			t.Fatal("actual enricher context attribute contract lost")
		}
	}
}
func TestTypedBodyBoundsAndNumericMeaning(t *testing.T) {
	v := pcommon.NewValueMap()
	if err := v.Map().FromRaw(map[string]any{"safe": int64(9007199254740993), "password": "private-value"}); err != nil {
		t.Fatal(err)
	}
	got, _ := scrubBody(bodyText(v), 4096)
	if strings.Contains(got, "private-value") || !strings.Contains(got, "9007199254740993") {
		t.Fatal("secret/integer handling regressed")
	}
	if bodyText(pcommon.NewValueDouble(math.NaN())) != "[unsupported log value]" {
		t.Fatal("unsupported value escaped")
	}
	got, truncated := scrubBody(strings.Repeat("€", 1000), 256)
	if !truncated || !strings.Contains(got, "capture truncated") {
		t.Fatal("UTF8 limit lost")
	}
	converted := otelValue(map[string]any{"int": json.Number("9007199254740993"), "fraction": json.Number("1.5"), "huge": json.Number("1e99999"), "array": []any{json.Number("2"), true}}).(map[string]any)
	if converted["int"] != int64(9007199254740993) || converted["fraction"] != float64(1.5) || converted["huge"] != "1e99999" || converted["array"].([]any)[0] != int64(2) {
		t.Fatal("OTEL conversion changed values")
	}
}

func TestPreparedEventCommitIsAtomicAndRejectsUnsupportedValues(t *testing.T) {
	for _, input := range []map[string]any{
		{"event.details": map[string]any{"bad": make(chan int)}},
		{"k8s.context": map[string]any{"bad": make(chan int)}},
		{"ordinary": make(chan int)},
		{"ordinary": math.NaN()},
	} {
		logs := fixture("execution", "runner", "original-safe-body")
		l := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		if err := writePreparedEvent(l, input); err == nil {
			t.Fatal("unsupported/unencodable prepared event accepted")
		}
		if l.Body().Str() != "original-safe-body" {
			t.Fatal("failed preparation partially committed body")
		}
		if v, ok := l.Attributes().Get("cornerstone.validation.valid"); !ok || !v.Bool() {
			t.Fatal("failed preparation partially committed attrs")
		}
	}
	logs := fixture("execution", "runner", "")
	l := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	event := map[string]any{"event.details": map[string]any{"big": json.Number("18446744073709551616")}, "cornerstone.validation.valid": true}
	if err := writePreparedEvent(l, event); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.Body().Str(), "18446744073709551616") {
		t.Fatal("attribute conversion rounded body integer")
	}
	if _, ok := l.Attributes().Get("cornerstone.cornerstone.validation.valid"); ok {
		t.Fatal("producer validation copied as processor assertion")
	}
	if _, ok := event["event.details"].(map[string]any)["big"].(json.Number); !ok {
		t.Fatal("attribute conversion mutated input representation")
	}
}
func TestTrustedProducerCannotOverrideProcessorClaimsOrActorPrefixes(t *testing.T) {
	event := validFixtureEvent()
	event["cornerstone.validation.valid"] = true
	event["k8s.context.k8s.pod.uid"] = "forged-actor"
	event["cloud.context.cloud.provider"] = "forged-cloud"
	raw, _ := json.Marshal(event)
	logs := fixture("management", "orchestrator", string(raw))
	c := &Config{Environment: "Testing", MaxBodyBytes: 4096, TrustedSources: []TrustedSource{{Namespace: "management", Container: "orchestrator", PodNamePrefix: "runsecure-", Signature: "runsecure-orchestrator-v1"}}}
	if err := normalizeLogs(context.Background(), logs, c); err != nil {
		t.Fatal(err)
	}
	got, l := decoded(t, logs)
	for _, key := range []string{"cornerstone.validation.valid", "k8s.context.k8s.pod.uid", "cloud.context.cloud.provider"} {
		if _, ok := got[key]; ok {
			t.Fatalf("producer claim persisted as top-level field: %s", key)
		}
	}
	if v, ok := l.Attributes().Get("cornerstone.k8s.context.k8s.pod.uid"); !ok || v.Str() != "host-derived-uid" {
		t.Fatal("dotted alias overrode host actor")
	}
}

func TestStructuredQuotedCredentialKeepsTrustedEnvelopeAndValidJSON(t *testing.T) {
	event := validFixtureEvent()
	event["event.details"].(map[string]any)["message"] = `token="opaque-value"`
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	logs := fixture("management", "orchestrator", string(raw))
	c := &Config{Environment: "Testing", MaxBodyBytes: 4096, TrustedSources: []TrustedSource{{Namespace: "management", Container: "orchestrator", PodNamePrefix: "runsecure-", Signature: "runsecure-orchestrator-v1"}}}
	if err := normalizeLogs(context.Background(), logs, c); err != nil {
		t.Fatal(err)
	}
	got, l := decoded(t, logs)
	if got["event.signature"] != "runsecure-orchestrator-v1" {
		t.Fatalf("structured redaction corrupted trusted envelope: %s", l.Body().Str())
	}
	message := got["event.details"].(map[string]any)["message"].(string)
	if strings.Contains(message, "opaque-value") || !strings.Contains(message, "REDACTED") {
		t.Fatal("quoted credential redaction was lost")
	}
}
