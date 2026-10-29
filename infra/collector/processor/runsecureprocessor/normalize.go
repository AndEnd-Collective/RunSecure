// Package runsecureprocessor adapts host-attributed log records to the public
// Cornerstone event envelope. It does not assert schema/signature validation;
// the pinned Cornerstone processors must run immediately after this adapter.
package runsecureprocessor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"runsecure/collector/processor/internal/telemetry"
)

const maxInputBytes = 1024 * 1024

type TrustedSource struct {
	Namespace     string `mapstructure:"namespace"`
	Container     string `mapstructure:"container"`
	PodNamePrefix string `mapstructure:"pod_name_prefix"`
	Signature     string `mapstructure:"signature"`
}

type Config struct {
	TrustedSources []TrustedSource `mapstructure:"trusted_sources"`
	Environment    string          `mapstructure:"environment"`
	MaxBodyBytes   int             `mapstructure:"max_body_bytes"`
	RedactOnly     bool            `mapstructure:"redact_only"`
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
var uuid = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func (c *Config) Validate() error {
	if c.Environment != "Development" && c.Environment != "Testing" && c.Environment != "Staging" && c.Environment != "Production" {
		return errors.New("environment must be a canonical deployment environment")
	}
	if c.MaxBodyBytes < 256 || c.MaxBodyBytes > 65536 {
		return errors.New("max_body_bytes must be between 256 and 65536")
	}
	for _, s := range c.TrustedSources {
		if !identifier.MatchString(s.Namespace) || !identifier.MatchString(s.Container) || !identifier.MatchString(s.PodNamePrefix) || (s.Signature != "runsecure-orchestrator-v1" && s.Signature != "runsecure-socket-proxy-v1") {
			return errors.New("invalid trusted source identity or signature")
		}
	}
	return nil
}

func NewFactory() processor.Factory {
	return processor.NewFactory(component.MustNewType("runsecure_normalize"), func() component.Config { return &Config{Environment: "Testing", MaxBodyBytes: 65536} }, processor.WithLogs(createLogs, component.StabilityLevelBeta))
}

type logsProcessor struct {
	config *Config
	next   consumer.Logs
}

func createLogs(_ context.Context, _ processor.Settings, c component.Config, next consumer.Logs) (processor.Logs, error) {
	config, ok := c.(*Config)
	if !ok {
		return nil, errors.New("unexpected processor config")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &logsProcessor{config, next}, nil
}
func (*logsProcessor) Start(context.Context, component.Host) error { return nil }
func (*logsProcessor) Shutdown(context.Context) error              { return nil }
func (*logsProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}
func (p *logsProcessor) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	if err := normalizeLogs(ctx, logs, p.config); err != nil {
		return err
	}
	return p.next.ConsumeLogs(ctx, logs)
}

var resourceKeys = map[string]bool{
	"k8s.cluster.name": true, "k8s.namespace.name": true, "k8s.pod.name": true, "k8s.pod.uid": true, "k8s.container.name": true, "k8s.node.name": true,
	"host.name": true, "cloud.provider": true, "cloud.account.id": true, "cloud.region": true, "cloud.availability_zone": true, "rs.source.class": true,
}

func cleanResources(attrs pcommon.Map) map[string]string {
	values := map[string]string{}
	attrs.RemoveIf(func(k string, v pcommon.Value) bool {
		if !resourceKeys[k] || v.Type() != pcommon.ValueTypeStr || len(v.Str()) > 256 {
			return true
		}
		// Receiver/resource processors supply these values. Workload JSON is never
		// allowed to overwrite them; arbitrary OTLP ingress is not supported.
		clean := telemetry.RedactString(v.Str())
		attrs.PutStr(k, clean)
		values[k] = clean
		return false
	})
	return values
}

func normalizeLogs(_ context.Context, logs plog.Logs, c *Config) error {
	var result error
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		r := logs.ResourceLogs().At(i)
		resource := cleanResources(r.Resource().Attributes())
		for j := 0; j < r.ScopeLogs().Len(); j++ {
			s := r.ScopeLogs().At(j)
			s.Scope().Attributes().Clear()
			s.Scope().SetName("runsecure.capture")
			s.Scope().SetVersion("")
			for k := 0; k < s.LogRecords().Len(); k++ {
				result = errors.Join(result, normalizeRecord(s.LogRecords().At(k), resource, c))
			}
		}
	}
	return result
}

func bodyText(v pcommon.Value) string {
	if v.Type() == pcommon.ValueTypeStr {
		return v.Str()
	}
	if v.Type() == pcommon.ValueTypeBytes {
		if utf8.Valid(v.Bytes().AsRaw()) {
			return string(v.Bytes().AsRaw())
		}
		return "[binary log body not captured]"
	}
	raw, err := json.Marshal(v.AsRaw())
	if err != nil {
		return "[unsupported log value]"
	}
	return string(raw)
}

func scrubBody(text string, limit int) (string, bool) {
	if len(text) > maxInputBytes {
		return "[record exceeds capture input limit; original not persisted]", true
	}
	// Structured decoding catches secret-valued keys even when arbitrary strings
	// do not resemble known tokens. Opaque output still receives pattern redaction.
	var obj any
	structured := false
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	if d.Decode(&obj) == nil && obj != nil && jsonEOF(d) {
		if encoded, err := telemetry.Marshal(map[string]any{"capture": obj}, telemetry.Identity{}); err == nil {
			var wrapper map[string]json.RawMessage
			if json.Unmarshal(encoded, &wrapper) == nil {
				text = string(wrapper["capture"])
				structured = true
			}
		}
	}
	// Structured values were recursively redacted before encoding. Running a
	// second regex over escaped JSON can corrupt quoted nested strings and
	// demote an otherwise valid producer envelope to a raw receipt.
	if !structured {
		text = telemetry.RedactString(text)
	}
	text = strings.ToValidUTF8(text, "�")
	if len(text) <= limit {
		return text, false
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end] + " [capture truncated after redaction]", true
}

func expectedSignature(resource map[string]string, c *Config) string {
	if resource["rs.source.class"] != "cri" {
		return ""
	}
	for _, s := range c.TrustedSources {
		if s.Namespace == resource["k8s.namespace.name"] && s.Container == resource["k8s.container.name"] && strings.HasPrefix(resource["k8s.pod.name"], s.PodNamePrefix) {
			return s.Signature
		}
	}
	return ""
}

func validEnvelope(event map[string]any, signature string) bool {
	if signature == "" || event["event.signature"] != signature {
		return false
	}
	for _, key := range []string{"event.uuid", "event.definition.uuid"} {
		v, ok := event[key].(string)
		if !ok || !uuid.MatchString(v) {
			return false
		}
	}
	typeName, ok := event["event.type"].(string)
	if !ok || (typeName != "Activity" && typeName != "Change") {
		return false
	}
	stamp, ok := event["time.stamp"].(string)
	if !ok {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		return false
	}
	details, ok := event["event.details"].(map[string]any)
	if !ok {
		return false
	}
	summary, ok := details["summary"].(string)
	if !ok || summary == "" {
		return false
	}
	severity, ok := details["severity"].(json.Number)
	if !ok {
		return false
	}
	n, err := severity.Int64()
	if err != nil || n < 0 || n > 7 {
		return false
	}
	if details["result"] != "success" && details["result"] != "failure" {
		return false
	}
	if details["result"] == "failure" {
		reason, ok := details["failure.reason"].(string)
		if !ok || reason == "" {
			return false
		}
	}
	return true
}

func captureEvent(text string, resource map[string]string, l plog.LogRecord, truncated bool) map[string]any {
	class := resource["rs.source.class"]
	kind, id := "workload", "413ad39d-47ae-49c0-beee-aedeab2b73fd"
	if class == "host" {
		kind, id = "host", "57a837ff-4190-467b-b32b-0832d53430f5"
	} else if class == "collector" || expectedInfrastructure(resource) {
		kind, id = "infrastructure", "728f38f1-ac65-4dc5-8591-fcdb8325437c"
	}
	var random [16]byte
	// Supported Go crypto/rand.Read terminates on entropy failure; it cannot
	// return a recoverable error or silently produce a weak identifier.
	rand.Read(random[:])
	random[6] = (random[6] & 15) | 64
	random[8] = (random[8] & 63) | 128
	eventID := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
	stamp := l.Timestamp().AsTime()
	if l.Timestamp() == 0 {
		stamp = time.Now().UTC()
	}
	tags := []any{"source:" + kind, "untrusted-content", "capture-receipt"}
	if truncated {
		tags = append(tags, "capture-truncated")
	}
	return map[string]any{"event.uuid": eventID, "event.definition.uuid": id, "event.sub.type": "runsecure.telemetry." + kind + ".log", "event.signature": "runsecure-telemetry-v1", "event.type": "Activity", "time.stamp": stamp.UTC().Format(time.RFC3339Nano), "event.details": map[string]any{"summary": "Captured " + kind + " log", "message": text, "severity": 6, "result": "success", "tags": tags}}
}

// Platform namespace identity is derived from host paths, not labels supplied
// inside the log message. This only classifies raw captures, never validation.
func expectedInfrastructure(r map[string]string) bool {
	return r["k8s.namespace.name"] == "kube-system" || r["k8s.namespace.name"] == "runsecure-system"
}

func normalizeRecord(l plog.LogRecord, r map[string]string, c *Config) error {
	text, truncated := scrubBody(bodyText(l.Body()), c.MaxBodyBytes)
	l.Attributes().Clear()
	l.SetTraceID(pcommon.TraceID{})
	l.SetSpanID(pcommon.SpanID{})
	l.SetFlags(0)
	l.SetSeverityText("")
	if c.RedactOnly {
		l.Body().SetStr(text)
		return nil
	}
	var event map[string]any
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	if decoder.Decode(&event) != nil || !jsonEOF(decoder) || !validEnvelope(event, expectedSignature(r, c)) || truncated {
		event = captureEvent(text, r, l, truncated)
	}
	// Replace any producer-supplied actor metadata, including trusted components,
	// with the host-attributed source. Do not confuse the runner target with actor.
	for key := range event {
		if key == "cornerstone" || strings.HasPrefix(key, "cornerstone.") || key == "k8s.context" || strings.HasPrefix(key, "k8s.context.") || key == "cloud.context" || strings.HasPrefix(key, "cloud.context.") {
			delete(event, key)
		}
	}
	k8s := map[string]any{}
	cloud := map[string]any{}
	for key, value := range r {
		if strings.HasPrefix(key, "k8s.") {
			k8s[key] = value
		}
		if strings.HasPrefix(key, "cloud.") {
			cloud[key] = value
		}
	}
	if len(k8s) > 0 {
		event["k8s.context"] = k8s
	}
	if len(cloud) > 0 {
		event["cloud.context"] = cloud
	}
	event["deployment.environment"] = c.Environment
	// scrubBody has already redacted the decoded event. Generated capture
	// fields and host resources are bounded, redacted values as well.
	return writePreparedEvent(l, event)
}

// writePreparedEvent commits a previously redacted event only after both JSON
// encoding and OTEL conversion succeed. It preserves the JSON representation:
// attribute numeric conversion must never round or mutate the archived body.
func writePreparedEvent(l plog.LogRecord, event map[string]any) error {
	attrs, err := eventAttributes(event)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	attrs.CopyTo(l.Attributes())
	l.Body().SetStr(string(encoded))
	return nil
}

// eventAttributes translates JSON-compatible values to the actual pinned
// Cornerstone attribute contract, including flattened context children. No
// producer may supply the processor's namespaced provenance assertions.
func eventAttributes(event map[string]any) (pcommon.Map, error) {
	attrs := pcommon.NewMap()
	for key, value := range event {
		if strings.HasPrefix(key, "cornerstone.") {
			continue
		}
		if context, ok := value.(map[string]any); ok && strings.HasSuffix(key, ".context") {
			for child, item := range context {
				if err := attrs.PutEmpty("cornerstone." + key + "." + child).FromRaw(otelValue(item)); err != nil {
					return pcommon.Map{}, err
				}
			}
		} else if err := attrs.PutEmpty("cornerstone." + key).FromRaw(otelValue(value)); err != nil {
			return pcommon.Map{}, err
		}
	}
	return attrs, nil
}

func otelValue(value any) any {
	switch v := value.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = otelValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = otelValue(item)
		}
		return out
	default:
		return value
	}
}

// A valid envelope consumes the complete input. Trailing data is retained as an
// untrusted capture rather than silently discarded or promoted to a trusted event.
func jsonEOF(decoder *json.Decoder) bool { var extra any; return decoder.Decode(&extra) == io.EOF }
