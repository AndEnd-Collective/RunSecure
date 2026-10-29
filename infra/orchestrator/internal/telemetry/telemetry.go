// Package telemetry is RunSecure's in-tree JSON emission support, not an
// upstream SDK. Run sync-telemetry.py after edits; consumer copies are generated
// to preserve the orchestrator and socket-proxy's isolated Docker build contexts.
package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Identity contains only explicitly configured, non-secret process identity.
// k8s.context identifies the emitting Pod, never a spawned job Pod.
type Identity struct {
	Environment string
	Kubernetes  map[string]string
	Cloud       map[string]string
}

// FromEnv does not discover identity using metadata, Kubernetes or cloud APIs.
// It never enumerates environment variables or reads a credential file.
func FromEnv() Identity { return fromEnv(os.Getenv) }

func fromEnv(getenv func(string) string) Identity {
	id := Identity{Kubernetes: map[string]string{}, Cloud: map[string]string{}}
	for field, key := range map[string]string{
		"k8s.cluster.name": "RUNSECURE_K8S_CLUSTER", "k8s.namespace.name": "RUNSECURE_POD_NAMESPACE",
		"k8s.pod.name": "RUNSECURE_POD_NAME", "k8s.pod.uid": "RUNSECURE_POD_UID", "k8s.node.name": "RUNSECURE_NODE_NAME",
	} {
		if value := getenv(key); value != "" {
			id.Kubernetes[field] = value
		}
	}
	for field, key := range map[string]string{
		"cloud.account.id": "RUNSECURE_CLOUD_ACCOUNT_ID", "cloud.region": "RUNSECURE_CLOUD_REGION", "cloud.zone": "RUNSECURE_CLOUD_ZONE",
	} {
		if value := getenv(key); value != "" {
			id.Cloud[field] = value
		}
	}
	switch provider := getenv("RUNSECURE_CLOUD_PROVIDER"); provider {
	case "aws", "gcp", "azure", "digitalocean", "oci", "alibaba", "ibm", "tencent":
		id.Cloud["cloud.provider"] = provider
	}
	switch strings.ToLower(getenv("CORNERSTONE_ENV")) {
	case "development":
		id.Environment = "Development"
	case "testing":
		id.Environment = "Testing"
	case "staging":
		id.Environment = "Staging"
	case "production":
		id.Environment = "Production"
	}
	return id
}

var (
	sensitiveKey = regexp.MustCompile(`(?i)(authorization|cookie|password|passwd|secret|token|credential|private.?key|jit.?config|encoded.?jit|access.?key|api.?key)`)
	pemKey       = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	githubToken  = regexp.MustCompile(`(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+`)
	awsAccessKey = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	bearer       = regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[^\s"',;]+`)
	jwt          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	httpURL      = regexp.MustCompile(`https?://[^\s"<>]+`)
	inlineSecret = regexp.MustCompile(`(?i)(authorization|password|passwd|secret|token|credential|private[_-]?key|(?:encoded[_-]?)?jit[_-]?config(?:[_-]?b64)?|access[_-]?key|api[_-]?key|client[_-]?secret|secret[_-]?access[_-]?key)(["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',;}\]]+)`)
)

// RedactString removes recognizable credential formats and URL userinfo/query
// material. Typed callers must still avoid request bodies and untrusted output;
// pattern matching cannot identify every arbitrary secret string.
func RedactString(value string) string {
	value = pemKey.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = githubToken.ReplaceAllString(value, "[REDACTED]")
	value = awsAccessKey.ReplaceAllString(value, "[REDACTED]")
	value = bearer.ReplaceAllString(value, "[REDACTED AUTHORIZATION]")
	value = jwt.ReplaceAllString(value, "[REDACTED JWT]")
	value = httpURL.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "[REDACTED URL]"
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return parsed.String()
	})
	return inlineSecret.ReplaceAllString(value, `$1$2"[REDACTED]"`)
}

func sanitize(value any, depth int) any {
	if depth > 32 {
		return "[REDACTED DEPTH LIMIT]"
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if sensitiveKey.MatchString(key) {
				out[key] = "[REDACTED]"
			} else {
				out[key] = sanitize(item, depth+1)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitize(item, depth+1)
		}
		return out
	case string:
		return RedactString(v)
	default:
		return value
	}
}

// Marshal prepares one newline-terminated event without mutating caller data.
// UseNumber preserves large integer identities exactly across JSON preparation.
func Marshal(record any, id Identity) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var event map[string]any
	if err := decoder.Decode(&event); err != nil {
		return nil, err
	}
	if event == nil {
		return nil, errors.New("telemetry: event must be an object")
	}
	if _, present := event["deployment.environment"]; !present && id.Environment != "" {
		event["deployment.environment"] = id.Environment
	}
	if _, present := event["k8s.context"]; !present && len(id.Kubernetes) > 0 {
		context := make(map[string]any, len(id.Kubernetes))
		for key, value := range id.Kubernetes {
			context[key] = value
		}
		event["k8s.context"] = context
	}
	if _, present := event["cloud.context"]; !present && len(id.Cloud) > 0 {
		context := make(map[string]any, len(id.Cloud))
		for key, value := range id.Cloud {
			context[key] = value
		}
		event["cloud.context"] = context
	}
	clean, err := json.Marshal(sanitize(event, 0))
	return append(clean, '\n'), err
}

// Write detects short writes as well as explicit sink errors. Callers serialize
// concurrent writes and surface failures on a separate diagnostic sink.
func Write(w io.Writer, encoded []byte) error {
	n, err := w.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
