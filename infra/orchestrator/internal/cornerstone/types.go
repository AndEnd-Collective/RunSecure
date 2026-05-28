// Package cornerstone implements the in-tree emitter for Cerebras Cornerstone
// semantic-logging events.
//
// Schemas: https://cerebras.github.io/Cornerstone/schemas/
// Canonical repo: /Users/naor.penso/Code/Projects/cornerstone-docs
//
// No upstream Go SDK exists at the time of writing. This package is a small,
// dependency-free emitter; corner-lint (Go CLI) provides validation in CI.
package cornerstone

import "errors"

// EventType is the closed enum from cornerstone-event.json.
type EventType string

const (
	EventTypeActivity EventType = "Activity"
	EventTypeChange   EventType = "Change"
)

// Result is the closed enum from event-details.json.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// Status mirrors event-details.json's `status` enum. We only use a subset.
type Status string

const (
	StatusStarted             Status = "Started"
	StatusInProgress          Status = "In Progress"
	StatusCompleted           Status = "Completed"
	StatusCompletedWithErrors Status = "Completed with Errors"
	StatusFailed              Status = "Failed"
)

// Event is the top-level Cornerstone event envelope.
//
// Field names use dot-notation per the schema (event.uuid, time.stamp, etc.).
type Event struct {
	EventUUID             string            `json:"event.uuid"`
	EventSignature        string            `json:"event.signature"`
	EventSubType          string            `json:"event.sub.type,omitempty"`
	EventType             EventType         `json:"event.type"`
	TimeStamp             string            `json:"time.stamp"`
	DeploymentEnvironment string            `json:"deployment.environment,omitempty"`
	TraceID               string            `json:"trace.id,omitempty"`
	EventDetails          EventDetails      `json:"event.details"`
	ContainerContext      *ContainerContext `json:"container.context,omitempty"`
	NetworkContext        *NetworkContext   `json:"network.context,omitempty"`
	RateLimitContext      *RateLimitContext `json:"rate.limit.context,omitempty"`
	AuditContext          *AuditContext     `json:"audit.context,omitempty"`
}

// EventDetails — the required-on-every-event payload.
type EventDetails struct {
	EventCode     string         `json:"event.code,omitempty"`
	Summary       string         `json:"summary"`
	Message       string         `json:"message,omitempty"`
	Severity      int            `json:"severity"`
	Result        Result         `json:"result"`
	FailureReason string         `json:"failure.reason,omitempty"`
	ErrorData     map[string]any `json:"error.data,omitempty"`
	Status        Status         `json:"status,omitempty"`
	Duration      int64          `json:"duration,omitempty"` // milliseconds
	Tags          []string       `json:"tags,omitempty"`
}

// ErrFailureReasonRequired is returned by EventDetails.Validate when result is
// failure but failure.reason is empty.
var ErrFailureReasonRequired = errors.New("cornerstone: result=failure requires failure.reason")

// Validate enforces the schema invariants the JSON Schema would catch.
func (d EventDetails) Validate() error {
	if d.Result == ResultFailure && d.FailureReason == "" {
		return ErrFailureReasonRequired
	}
	if d.Severity < 0 || d.Severity > 7 {
		return errors.New("cornerstone: severity must be 0..7 (RFC 5424)")
	}
	if d.Summary == "" {
		return errors.New("cornerstone: summary is required")
	}
	return nil
}

// ContainerContext — see schemas/contexts/container-context.json.
type ContainerContext struct {
	ID          string `json:"container.id,omitempty"`
	Name        string `json:"container.name,omitempty"`
	ImageDigest string `json:"container.image.digest,omitempty"`
	Runtime     string `json:"container.runtime,omitempty"`
	ExitCode    *int   `json:"container.exit.code,omitempty"`
}

// NetworkContext — see schemas/contexts/network-context.json.
type NetworkContext struct {
	Name   string `json:"network.name,omitempty"`
	Driver string `json:"network.driver,omitempty"`
}

// RateLimitContext — see schemas/contexts/rate-limit-context.json.
type RateLimitContext struct {
	Remaining int    `json:"rate.limit.remaining"`
	Limit     int    `json:"rate.limit.limit"`
	ResetISO  string `json:"rate.limit.reset,omitempty"`
}

// AuditContext — see schemas/contexts/audit-context.json.
type AuditContext struct {
	Action       string `json:"audit.action,omitempty"`
	ResourceType string `json:"audit.resource.type,omitempty"`
	ResourceID   string `json:"audit.resource.id,omitempty"`
}
