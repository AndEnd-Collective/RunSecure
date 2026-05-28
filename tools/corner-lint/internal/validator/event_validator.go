// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/schema"
	"gopkg.in/yaml.v3"
)

// EventValidator validates Cornerstone event data.
type EventValidator struct {
	registry *schema.Registry
}

// NewEventValidator creates a new event validator.
func NewEventValidator(registry *schema.Registry) *EventValidator {
	return &EventValidator{registry: registry}
}

// ValidateFile validates an event file.
func (v *EventValidator) ValidateFile(path string) (*FileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var eventData map[string]any
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &eventData); err != nil {
			return &FileResult{
				Path:  path,
				Type:  FileTypeEvent,
				Valid: false,
				Errors: []ValidationError{{
					Message: fmt.Sprintf("invalid JSON: %v", err),
				}},
			}, nil
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &eventData); err != nil {
			return &FileResult{
				Path:  path,
				Type:  FileTypeEvent,
				Valid: false,
				Errors: []ValidationError{{
					Message: fmt.Sprintf("invalid YAML: %v", err),
				}},
			}, nil
		}
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}

	return v.ValidateData(path, eventData), nil
}

// ValidateData validates event data.
func (v *EventValidator) ValidateData(path string, data map[string]any) *FileResult {
	result := &FileResult{
		Path:  path,
		Type:  FileTypeEvent,
		Valid: true,
	}

	// Extract event summary
	result.Summary = v.extractSummary(data)

	// Schema validation
	schemaResult := v.registry.ValidateEvent(data)
	if !schemaResult.Valid {
		result.Valid = false
		for _, err := range schemaResult.Errors {
			result.Errors = append(result.Errors, ValidationError{
				Path:    err.Path,
				Field:   err.Field,
				Message: err.Message,
			})
		}
	}

	// Semantic validation
	semanticErrors := v.validateSemantics(data)
	if len(semanticErrors) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, semanticErrors...)
	}

	return result
}

// extractSummary extracts summary information from event data.
func (v *EventValidator) extractSummary(data map[string]any) *EventSummary {
	summary := &EventSummary{}

	if uuid, ok := data["event.uuid"].(string); ok {
		summary.UUID = uuid
	}
	if sig, ok := data["event.signature"].(string); ok {
		summary.Signature = sig
	}
	if eventType, ok := data["event.type"].(string); ok {
		summary.Type = eventType
	}
	if ts, ok := data["time.stamp"].(string); ok {
		summary.Timestamp = ts
	}

	return summary
}

// validateSemantics performs semantic validation beyond JSON Schema.
func (v *EventValidator) validateSemantics(data map[string]any) []ValidationError {
	var errors []ValidationError

	// Check UUID format
	if uuid, ok := data["event.uuid"].(string); ok {
		if !isValidUUID(uuid) {
			errors = append(errors, ValidationError{
				Field:   "event.uuid",
				Message: fmt.Sprintf("invalid UUID format: %s", uuid),
			})
		}
	}

	// Check event type
	if eventType, ok := data["event.type"].(string); ok {
		if eventType != "Activity" && eventType != "Change" {
			errors = append(errors, ValidationError{
				Field:   "event.type",
				Message: fmt.Sprintf("invalid event type '%s' (must be 'Activity' or 'Change')", eventType),
			})
		}
	}

	// Check severity range
	if details, ok := data["event.details"].(map[string]any); ok {
		if severity, ok := details["severity"]; ok {
			var sevValue int
			switch s := severity.(type) {
			case int:
				sevValue = s
			case float64:
				sevValue = int(s)
			case int64:
				sevValue = int(s)
			default:
				errors = append(errors, ValidationError{
					Field:   "event.details.severity",
					Message: "severity must be an integer",
				})
				sevValue = -1
			}
			if sevValue != -1 && (sevValue < 0 || sevValue > 7) {
				errors = append(errors, ValidationError{
					Field:   "event.details.severity",
					Message: fmt.Sprintf("severity %d out of range (must be 0-7)", sevValue),
				})
			}
		}

		// Check result value
		if result, ok := details["result"].(string); ok {
			if result != "success" && result != "failure" {
				errors = append(errors, ValidationError{
					Field:   "event.details.result",
					Message: fmt.Sprintf("invalid result '%s' (must be 'success' or 'failure')", result),
				})
			}

			// Check failure_reason when result is failure
			if result == "failure" {
				if _, hasReason := details["failure.reason"]; !hasReason {
					errors = append(errors, ValidationError{
						Field:   "event.details.failure.reason",
						Message: "'failure.reason' is required when result is 'failure'",
					})
				}
			}
		}
	}

	return errors
}

// UUID regex pattern
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isValidUUID(s string) bool {
	return uuidPattern.MatchString(s)
}
