// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Registry holds compiled JSON schemas for Cornerstone validation.
type Registry struct {
	compiler        *jsonschema.Compiler
	eventSchema     *jsonschema.Schema
	signatureSchema *jsonschema.Schema
	detailsSchema   *jsonschema.Schema
	contextSchemas  map[string]*jsonschema.Schema
}

// embeddedSchemaLoader implements jsonschema.URLLoader for embedded schemas.
type embeddedSchemaLoader struct {
	baseURL string
}

// Load implements jsonschema.URLLoader interface.
func (l *embeddedSchemaLoader) Load(url string) (any, error) {
	if !strings.HasPrefix(url, l.baseURL) {
		return nil, fmt.Errorf("unknown schema URL: %s (expected prefix: %s)", url, l.baseURL)
	}
	relativePath := strings.TrimPrefix(url, l.baseURL)
	filePath := "schemas/" + relativePath

	data, err := embeddedSchemas.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded schema %s: %w", filePath, err)
	}

	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("failed to parse schema %s: %w", filePath, err)
	}
	return v, nil
}

// contextSchemaMapping maps context prefixes to schema files.
var contextSchemaMapping = map[string]string{
	"initiating.user":     "contexts/user-context.json",
	"impacted.user":       "contexts/user-context.json",
	"web.context":         "contexts/web-context.json",
	"database.context":    "contexts/database-context.json",
	"network.context":     "contexts/network-context.json",
	"file.context":        "contexts/file-context.json",
	"cloud.context":       "contexts/cloud-context.json",
	"k8s.context":         "contexts/kubernetes-context.json",
	"container.context":   "contexts/container-context.json",
	"host.context":        "contexts/host-context.json",
	"geo.context":         "contexts/geo-context.json",
	"device.context":      "contexts/device-context.json",
	"session.context":     "contexts/session-context.json",
	"audit.context":       "contexts/audit-context.json",
	"rate.limit.context":  "contexts/rate-limit-context.json",
	"encryption.context":  "contexts/encryption-context.json",
	"data.classification": "contexts/data-classification.json",
	"anti.malware":        "contexts/anti-malware-context.json",
	"data.import":         "contexts/data-import-context.json",
	"data.export":         "contexts/data-export-context.json",
	"information.context": "contexts/information-context.json",
}

// NewRegistry creates a new schema registry with embedded schemas.
func NewRegistry() (*Registry, error) {
	const baseURL = "https://cerebras.github.io/Cornerstone/schemas/"

	compiler := jsonschema.NewCompiler()
	loader := &embeddedSchemaLoader{baseURL: baseURL}
	compiler.UseLoader(loader)

	r := &Registry{
		compiler:       compiler,
		contextSchemas: make(map[string]*jsonschema.Schema),
	}

	// Compile event schema
	eventSchema, err := compiler.Compile(baseURL + "cornerstone-event.json")
	if err != nil {
		return nil, fmt.Errorf("failed to compile event schema: %w", err)
	}
	r.eventSchema = eventSchema

	// Compile signature schema
	signatureSchema, err := compiler.Compile(baseURL + "event-signature.json")
	if err != nil {
		return nil, fmt.Errorf("failed to compile signature schema: %w", err)
	}
	r.signatureSchema = signatureSchema

	// Compile details schema
	detailsSchema, err := compiler.Compile(baseURL + "event-details.json")
	if err != nil {
		return nil, fmt.Errorf("failed to compile details schema: %w", err)
	}
	r.detailsSchema = detailsSchema

	// Compile context schemas
	for prefix, schemaFile := range contextSchemaMapping {
		schema, err := compiler.Compile(baseURL + schemaFile)
		if err != nil {
			// Non-fatal: log warning but continue
			continue
		}
		r.contextSchemas[prefix] = schema
	}

	return r, nil
}

// ValidationError represents a schema validation error.
type ValidationError struct {
	Path    string `json:"path"`
	Field   string `json:"field"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

// ValidationResult contains the result of schema validation.
type ValidationResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
}

// ValidateEvent validates event data against the event schema.
func (r *Registry) ValidateEvent(data map[string]any) ValidationResult {
	if r.eventSchema == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Message: "event schema not loaded"}},
		}
	}

	err := r.eventSchema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	return r.extractErrors(err)
}

// ValidateSignature validates signature data against the signature schema.
func (r *Registry) ValidateSignature(data map[string]any) ValidationResult {
	if r.signatureSchema == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Message: "signature schema not loaded"}},
		}
	}

	err := r.signatureSchema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	return r.extractErrors(err)
}

// ValidateEventDetails validates event details against the details schema.
func (r *Registry) ValidateEventDetails(data map[string]any) ValidationResult {
	if r.detailsSchema == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Message: "details schema not loaded"}},
		}
	}

	err := r.detailsSchema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	return r.extractErrors(err)
}

// extractErrors converts jsonschema validation errors to ValidationErrors.
func (r *Registry) extractErrors(err error) ValidationResult {
	result := ValidationResult{Valid: false}

	if validationErr, ok := err.(*jsonschema.ValidationError); ok {
		result.Errors = r.extractValidationErrors(validationErr)
	} else {
		result.Errors = []ValidationError{{Message: err.Error()}}
	}

	return result
}

// extractValidationErrors recursively extracts errors from ValidationError tree.
func (r *Registry) extractValidationErrors(ve *jsonschema.ValidationError) []ValidationError {
	var errors []ValidationError

	pathStr := strings.Join(ve.InstanceLocation, "/")
	if pathStr != "" {
		pathStr = "/" + pathStr
	}

	message := ve.Error()

	// Add this error if it has no nested causes (leaf error)
	if len(ve.Causes) == 0 && message != "" {
		errors = append(errors, ValidationError{
			Path:    pathStr,
			Field:   lastPathSegment(ve.InstanceLocation),
			Message: message,
		})
	}

	// Add nested errors
	for _, cause := range ve.Causes {
		errors = append(errors, r.extractValidationErrors(cause)...)
	}

	// If no specific errors found, add top-level message
	if len(errors) == 0 && message != "" {
		errors = append(errors, ValidationError{
			Path:    pathStr,
			Field:   lastPathSegment(ve.InstanceLocation),
			Message: message,
		})
	}

	return errors
}

func lastPathSegment(path []string) string {
	if len(path) == 0 {
		return ""
	}
	return path[len(path)-1]
}

// GetKnownContexts returns the list of known context prefixes.
func (r *Registry) GetKnownContexts() []string {
	contexts := make([]string, 0, len(contextSchemaMapping))
	for prefix := range contextSchemaMapping {
		contexts = append(contexts, prefix)
	}
	return contexts
}
