// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/schema"
	"gopkg.in/yaml.v3"
)

// SignatureValidator validates Cornerstone signature files.
type SignatureValidator struct {
	registry *schema.Registry
}

// NewSignatureValidator creates a new signature validator.
func NewSignatureValidator(registry *schema.Registry) *SignatureValidator {
	return &SignatureValidator{registry: registry}
}

// ValidateFile validates a signature file.
func (v *SignatureValidator) ValidateFile(path string) (*FileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var sigData map[string]any
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &sigData); err != nil {
			return &FileResult{
				Path:  path,
				Type:  FileTypeSignature,
				Valid: false,
				Errors: []ValidationError{{
					Message: fmt.Sprintf("invalid YAML: %v", err),
				}},
			}, nil
		}
	case ".json":
		// JSON signatures are less common but supported
		if err := yaml.Unmarshal(data, &sigData); err != nil {
			return &FileResult{
				Path:  path,
				Type:  FileTypeSignature,
				Valid: false,
				Errors: []ValidationError{{
					Message: fmt.Sprintf("invalid JSON: %v", err),
				}},
			}, nil
		}
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}

	return v.ValidateData(path, sigData), nil
}

// ValidateData validates signature data.
func (v *SignatureValidator) ValidateData(path string, data map[string]any) *FileResult {
	result := &FileResult{
		Path:  path,
		Type:  FileTypeSignature,
		Valid: true,
	}

	// Schema validation against event-signature.json
	schemaResult := v.registry.ValidateSignature(data)
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

	// Warnings for best practices
	warnings := v.checkBestPractices(data)
	result.Warnings = warnings

	return result
}

// validateSemantics performs semantic validation beyond JSON Schema.
func (v *SignatureValidator) validateSemantics(data map[string]any) []ValidationError {
	var errors []ValidationError

	// Check configuration constraints
	if config, ok := data["configuration"].(map[string]any); ok {
		// If event.structure is "variables", delimiter and fields.order are required
		if structure, ok := config["event.structure"].(string); ok && structure == "variables" {
			if _, hasDelimiter := config["delimiter"]; !hasDelimiter {
				errors = append(errors, ValidationError{
					Field:   "configuration.delimiter",
					Message: "'delimiter' is required when event.structure is 'variables'",
				})
			}
			if _, hasOrder := config["fields.order"]; !hasOrder {
				errors = append(errors, ValidationError{
					Field:   "configuration.fields.order",
					Message: "'fields.order' is required when event.structure is 'variables'",
				})
			}
		}
	}

	// Validate pre.population entries
	if prePop, ok := data["pre.population"].([]any); ok {
		knownContexts := v.registry.GetKnownContexts()
		for i, entry := range prePop {
			if entryMap, ok := entry.(map[string]any); ok {
				if ctxName, ok := entryMap["context.name"].(string); ok {
					if !isKnownContext(ctxName, knownContexts) {
						errors = append(errors, ValidationError{
							Field:   fmt.Sprintf("pre.population[%d].context.name", i),
							Message: fmt.Sprintf("unknown context '%s'", ctxName),
						})
					}
				}
			}
		}
	}

	return errors
}

// checkBestPractices checks for best practice violations (warnings).
func (v *SignatureValidator) checkBestPractices(data map[string]any) []ValidationError {
	var warnings []ValidationError

	// Check signature naming convention
	if sig, ok := data["event.signature"].(string); ok {
		if !isValidSignatureName(sig) {
			warnings = append(warnings, ValidationError{
				Field:   "event.signature",
				Message: fmt.Sprintf("signature name '%s' should follow convention: lowercase-with-hyphens-v1", sig),
			})
		}
	}

	// Warn if no schema.version
	if _, ok := data["schema.version"]; !ok {
		warnings = append(warnings, ValidationError{
			Field:   "schema.version",
			Message: "consider adding 'schema.version' for compatibility tracking",
		})
	}

	return warnings
}

// isKnownContext checks if a context name is known.
func isKnownContext(name string, knownContexts []string) bool {
	for _, ctx := range knownContexts {
		if ctx == name || strings.HasPrefix(ctx, name) || strings.HasPrefix(name, ctx) {
			return true
		}
	}
	return false
}

// isValidSignatureName checks if signature name follows conventions.
func isValidSignatureName(name string) bool {
	// Should be lowercase with hyphens, optionally ending with version
	if name == "" {
		return false
	}
	// Allow letters, numbers, hyphens, dots, underscores
	for _, c := range name {
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isPunct := c == '-' || c == '_' || c == '.'
		if !isLower && !isDigit && !isPunct {
			return false
		}
	}
	return true
}
