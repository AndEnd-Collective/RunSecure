// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"encoding/json"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/validator"
)

// JSONOutput represents the complete JSON output structure.
type JSONOutput struct {
	Version string                    `json:"version"`
	Files   []*validator.FileResult   `json:"files"`
	Summary *validator.ValidationStats `json:"summary"`
}

// JSONFormatter formats validation results as JSON.
type JSONFormatter struct {
	version string
	results []*validator.FileResult
	pretty  bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{
		results: make([]*validator.FileResult, 0),
		pretty:  pretty,
	}
}

// FormatHeader stores the version for final output.
func (f *JSONFormatter) FormatHeader(version string) string {
	f.version = version
	return "" // JSON output is written all at once in FormatSummary
}

// FormatResult accumulates results for final JSON output.
func (f *JSONFormatter) FormatResult(result *validator.FileResult) string {
	f.results = append(f.results, result)
	return "" // JSON output is written all at once in FormatSummary
}

// FormatSummary outputs the complete JSON result.
func (f *JSONFormatter) FormatSummary(stats *validator.ValidationStats) string {
	output := JSONOutput{
		Version: f.version,
		Files:   f.results,
		Summary: stats,
	}

	var data []byte
	var err error

	if f.pretty {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}

	if err != nil {
		return `{"error": "failed to marshal output"}`
	}

	return string(data)
}
