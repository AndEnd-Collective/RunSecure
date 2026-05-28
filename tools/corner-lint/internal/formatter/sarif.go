// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"encoding/json"
	"path/filepath"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/validator"
)

// SARIF 2.1.0 structures
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFLog is the root SARIF object
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of the tool
type SARIFRun struct {
	Tool      SARIFTool       `json:"tool"`
	Results   []SARIFResult   `json:"results"`
	Artifacts []SARIFArtifact `json:"artifacts,omitempty"`
}

// SARIFTool describes the tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool metadata and rules
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule defines a validation rule
type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	FullDescription  SARIFMessage   `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	DefaultConfig    SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
}

// SARIFRuleConfig defines rule configuration
type SARIFRuleConfig struct {
	Level string `json:"level"` // error, warning, note
}

// SARIFMessage is a text message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
}

// SARIFLocation represents where a result was found
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a file location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation is a file path
type SARIFArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

// SARIFRegion is a location within a file
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// SARIFArtifact describes an analyzed file
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

// SARIFFormatter formats validation results as SARIF 2.1.0
type SARIFFormatter struct {
	version   string
	results   []*validator.FileResult
	artifacts []SARIFArtifact
}

// NewSARIFFormatter creates a new SARIF formatter
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{
		results:   make([]*validator.FileResult, 0),
		artifacts: make([]SARIFArtifact, 0),
	}
}

// FormatHeader stores version for final output
func (f *SARIFFormatter) FormatHeader(version string) string {
	f.version = version
	return ""
}

// FormatResult accumulates results and artifacts
func (f *SARIFFormatter) FormatResult(result *validator.FileResult) string {
	f.results = append(f.results, result)
	f.artifacts = append(f.artifacts, SARIFArtifact{
		Location: SARIFArtifactLocation{
			URI:   filepath.ToSlash(result.Path),
			Index: len(f.artifacts),
		},
	})
	return ""
}

// FormatSummary outputs the complete SARIF document
func (f *SARIFFormatter) FormatSummary(stats *validator.ValidationStats) string {
	log := SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool:      f.buildTool(),
				Results:   f.buildResults(),
				Artifacts: f.artifacts,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return `{"error": "failed to marshal SARIF output"}`
	}

	return string(data)
}

// buildTool creates the tool metadata with rules
func (f *SARIFFormatter) buildTool() SARIFTool {
	return SARIFTool{
		Driver: SARIFDriver{
			Name:           "corner-lint",
			Version:        f.version,
			InformationURI: "https://github.com/Cerebras/Cornerstone/tree/master/corner-lint",
			Rules: []SARIFRule{
				{
					ID:               "CS001",
					Name:             "schema-validation",
					ShortDescription: SARIFMessage{Text: "JSON Schema validation error"},
					FullDescription:  SARIFMessage{Text: "The data does not conform to the Cornerstone JSON Schema"},
					DefaultConfig:    SARIFRuleConfig{Level: "error"},
				},
				{
					ID:               "CS002",
					Name:             "missing-required-field",
					ShortDescription: SARIFMessage{Text: "Missing required field"},
					FullDescription:  SARIFMessage{Text: "A required field is missing from the Cornerstone event or signature"},
					DefaultConfig:    SARIFRuleConfig{Level: "error"},
				},
				{
					ID:               "CS003",
					Name:             "invalid-value",
					ShortDescription: SARIFMessage{Text: "Invalid field value"},
					FullDescription:  SARIFMessage{Text: "A field contains a value that is not allowed by the schema"},
					DefaultConfig:    SARIFRuleConfig{Level: "error"},
				},
				{
					ID:               "CS004",
					Name:             "semantic-validation",
					ShortDescription: SARIFMessage{Text: "Semantic validation error"},
					FullDescription:  SARIFMessage{Text: "The data violates Cornerstone semantic rules beyond JSON Schema"},
					DefaultConfig:    SARIFRuleConfig{Level: "error"},
				},
			},
		},
	}
}

// buildResults creates SARIF results from validation results
func (f *SARIFFormatter) buildResults() []SARIFResult {
	results := make([]SARIFResult, 0) // Initialize to empty slice for proper JSON output

	for fileIdx, fileResult := range f.results {
		for _, err := range fileResult.Errors {
			result := SARIFResult{
				RuleID:  f.classifyError(err),
				Level:   "error",
				Message: SARIFMessage{Text: err.Message},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI:   filepath.ToSlash(fileResult.Path),
								Index: fileIdx,
							},
						},
					},
				},
			}

			// Add region if we have line information
			if err.Line > 0 {
				result.Locations[0].PhysicalLocation.Region = &SARIFRegion{
					StartLine:   err.Line,
					StartColumn: err.Column,
				}
			}

			results = append(results, result)
		}

		// Add warnings as notes
		for _, warn := range fileResult.Warnings {
			result := SARIFResult{
				RuleID:  "CS004",
				Level:   "warning",
				Message: SARIFMessage{Text: warn.Message},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI:   filepath.ToSlash(fileResult.Path),
								Index: fileIdx,
							},
						},
					},
				},
			}
			results = append(results, result)
		}
	}

	return results
}

// classifyError determines which rule an error belongs to
func (f *SARIFFormatter) classifyError(err validator.ValidationError) string {
	msg := err.Message

	// Check for missing properties
	if contains(msg, "missing properties") || contains(msg, "required") {
		return "CS002"
	}

	// Check for invalid values
	if contains(msg, "value must be") || contains(msg, "out of range") || contains(msg, "invalid") {
		return "CS003"
	}

	// Check for semantic errors (from our custom validation)
	if contains(msg, "severity") || contains(msg, "result") || contains(msg, "failure.reason") {
		return "CS004"
	}

	// Default to schema validation
	return "CS001"
}

// contains checks if s contains substr (case-insensitive would be better but keeping simple)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
