// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package validator

// FileType represents the type of file being validated.
type FileType string

const (
	FileTypeEvent     FileType = "event"
	FileTypeSignature FileType = "signature"
	FileTypeUnknown   FileType = "unknown"
)

// FileResult represents the validation result for a single file.
type FileResult struct {
	Path     string           `json:"path"`
	Type     FileType         `json:"type"`
	Valid    bool             `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
	Summary  *EventSummary    `json:"summary,omitempty"`
}

// ValidationError represents a validation error with location info.
type ValidationError struct {
	Path    string `json:"path,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

// EventSummary contains summary info about a validated event.
type EventSummary struct {
	UUID      string `json:"uuid,omitempty"`
	Signature string `json:"signature,omitempty"`
	Type      string `json:"type,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// ValidationStats contains aggregate statistics.
type ValidationStats struct {
	TotalFiles    int `json:"totalFiles"`
	ValidFiles    int `json:"validFiles"`
	InvalidFiles  int `json:"invalidFiles"`
	TotalErrors   int `json:"totalErrors"`
	TotalWarnings int `json:"totalWarnings"`
}
