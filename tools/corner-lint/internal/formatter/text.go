// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"fmt"
	"strings"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/validator"
	"github.com/fatih/color"
)

// TextFormatter formats validation results as human-readable text.
type TextFormatter struct {
	verbose int
}

// NewTextFormatter creates a new text formatter.
func NewTextFormatter(verbose int) *TextFormatter {
	return &TextFormatter{verbose: verbose}
}

var (
	greenCheck = color.New(color.FgGreen).SprintFunc()
	redX       = color.New(color.FgRed).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	cyan       = color.New(color.FgCyan).SprintFunc()
	bold       = color.New(color.Bold).SprintFunc()
)

// FormatHeader formats the header.
func (f *TextFormatter) FormatHeader(version string) string {
	return fmt.Sprintf("%s %s\n", bold("corner-lint"), version)
}

// FormatResult formats a single file result.
func (f *TextFormatter) FormatResult(result *validator.FileResult) string {
	var sb strings.Builder

	// File path
	fmt.Fprintf(&sb, "\n%s\n", cyan(result.Path))

	if result.Valid {
		// Success
		typeStr := ""
		if result.Summary != nil && result.Summary.Type != "" {
			typeStr = fmt.Sprintf(" (%s)", result.Summary.Type)
		}
		fmt.Fprintf(&sb, "  %s Valid %s%s\n", greenCheck("✓"), result.Type, typeStr)

		// Show summary in verbose mode
		if f.verbose > 0 && result.Summary != nil {
			if result.Summary.UUID != "" {
				fmt.Fprintf(&sb, "    UUID: %s\n", result.Summary.UUID)
			}
			if result.Summary.Signature != "" {
				fmt.Fprintf(&sb, "    Signature: %s\n", result.Summary.Signature)
			}
		}
	} else {
		// Failure
		errorCount := len(result.Errors)
		fmt.Fprintf(&sb, "  %s %d validation error(s)\n", redX("✗"), errorCount)

		// Show errors
		for _, err := range result.Errors {
			if err.Field != "" {
				fmt.Fprintf(&sb, "    - %s: %s\n", bold(err.Field), err.Message)
			} else if err.Path != "" {
				fmt.Fprintf(&sb, "    - %s: %s\n", err.Path, err.Message)
			} else {
				fmt.Fprintf(&sb, "    - %s\n", err.Message)
			}
		}
	}

	// Show warnings if any
	if len(result.Warnings) > 0 {
		for _, warn := range result.Warnings {
			if warn.Field != "" {
				fmt.Fprintf(&sb, "  %s %s: %s\n", yellow("⚠"), warn.Field, warn.Message)
			} else {
				fmt.Fprintf(&sb, "  %s %s\n", yellow("⚠"), warn.Message)
			}
		}
	}

	return sb.String()
}

// FormatSummary formats the final summary.
func (f *TextFormatter) FormatSummary(stats *validator.ValidationStats) string {
	var sb strings.Builder

	sb.WriteString("\n" + strings.Repeat("─", 50) + "\n")
	sb.WriteString(bold("Summary") + "\n")
	fmt.Fprintf(&sb, "  Files validated: %d\n", stats.TotalFiles)

	if stats.ValidFiles > 0 {
		fmt.Fprintf(&sb, "  %s Passed: %d\n", greenCheck("✓"), stats.ValidFiles)
	}
	if stats.InvalidFiles > 0 {
		fmt.Fprintf(&sb, "  %s Failed: %d\n", redX("✗"), stats.InvalidFiles)
	}
	if stats.TotalErrors > 0 {
		fmt.Fprintf(&sb, "  Total errors: %d\n", stats.TotalErrors)
	}
	if stats.TotalWarnings > 0 {
		fmt.Fprintf(&sb, "  Total warnings: %d\n", stats.TotalWarnings)
	}

	return sb.String()
}
