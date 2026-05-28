// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"github.com/Cerebras/Cornerstone/corner-lint/internal/validator"
)

// Formatter formats validation results for output.
type Formatter interface {
	// FormatResult formats a single file result.
	FormatResult(result *validator.FileResult) string

	// FormatSummary formats the final summary.
	FormatSummary(stats *validator.ValidationStats) string

	// FormatHeader formats the header (tool version, etc.).
	FormatHeader(version string) string
}
