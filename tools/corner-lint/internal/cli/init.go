// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a .corner-lint.yaml configuration file",
	Long: `Create a .corner-lint.yaml configuration file in the current directory.

This command generates a default configuration file with all available options
documented. You can customize this file to match your project's needs.`,
	RunE: runInit,
}

var (
	initForce bool
)

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite existing config file")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	configPath := filepath.Join(".", ".corner-lint.yaml")

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil && !initForce {
		return fmt.Errorf("config file already exists: %s (use --force to overwrite)", configPath)
	}

	// Write default config with comments
	configContent := `# corner-lint configuration file
# Documentation: https://github.com/Cerebras/Cornerstone/tree/master/corner-lint

version: "1.0"

# Schema configuration
schemas:
  # Use embedded schemas (bundled with corner-lint)
  embed: true
  # Override with custom schema directory (optional)
  # directory: "./custom-schemas"

# Validation settings
validation:
  # Fail on unknown attributes not in schema
  strict: false
  # Exit with code 1 on warnings (useful for CI)
  fail_on_warning: false

# File scanning configuration
scan:
  # Glob patterns for files to include
  include:
    - "**/*.json"
    - "**/*.yaml"
    - "**/*.yml"
  # Glob patterns for files to exclude
  exclude:
    - "node_modules/**"
    - "vendor/**"
    - ".git/**"
    - "dist/**"
    - "build/**"

# File type detection patterns
types:
  # Patterns that identify signature files
  signatures:
    patterns:
      - "**/signatures/**"
      - "**/*-signature.yaml"
      - "**/*-signature.yml"
      - "**/*-sig.yaml"
      - "**/*-sig.yml"
  # Patterns that identify event files
  events:
    patterns:
      - "**/events/**"
      - "**/logs/**"

# Output configuration
output:
  # Output format: text, json, sarif
  format: text
  # Color output: auto, always, never
  color: auto

# Watch mode configuration
watch:
  # Debounce duration for file changes
  debounce: 100ms
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Created %s\n", configPath)
	return nil
}
