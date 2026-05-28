// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version info set from main
	versionInfo struct {
		Version string
		Commit  string
		Date    string
	}

	// Global flags
	configFile   string
	outputFormat string
	verbosity    int
	quiet        bool
	noColor      bool

	// Loaded configuration
	cfg *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "corner-lint",
	Short: "Cornerstone semantic logging validator",
	Long: `corner-lint validates Cornerstone event signatures and event data
against JSON Schema definitions.

Examples:
  # Validate event files
  corner-lint validate event ./events/*.json

  # Validate signature files
  corner-lint validate signature ./signatures/*.yaml

  # Validate all files in a directory
  corner-lint validate -r ./src/

  # Watch mode for continuous validation
  corner-lint validate -w -r ./src/`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// SetVersionInfo sets version information from main
func SetVersionInfo(version, commit, date string) {
	versionInfo.Version = version
	versionInfo.Commit = commit
	versionInfo.Date = date
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default: .corner-lint.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "text", "output format: text, json, sarif")
	rootCmd.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "increase verbosity (-v, -vv, -vvv)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-error output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
}

func initConfig() {
	// Disable color if requested or not a terminal
	if noColor || os.Getenv("NO_COLOR") != "" {
		color.NoColor = true
	}

	// Load config file
	var err error
	cfg, err = config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// Apply config-based color setting
	switch cfg.Output.Color {
	case "never":
		color.NoColor = true
	case "always":
		color.NoColor = false
	}
}

// getConfig returns the loaded configuration
func getConfig() *config.Config {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return cfg
}

// getVerbosity returns the current verbosity level
func getVerbosity() int {
	if quiet {
		return -1
	}
	return verbosity
}

// getOutputFormat returns the current output format
// CLI flags take precedence over config file
func getOutputFormat() string {
	if outputFormat != "" && outputFormat != "text" {
		return outputFormat
	}
	if cfg != nil && cfg.Output.Format != "" {
		return cfg.Output.Format
	}
	return outputFormat
}
