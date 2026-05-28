// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/formatter"
	"github.com/Cerebras/Cornerstone/corner-lint/internal/schema"
	"github.com/Cerebras/Cornerstone/corner-lint/internal/validator"
	"github.com/Cerebras/Cornerstone/corner-lint/internal/watcher"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Validate command flags
	watchMode   bool
	recursive   bool
	includeGlob []string
	excludeGlob []string
	useStdin    bool
	forceType   string
	failOnWarn  bool
)

var validateCmd = &cobra.Command{
	Use:   "validate [files...]",
	Short: "Validate Cornerstone event and signature files",
	Long: `Validate Cornerstone event data and signature files against JSON Schema definitions.

Auto-detects file type based on content and naming patterns.
Use 'validate event' or 'validate signature' for explicit type validation.

Examples:
  corner-lint validate ./events/*.json
  corner-lint validate -r ./src/
  corner-lint validate --type event data.yaml`,
	Args: cobra.MinimumNArgs(0),
	RunE: runValidate,
}

var validateEventCmd = &cobra.Command{
	Use:   "event [files...]",
	Short: "Validate event files only",
	Long:  `Validate Cornerstone event data files against the event JSON Schema.`,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		forceType = "event"
		return runValidate(cmd, args)
	},
}

var validateSignatureCmd = &cobra.Command{
	Use:   "signature [files...]",
	Short: "Validate signature files only",
	Long:  `Validate Cornerstone signature files against the signature JSON Schema.`,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		forceType = "signature"
		return runValidate(cmd, args)
	},
}

func init() {
	// Add flags to validate command
	validateCmd.Flags().BoolVarP(&watchMode, "watch", "w", false, "watch mode for continuous validation")
	validateCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "recursively scan directories")
	validateCmd.Flags().StringSliceVar(&includeGlob, "include", nil, "include patterns (globs)")
	validateCmd.Flags().StringSliceVar(&excludeGlob, "exclude", nil, "exclude patterns (globs)")
	validateCmd.Flags().BoolVar(&useStdin, "stdin", false, "read from stdin")
	validateCmd.Flags().StringVar(&forceType, "type", "", "force file type: event, signature")
	validateCmd.Flags().BoolVar(&failOnWarn, "fail-on-warn", false, "exit 1 on warnings")

	// Add subcommands
	validateCmd.AddCommand(validateEventCmd)
	validateCmd.AddCommand(validateSignatureCmd)

	// Add to root
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Initialize schema registry
	registry, err := schema.NewRegistry()
	if err != nil {
		return fmt.Errorf("failed to initialize schema registry: %w", err)
	}

	// Create validators
	eventValidator := validator.NewEventValidator(registry)
	sigValidator := validator.NewSignatureValidator(registry)

	// Create formatter
	outputFormat := getOutputFormat()
	var fmtr formatter.Formatter
	switch outputFormat {
	case "json":
		fmtr = formatter.NewJSONFormatter(true) // pretty-print JSON
	case "sarif":
		fmtr = formatter.NewSARIFFormatter()
	default:
		fmtr = formatter.NewTextFormatter(getVerbosity())
	}

	// Print header
	if !quiet {
		_, _ = os.Stdout.WriteString(fmtr.FormatHeader(versionInfo.Version))
	}

	// Collect files to validate
	files, err := collectFiles(args, recursive, includeGlob, excludeGlob)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return fmt.Errorf("no files to validate") //nolint:govet
	}

	// Validate files
	stats := &validator.ValidationStats{}
	var hasErrors bool

	for _, file := range files {
		var result *validator.FileResult
		var err error

		fileType := detectFileType(file, forceType)
		switch fileType {
		case validator.FileTypeEvent:
			result, err = eventValidator.ValidateFile(file)
		case validator.FileTypeSignature:
			result, err = sigValidator.ValidateFile(file)
		default:
			// Skip unknown files
			continue
		}

		if err != nil {
			return fmt.Errorf("error validating %s: %w", file, err)
		}

		// Update stats
		stats.TotalFiles++
		if result.Valid {
			stats.ValidFiles++
		} else {
			stats.InvalidFiles++
			hasErrors = true
		}
		stats.TotalErrors += len(result.Errors)
		stats.TotalWarnings += len(result.Warnings)

		// Print result
		if !quiet {
			_, _ = os.Stdout.WriteString(fmtr.FormatResult(result))
		}

		// Check warnings with fail-on-warn
		if failOnWarn && len(result.Warnings) > 0 {
			hasErrors = true
		}
	}

	// Print summary
	// For JSON/SARIF formats, always output (they accumulate results in FormatSummary)
	// For text format, only show summary if multiple files
	if !quiet && (outputFormat != "text" || stats.TotalFiles > 1) {
		_, _ = os.Stdout.WriteString(fmtr.FormatSummary(stats))
	}

	// Handle watch mode
	if watchMode {
		return runWatchMode(args, eventValidator, sigValidator)
	}

	if hasErrors {
		os.Exit(1)
	}

	return nil
}

// runWatchMode starts watching files for changes and re-validates on change.
func runWatchMode(args []string, eventValidator *validator.EventValidator, sigValidator *validator.SignatureValidator) error {
	// Parse debounce from config
	cfg := getConfig()
	debounce, err := time.ParseDuration(cfg.Watch.Debounce)
	if err != nil {
		debounce = 100 * time.Millisecond
	}

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	fmt.Println()
	_, _ = cyan.Println("👀 Watching for changes... (press Ctrl+C to stop)")
	fmt.Println()

	// Create watcher with validation callback
	w, err := watcher.New(debounce, func(path string) {
		// Clear screen for better visibility
		fmt.Printf("\033[2K\r") // Clear current line

		fileType := detectFileType(path, forceType)
		var result *validator.FileResult
		var validateErr error

		switch fileType {
		case validator.FileTypeEvent:
			result, validateErr = eventValidator.ValidateFile(path)
		case validator.FileTypeSignature:
			result, validateErr = sigValidator.ValidateFile(path)
		default:
			return
		}

		if validateErr != nil {
			_, _ = red.Printf("Error: %v\n", validateErr)
			return
		}

		timestamp := time.Now().Format("15:04:05")
		if result.Valid {
			_, _ = green.Printf("[%s] ✓ %s - Valid\n", timestamp, path)
		} else {
			_, _ = red.Printf("[%s] ✗ %s - %d error(s)\n", timestamp, path, len(result.Errors))
			for _, e := range result.Errors {
				fmt.Printf("    - %s\n", e.Message)
			}
		}
	})
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	// Add paths to watch
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if recursive {
				if err := w.AddRecursive(arg); err != nil {
					return fmt.Errorf("failed to watch %s: %w", arg, err)
				}
			} else {
				if err := w.AddPath(arg); err != nil {
					return fmt.Errorf("failed to watch %s: %w", arg, err)
				}
			}
		} else {
			// Watch the directory containing the file
			dir := filepath.Dir(arg)
			if err := w.AddPath(dir); err != nil {
				return fmt.Errorf("failed to watch %s: %w", dir, err)
			}
		}
	}

	// Start watching
	w.Start()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println()
	_, _ = cyan.Println("Stopping watcher...")
	return w.Stop()
}

func collectFiles(args []string, recursive bool, include, exclude []string) ([]string, error) {
	var files []string

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			// Try as glob pattern
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid pattern %s: %w", arg, err)
			}
			for _, match := range matches {
				if isValidFile(match, include, exclude) {
					files = append(files, match)
				}
			}
			continue
		}

		if info.IsDir() {
			if recursive {
				err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() && isValidFile(path, include, exclude) {
						files = append(files, path)
					}
					return nil
				})
				if err != nil {
					return nil, err
				}
			}
		} else {
			if isValidFile(arg, include, exclude) {
				files = append(files, arg)
			}
		}
	}

	return files, nil
}

func isValidFile(path string, include, exclude []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return false
	}

	// Check exclude patterns
	for _, pattern := range exclude {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return false
		}
	}

	// Check include patterns (if any specified)
	if len(include) > 0 {
		for _, pattern := range include {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return true
			}
		}
		return false
	}

	return true
}

func detectFileType(path, forced string) validator.FileType {
	if forced != "" {
		switch forced {
		case "event":
			return validator.FileTypeEvent
		case "signature":
			return validator.FileTypeSignature
		}
	}

	// Auto-detect based on path patterns
	lower := strings.ToLower(path)

	// Signature patterns
	if strings.Contains(lower, "signature") ||
		strings.HasSuffix(lower, "-sig.yaml") ||
		strings.HasSuffix(lower, "-sig.yml") {
		return validator.FileTypeSignature
	}

	// Event patterns (default for JSON, event directories)
	if strings.Contains(lower, "event") ||
		strings.Contains(lower, "/logs/") ||
		strings.HasSuffix(lower, ".json") {
		return validator.FileTypeEvent
	}

	// Default to event for YAML files
	return validator.FileTypeEvent
}
