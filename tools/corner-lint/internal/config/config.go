// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the corner-lint configuration file structure.
type Config struct {
	Version    string          `yaml:"version"`
	Schemas    SchemasConfig   `yaml:"schemas"`
	Validation ValidationConfig `yaml:"validation"`
	Scan       ScanConfig      `yaml:"scan"`
	Types      TypesConfig     `yaml:"types"`
	Output     OutputConfig    `yaml:"output"`
	Watch      WatchConfig     `yaml:"watch"`
}

// SchemasConfig configures schema loading.
type SchemasConfig struct {
	Embed     bool   `yaml:"embed"`     // Use embedded schemas (default: true)
	Directory string `yaml:"directory"` // Override with custom schema directory
}

// ValidationConfig configures validation behavior.
type ValidationConfig struct {
	Strict        bool `yaml:"strict"`         // Fail on unknown attributes
	FailOnWarning bool `yaml:"fail_on_warning"` // Exit 1 on warnings
}

// ScanConfig configures file scanning.
type ScanConfig struct {
	Include []string `yaml:"include"` // Glob patterns to include
	Exclude []string `yaml:"exclude"` // Glob patterns to exclude
}

// TypesConfig maps file patterns to types.
type TypesConfig struct {
	Signatures TypePatterns `yaml:"signatures"`
	Events     TypePatterns `yaml:"events"`
}

// TypePatterns defines patterns for file type detection.
type TypePatterns struct {
	Patterns []string `yaml:"patterns"`
}

// OutputConfig configures output behavior.
type OutputConfig struct {
	Format string `yaml:"format"` // text, json, sarif
	Color  string `yaml:"color"`  // auto, always, never
}

// WatchConfig configures watch mode.
type WatchConfig struct {
	Debounce string `yaml:"debounce"` // Debounce duration (e.g., "100ms")
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1.0",
		Schemas: SchemasConfig{
			Embed:     true,
			Directory: "",
		},
		Validation: ValidationConfig{
			Strict:        false,
			FailOnWarning: false,
		},
		Scan: ScanConfig{
			Include: []string{"**/*.json", "**/*.yaml", "**/*.yml"},
			Exclude: []string{"node_modules/**", "vendor/**", ".git/**"},
		},
		Types: TypesConfig{
			Signatures: TypePatterns{
				Patterns: []string{"**/signatures/**", "**/*-signature.yaml", "**/*-sig.yaml"},
			},
			Events: TypePatterns{
				Patterns: []string{"**/events/**", "**/logs/**"},
			},
		},
		Output: OutputConfig{
			Format: "text",
			Color:  "auto",
		},
		Watch: WatchConfig{
			Debounce: "100ms",
		},
	}
}

// Load loads configuration from a file path.
// If path is empty, it searches for .corner-lint.yaml in current and parent directories.
func Load(path string) (*Config, error) {
	if path == "" {
		path = findConfigFile()
	}

	if path == "" {
		return DefaultConfig(), nil
	}

	return loadFile(path)
}

// findConfigFile searches for .corner-lint.yaml in current and parent directories.
func findConfigFile() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		configPath := filepath.Join(dir, ".corner-lint.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}

		// Also check .corner-lint.yml
		configPath = filepath.Join(dir, ".corner-lint.yml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

// loadFile loads configuration from a specific file.
func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Merge merges command-line flags into configuration.
func (c *Config) Merge(format string, failOnWarn bool, include, exclude []string) {
	if format != "" {
		c.Output.Format = format
	}

	if failOnWarn {
		c.Validation.FailOnWarning = true
	}

	if len(include) > 0 {
		c.Scan.Include = include
	}

	if len(exclude) > 0 {
		c.Scan.Exclude = exclude
	}
}
