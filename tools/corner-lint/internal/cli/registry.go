// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Cerebras/Cornerstone/corner-lint/internal/registry"
	"github.com/spf13/cobra"
)

// registryCmd is the parent for `corner-lint registry ...` subcommands.
var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Manage the project-local .cornerstone/ registry",
	Long: `Manage the .cornerstone/ directory — the project-local Cornerstone
registry that lists registered event signatures, defaults, transformations,
and the emission style this project uses.

Subcommands:
  init      scaffold .cornerstone/ in the current directory
  validate  check the registry for consistency (duplicate UUIDs, dangling sites)
  list      print a summary table of registered events`,
}

// ----- init ---------------------------------------------------------------

var (
	initGreenfield  bool
	initProjectName string
	initLanguage    string
	initForceReg    bool
)

var registryInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold a .cornerstone/ directory",
	Long: `Create .cornerstone/manifest.yaml and .cornerstone/events/ in the current
directory. Detects the language and existing logging libraries to recommend a
sensible default emission style.

Default emission style:
  - --greenfield        → sdk          (use cornerstone-sdk; recommended only for new projects)
  - OTEL deps detected  → otel-direct  (emit via OpenTelemetry with cornerstone.* attributes)
  - otherwise           → raw-json     (Cornerstone-shaped JSON to stderr; zero deps)`,
	RunE: runRegistryInit,
}

func init() { //nolint:gochecknoinits
	registryInitCmd.Flags().BoolVar(&initGreenfield, "greenfield", false,
		"recommend the SDK style (use only for net-new projects with no production logging)")
	registryInitCmd.Flags().StringVar(&initProjectName, "name", "",
		"project name (defaults to the current directory's basename)")
	registryInitCmd.Flags().StringVar(&initLanguage, "language", "",
		"primary language: python, typescript, go, mixed (auto-detected if not set)")
	registryInitCmd.Flags().BoolVar(&initForceReg, "force", false,
		"overwrite an existing .cornerstone/manifest.yaml")

	registryCmd.AddCommand(registryInitCmd)
	registryCmd.AddCommand(registryValidateCmd)
	registryCmd.AddCommand(registryListCmd)
	rootCmd.AddCommand(registryCmd)
}

func runRegistryInit(_ *cobra.Command, _ []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	dir := filepath.Join(wd, registry.DirName)
	manifestPath := filepath.Join(dir, registry.ManifestFileName)
	if _, err := os.Stat(manifestPath); err == nil && !initForceReg {
		return fmt.Errorf("%s already exists (use --force to overwrite)", manifestPath)
	}

	name := initProjectName
	if name == "" {
		name = filepath.Base(wd)
	}

	language := initLanguage
	if language == "" {
		language = detectLanguage(wd)
	}

	style := chooseStyle(wd, initGreenfield)

	if err := os.MkdirAll(filepath.Join(dir, registry.EventsDirName), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	content := manifestTemplate(name, language, style)
	if err := os.WriteFile(manifestPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return fmt.Errorf("write %s: %w", manifestPath, err)
	}

	gitkeep := filepath.Join(dir, registry.EventsDirName, ".gitkeep")
	if err := os.WriteFile(gitkeep, []byte{}, 0o644); err != nil { //nolint:gosec
		return fmt.Errorf("write %s: %w", gitkeep, err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Created %s (style=%s, language=%s)\n", manifestPath, style, language)
	_, _ = fmt.Fprintln(os.Stdout, "Next steps:")
	_, _ = fmt.Fprintln(os.Stdout, "  - Edit defaults / transformations / conventions in", manifestPath)
	_, _ = fmt.Fprintln(os.Stdout, "  - Add events under", filepath.Join(dir, registry.EventsDirName))
	_, _ = fmt.Fprintln(os.Stdout, "  - Run `corner-lint registry validate` to check consistency")
	return nil
}

// detectLanguage looks at the project root for marker files and returns the
// primary language. If multiple languages are detected, returns "mixed".
func detectLanguage(root string) string {
	hasPython := fileExists(filepath.Join(root, "pyproject.toml")) ||
		fileExists(filepath.Join(root, "setup.py")) ||
		fileExists(filepath.Join(root, "requirements.txt"))
	hasTS := fileExists(filepath.Join(root, "package.json"))
	hasGo := fileExists(filepath.Join(root, "go.mod"))

	count := 0
	for _, b := range []bool{hasPython, hasTS, hasGo} {
		if b {
			count++
		}
	}

	switch {
	case count > 1:
		return "mixed"
	case hasPython:
		return "python"
	case hasTS:
		return "typescript"
	case hasGo:
		return "go"
	default:
		return "python" // safe default; users can edit
	}
}

// chooseStyle picks a default emission style based on flag + dependency sniffing.
//
// Defensive default: existing projects get otel-direct or raw-json (proven,
// zero new dependencies). The SDK is recommended only when --greenfield is
// passed because it is not yet GA-proven for production-bearing code.
func chooseStyle(root string, greenfield bool) string {
	if greenfield {
		return "sdk"
	}
	if hasOtelDependency(root) {
		return "otel-direct"
	}
	return "raw-json"
}

func hasOtelDependency(root string) bool {
	checks := []struct {
		path  string
		needles []string
	}{
		{filepath.Join(root, "package.json"), []string{"@opentelemetry/"}},
		{filepath.Join(root, "pyproject.toml"), []string{"opentelemetry-"}},
		{filepath.Join(root, "requirements.txt"), []string{"opentelemetry-"}},
		{filepath.Join(root, "go.mod"), []string{"go.opentelemetry.io/"}},
	}
	for _, c := range checks {
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		for _, n := range c.needles {
			if containsBytes(data, []byte(n)) {
				return true
			}
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// containsBytes is a tiny, allocation-free substring check; avoids importing
// strings/regexp for one needle.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return len(needle) == 0
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if matchAt(haystack, needle, i) {
			return true
		}
	}
	return false
}

func matchAt(haystack, needle []byte, offset int) bool {
	for i := range needle {
		if haystack[offset+i] != needle[i] {
			return false
		}
	}
	return true
}

func manifestTemplate(name, language, style string) string {
	uuidNote := ""
	switch style {
	case "sdk":
		uuidNote = `# This project uses the cornerstone-sdk for emission. The SDK reads this
# manifest on Logger init and applies defaults + transformations automatically.`
	case "otel-direct":
		uuidNote = `# This project emits Cornerstone events via OpenTelemetry. The instrument
# skill bakes defaults + transformations into the generated code; the
# collector enforces them at the schema-validation step.`
	case "raw-json":
		uuidNote = `# This project emits Cornerstone-shaped JSON directly to stderr. The
# instrument skill bakes defaults + transformations into the generated code;
# the collector picks them up via an OTLP / filelog receiver.`
	}

	return fmt.Sprintf(`# .cornerstone/manifest.yaml
# Project-local Cornerstone registry. See:
# https://github.com/Cerebras/Cornerstone/blob/master/schemas/cornerstone-manifest.json
%s

apiVersion: cornerstone.cerebras.net/v1
kind: ProjectManifest

metadata:
  name: %s
  # owner: your-team
  # description: One-line summary of what this project emits.

emission:
  style: %s
  language: %s

uuid_strategy:
  mode: random        # random | deterministic
  # If you want stable UUIDs across forks of this project, switch to:
  # mode: deterministic
  # namespace: 6ba7b810-9dad-11d1-80b4-00c04fd430c8

# Always set on every event emitted from this project.
defaults:
  signature: %s-v1
  # environment: ${CORNERSTONE_ENV:-production}
  # tags: []

# Field-level transformations applied at emit time (e.g. never log raw email).
# transformations:
#   - field: initiating.user.user.email
#     transform: sha256
#   - field: web.context.headers.authorization
#     transform: redact

# Project-wide rules enforced by ` + "`corner-lint registry validate`" + ` and the
# cornerstone_validator collector processor.
# conventions:
#   required_contexts: [initiating_user]
#   forbidden_fields: [web.context.body]
#   severity_floor: informational

# Where the application code lives (used by the instrument and retrofit skills).
# sources:
#   python:
#     - "src/**/*.py"
#   typescript:
#     - "src/**/*.ts"
`, uuidNote, name, style, language, name)
}

// ----- validate -----------------------------------------------------------

var registryValidateCmd = &cobra.Command{
	Use:   "validate [project-root]",
	Short: "Validate the .cornerstone/ registry for consistency",
	Long: `Run cross-event consistency checks against the .cornerstone/ registry:
duplicate UUIDs, duplicate event names, dangling emit_sites, manifest sanity,
and status/deprecation_note coupling. Returns exit code 1 if errors are found.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRegistryValidate,
}

func runRegistryValidate(_ *cobra.Command, args []string) error {
	root, err := projectRoot(args)
	if err != nil {
		return err
	}

	reg, err := registry.Load(root)
	if err != nil {
		return err
	}

	issues := reg.Validate(root)

	if len(issues) == 0 {
		_, _ = fmt.Fprintf(os.Stdout, "✓ %d events registered, no issues\n", len(reg.Events))
		return nil
	}

	errCount := 0
	warnCount := 0
	for _, i := range issues {
		prefix := "warn"
		if i.Severity == "error" {
			prefix = "ERROR"
			errCount++
		} else {
			warnCount++
		}
		if i.File != "" {
			_, _ = fmt.Fprintf(os.Stdout, "%s  %s: %s\n", prefix, i.File, i.Message)
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "%s  %s\n", prefix, i.Message)
		}
	}
	_, _ = fmt.Fprintf(os.Stdout, "\n%d events, %d errors, %d warnings\n", len(reg.Events), errCount, warnCount)

	if errCount > 0 {
		return errors.New("registry validation failed")
	}
	return nil
}

// ----- list ---------------------------------------------------------------

var registryListCmd = &cobra.Command{
	Use:   "list [project-root]",
	Short: "Print a summary table of registered events",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRegistryList,
}

func runRegistryList(_ *cobra.Command, args []string) error {
	root, err := projectRoot(args)
	if err != nil {
		return err
	}

	reg, err := registry.Load(root)
	if err != nil {
		return err
	}

	if len(reg.Events) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "(no events registered yet)")
		return nil
	}

	type row struct {
		name, uuid, status string
		sites              int
	}
	rows := make([]row, 0, len(reg.Events))
	for _, e := range reg.Events {
		status := e.Metadata.Status
		if status == "" {
			status = "active"
		}
		rows = append(rows, row{
			name:   e.Metadata.Name,
			uuid:   e.Metadata.UUID,
			status: status,
			sites:  len(e.EmitSites),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	_, _ = fmt.Fprintf(os.Stdout, "%-30s  %-36s  %-10s  %s\n", "NAME", "UUID", "STATUS", "EMIT_SITES")
	for _, r := range rows {
		_, _ = fmt.Fprintf(os.Stdout, "%-30s  %-36s  %-10s  %d\n", r.name, r.uuid, r.status, r.sites)
	}
	return nil
}

// projectRoot returns the directory passed as the first arg, or cwd if no arg.
func projectRoot(args []string) (string, error) {
	if len(args) == 1 {
		abs, err := filepath.Abs(args[0])
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	return os.Getwd()
}
