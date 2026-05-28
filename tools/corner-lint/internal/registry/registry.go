// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

// Package registry loads and validates a project-local .cornerstone/ directory:
// the manifest and the per-event YAML records. It is consumed by the
// `corner-lint registry` subcommands and (later) by the SDK auto-load path.
package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

const (
	DirName          = ".cornerstone"
	ManifestFileName = "manifest.yaml"
	EventsDirName    = "events"
)

// Manifest mirrors schemas/cornerstone-manifest.json. Only fields the Go
// tooling reads are typed; the rest is preserved via the inline map for
// pass-through to validators.
type Manifest struct {
	APIVersion    string                 `yaml:"apiVersion"`
	Kind          string                 `yaml:"kind"`
	Metadata      ManifestMetadata       `yaml:"metadata"`
	Emission      Emission               `yaml:"emission"`
	UUIDStrategy  UUIDStrategy           `yaml:"uuid_strategy"`
	Defaults      map[string]any         `yaml:"defaults,omitempty"`
	Transforms    []Transform            `yaml:"transformations,omitempty"`
	Conventions   *Conventions           `yaml:"conventions,omitempty"`
	Sources       map[string][]string    `yaml:"sources,omitempty"`
	Extras        map[string]any         `yaml:",inline,omitempty"`
}

type ManifestMetadata struct {
	Name        string `yaml:"name"`
	Owner       string `yaml:"owner,omitempty"`
	Description string `yaml:"description,omitempty"`
}

type Emission struct {
	Style    string         `yaml:"style"`
	Language string         `yaml:"language"`
	SDK      *EmissionSDK   `yaml:"sdk,omitempty"`
	OTEL     *EmissionOTEL  `yaml:"otel,omitempty"`
	RawJSON  *EmissionRaw   `yaml:"raw_json,omitempty"`
	Mixed    *EmissionMixed `yaml:"mixed,omitempty"`
}

type EmissionSDK struct {
	Package      string `yaml:"package,omitempty"`
	LoggerModule string `yaml:"logger_module,omitempty"`
}

type EmissionOTEL struct {
	LoggerName      string `yaml:"logger_name,omitempty"`
	AttributePrefix string `yaml:"attribute_prefix,omitempty"`
}

type EmissionRaw struct {
	Target string `yaml:"target,omitempty"`
}

type EmissionMixed struct {
	Preferred string `yaml:"preferred"`
}

type UUIDStrategy struct {
	Mode      string `yaml:"mode"`
	Namespace string `yaml:"namespace,omitempty"`
}

type Transform struct {
	Field     string `yaml:"field"`
	Transform string `yaml:"transform"`
	SaltEnv   string `yaml:"salt_env,omitempty"`
	MaxLength int    `yaml:"max_length,omitempty"`
}

type Conventions struct {
	RequiredContexts []string `yaml:"required_contexts,omitempty"`
	ForbiddenFields  []string `yaml:"forbidden_fields,omitempty"`
	SeverityFloor    string   `yaml:"severity_floor,omitempty"`
}

// EventRecord mirrors schemas/cornerstone-event-record.json.
type EventRecord struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   EventMetadata  `yaml:"metadata"`
	Signature  map[string]any `yaml:"signature"`
	EmitSites  []EmitSite     `yaml:"emit_sites,omitempty"`
	Examples   []any          `yaml:"examples,omitempty"`

	// Path is set by the loader and is not part of the on-disk YAML.
	Path string `yaml:"-"`
}

type EventMetadata struct {
	Name             string   `yaml:"name"`
	UUID             string   `yaml:"uuid"`
	Description      string   `yaml:"description,omitempty"`
	Status           string   `yaml:"status,omitempty"`
	DeprecationNote  string   `yaml:"deprecation_note,omitempty"`
	Tags             []string `yaml:"tags,omitempty"`
}

type EmitSite struct {
	File     string `yaml:"file"`
	Line     int    `yaml:"line"`
	Function string `yaml:"function,omitempty"`
	LastSeen string `yaml:"last_seen,omitempty"`
}

// Registry is the in-memory representation of a loaded .cornerstone/ tree.
type Registry struct {
	Root     string
	Manifest *Manifest
	Events   []*EventRecord
}

// Load reads a .cornerstone/ tree rooted at the given directory (which must be
// the directory CONTAINING .cornerstone/, not .cornerstone itself). Returns an
// error if the manifest is missing or unparseable; missing events directory is
// not an error (a project may have a manifest but no events yet).
func Load(projectRoot string) (*Registry, error) {
	dir := filepath.Join(projectRoot, DirName)
	manifestPath := filepath.Join(dir, ManifestFileName)

	mfBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no Cornerstone registry found at %s (run `corner-lint registry init` to create one)", dir)
		}
		return nil, fmt.Errorf("read %s: %w", manifestPath, err)
	}

	mf := &Manifest{}
	if err := yaml.Unmarshal(mfBytes, mf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifestPath, err)
	}

	r := &Registry{
		Root:     dir,
		Manifest: mf,
	}

	eventsDir := filepath.Join(dir, EventsDirName)
	entries, err := os.ReadDir(eventsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", eventsDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
			continue
		}
		path := filepath.Join(eventsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		ev := &EventRecord{Path: path}
		if err := yaml.Unmarshal(data, ev); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		r.Events = append(r.Events, ev)
	}

	sort.Slice(r.Events, func(i, j int) bool {
		return r.Events[i].Metadata.Name < r.Events[j].Metadata.Name
	})

	return r, nil
}

// Issue is a finding reported by Validate.
type Issue struct {
	Severity string // "error" | "warning"
	File     string
	Message  string
}

// Validate runs the cross-event registry checks: schema-conformance is
// expected to be done by the JSON-Schema validator separately; this function
// adds the relational checks (no duplicate UUIDs / names, manifest sanity,
// dangling emit_sites).
func (r *Registry) Validate(projectRoot string) []Issue {
	var issues []Issue

	// Manifest sanity
	if r.Manifest.APIVersion != "cornerstone.cerebras.net/v1" {
		issues = append(issues, Issue{
			Severity: "error",
			File:     filepath.Join(r.Root, ManifestFileName),
			Message:  fmt.Sprintf("unsupported apiVersion %q (want cornerstone.cerebras.net/v1)", r.Manifest.APIVersion),
		})
	}
	if r.Manifest.Kind != "ProjectManifest" {
		issues = append(issues, Issue{
			Severity: "error",
			File:     filepath.Join(r.Root, ManifestFileName),
			Message:  fmt.Sprintf("kind must be ProjectManifest (got %q)", r.Manifest.Kind),
		})
	}
	if r.Manifest.UUIDStrategy.Mode == "deterministic" && r.Manifest.UUIDStrategy.Namespace == "" {
		issues = append(issues, Issue{
			Severity: "error",
			File:     filepath.Join(r.Root, ManifestFileName),
			Message:  "uuid_strategy.namespace is required when mode is 'deterministic'",
		})
	}
	if r.Manifest.Emission.Style == "mixed" && r.Manifest.Emission.Mixed == nil {
		issues = append(issues, Issue{
			Severity: "error",
			File:     filepath.Join(r.Root, ManifestFileName),
			Message:  "emission.mixed.preferred is required when emission.style is 'mixed'",
		})
	}

	// Cross-event uniqueness
	byUUID := map[string][]*EventRecord{}
	byName := map[string][]*EventRecord{}
	for _, ev := range r.Events {
		byUUID[ev.Metadata.UUID] = append(byUUID[ev.Metadata.UUID], ev)
		byName[ev.Metadata.Name] = append(byName[ev.Metadata.Name], ev)
	}
	for uuid, evs := range byUUID {
		if len(evs) > 1 {
			files := make([]string, 0, len(evs))
			for _, e := range evs {
				files = append(files, e.Path)
			}
			issues = append(issues, Issue{
				Severity: "error",
				Message:  fmt.Sprintf("duplicate UUID %s in: %v", uuid, files),
			})
		}
	}
	for name, evs := range byName {
		if len(evs) > 1 {
			files := make([]string, 0, len(evs))
			for _, e := range evs {
				files = append(files, e.Path)
			}
			issues = append(issues, Issue{
				Severity: "error",
				Message:  fmt.Sprintf("duplicate event name %q in: %v", name, files),
			})
		}
	}

	// File-name vs metadata.name consistency (warning, not error)
	for _, ev := range r.Events {
		base := filepath.Base(ev.Path)
		expected := ev.Metadata.Name + ".yaml"
		expectedShort := ev.Metadata.Name + ".yml"
		if base != expected && base != expectedShort {
			issues = append(issues, Issue{
				Severity: "warning",
				File:     ev.Path,
				Message:  fmt.Sprintf("filename %q does not match metadata.name %q (expected %q)", base, ev.Metadata.Name, expected),
			})
		}
	}

	// Dangling emit_sites — referenced files must exist
	for _, ev := range r.Events {
		for _, site := range ev.EmitSites {
			abs := filepath.Join(projectRoot, site.File)
			if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
				issues = append(issues, Issue{
					Severity: "warning",
					File:     ev.Path,
					Message:  fmt.Sprintf("emit_site references missing file %s:%d", site.File, site.Line),
				})
			}
		}
	}

	// Status / deprecation_note coupling (already in JSON Schema, but we re-check
	// for clearer messages)
	for _, ev := range r.Events {
		if (ev.Metadata.Status == "deprecated" || ev.Metadata.Status == "removed") && ev.Metadata.DeprecationNote == "" {
			issues = append(issues, Issue{
				Severity: "error",
				File:     ev.Path,
				Message:  fmt.Sprintf("status is %q but deprecation_note is empty", ev.Metadata.Status),
			})
		}
	}

	return issues
}

// HasErrors reports whether any of the issues are at error severity.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}
