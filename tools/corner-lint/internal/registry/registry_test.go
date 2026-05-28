// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingDir(t *testing.T) {
	tmp := t.TempDir()
	_, err := Load(tmp)
	if err == nil {
		t.Fatal("expected error when .cornerstone/ is missing")
	}
}

func TestLoadAndValidate_Valid(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".cornerstone", "manifest.yaml"), validManifest)
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "auth.login.yaml"), validEventLogin)
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "auth.logout.yaml"), validEventLogout)
	writeFile(t, filepath.Join(tmp, "src", "auth.py"), "# stub")

	reg, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(reg.Events) != 2 {
		t.Fatalf("want 2 events, got %d", len(reg.Events))
	}
	issues := reg.Validate(tmp)
	if HasErrors(issues) {
		t.Fatalf("unexpected errors: %+v", issues)
	}
}

func TestValidate_DuplicateUUID(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".cornerstone", "manifest.yaml"), validManifest)
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "a.yaml"), validEventLogin)
	// Second event reuses the UUID from validEventLogin
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "b.yaml"), validEventLoginDup)

	reg, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	issues := reg.Validate(tmp)
	if !HasErrors(issues) {
		t.Fatalf("expected duplicate-UUID error; got: %+v", issues)
	}
}

func TestValidate_DanglingEmitSite(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".cornerstone", "manifest.yaml"), validManifest)
	// validEventLogin references src/auth.py which we don't create
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "auth.login.yaml"), validEventLogin)

	reg, _ := Load(tmp)
	issues := reg.Validate(tmp)
	found := false
	for _, i := range issues {
		if i.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dangling-emit_site warning; got: %+v", issues)
	}
}

func TestValidate_DeprecationNoteRequired(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".cornerstone", "manifest.yaml"), validManifest)
	writeFile(t, filepath.Join(tmp, ".cornerstone", "events", "auth.login.yaml"), deprecatedNoNote)

	reg, _ := Load(tmp)
	issues := reg.Validate(tmp)
	if !HasErrors(issues) {
		t.Fatalf("expected error for deprecated event without deprecation_note; got: %+v", issues)
	}
}

func TestValidate_DeterministicNamespaceRequired(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".cornerstone", "manifest.yaml"), deterministicNoNamespace)

	reg, _ := Load(tmp)
	issues := reg.Validate(tmp)
	if !HasErrors(issues) {
		t.Fatalf("expected error for deterministic mode without namespace; got: %+v", issues)
	}
}

// ---- fixtures ------------------------------------------------------------

const validManifest = `apiVersion: cornerstone.cerebras.net/v1
kind: ProjectManifest
metadata:
  name: test-project
emission:
  style: raw-json
  language: python
  raw_json:
    target: stderr
uuid_strategy:
  mode: random
defaults:
  signature: test-project-v1
sources:
  python: ["src/**/*.py"]
`

const validEventLogin = `apiVersion: cornerstone.cerebras.net/v1
kind: EventSignature
metadata:
  name: auth.login
  uuid: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  description: User logs in.
  status: active
signature:
  event.signature: test-project-v1
  configuration:
    time.stamp: ISO 8601
    event.format: json
emit_sites:
  - file: src/auth.py
    line: 42
    function: handle_login
    last_seen: 2026-04-25
`

const validEventLogout = `apiVersion: cornerstone.cerebras.net/v1
kind: EventSignature
metadata:
  name: auth.logout
  uuid: b2c3d4e5-f6a7-8901-bcde-f23456789012
  description: User logs out.
signature:
  event.signature: test-project-v1
  configuration:
    time.stamp: ISO 8601
    event.format: json
`

// Same UUID as validEventLogin, different name.
const validEventLoginDup = `apiVersion: cornerstone.cerebras.net/v1
kind: EventSignature
metadata:
  name: auth.relogin
  uuid: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  description: dup
signature:
  event.signature: test-project-v1
  configuration:
    time.stamp: ISO 8601
    event.format: json
`

const deprecatedNoNote = `apiVersion: cornerstone.cerebras.net/v1
kind: EventSignature
metadata:
  name: auth.login
  uuid: c3d4e5f6-a7b8-9012-cdef-345678901234
  status: deprecated
signature:
  event.signature: test-project-v1
  configuration:
    time.stamp: ISO 8601
    event.format: json
`

const deterministicNoNamespace = `apiVersion: cornerstone.cerebras.net/v1
kind: ProjectManifest
metadata:
  name: test-project
emission:
  style: raw-json
  language: python
uuid_strategy:
  mode: deterministic
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}
