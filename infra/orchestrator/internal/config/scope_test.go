package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_ValidScope(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_xxx\n"), 0o400))

	projDir := filepath.Join(dir, "proj")
	require.NoError(t, os.MkdirAll(filepath.Join(projDir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projDir, ".github", "runner.yml"), []byte("runtime: node:24\n"), 0o644))

	yml := `
apiVersion: runsecure.io/v1alpha1
name: datacentric
description: test
global_max_runners: 8
poll_interval_seconds: 15
security_profile: strict
allow_project_overrides: [allow_wildcards]
auth:
  type: pat
  pat_file: ` + patFile + `
orch_egress:
  allow_domains: [api.github.com]
repos:
  - repo: NaorPenso/datacentric
    project_dir: ` + projDir + `
    max_concurrent: 5
`
	path := filepath.Join(dir, "scope.yml")
	require.NoError(t, os.WriteFile(path, []byte(yml), 0o644))

	s, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "datacentric", s.Name)
	require.Equal(t, 8, s.GlobalMaxRunners)
	require.Equal(t, 15, s.PollIntervalSeconds)
	require.Equal(t, "strict", s.SecurityProfile)
	require.Equal(t, []string{"allow_wildcards"}, s.AllowProjectOverrides)
	require.Equal(t, "pat", s.Auth.Type)
	require.Equal(t, patFile, s.Auth.PATFile)
	require.Len(t, s.Repos, 1)
	require.Equal(t, "NaorPenso/datacentric", s.Repos[0].Repo)
	require.Equal(t, projDir, s.Repos[0].ProjectDir)
	require.Equal(t, 5, s.Repos[0].MaxConcurrent)
}

func TestLoad_MissingApiVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yml")
	require.NoError(t, os.WriteFile(path, []byte("name: x\n"), 0o644))
	_, err := Load(path)
	require.ErrorContains(t, err, "apiVersion")
}

func TestLoad_UnsupportedApiVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: runsecure.io/v2\nname: x\n"), 0o644))
	_, err := Load(path)
	require.ErrorContains(t, err, "unsupported apiVersion")
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/scope.yml")
	require.Error(t, err)
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yml")
	require.NoError(t, os.WriteFile(path, []byte("not: : valid: yaml"), 0o644))
	_, err := Load(path)
	require.Error(t, err)
}
