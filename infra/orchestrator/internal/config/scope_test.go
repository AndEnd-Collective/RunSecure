package config

import (
	"bytes"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// This boundary test parses the exact scope ConfigMap emitted by Helm through
// the production loader, including numeric GitHub App IDs and nested key names.
func TestHelmSharedScopeParsesInProduction(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm unavailable")
	}
	chart, err := filepath.Abs("../../../../charts/runsecure-orchestrator")
	require.NoError(t, err)
	projects := `[{"repo":"acme/alpha","namespace":"project-alpha","maxConcurrent":2,"runnerConfig":{"runtime":"node:24","labels":["self-hosted","Linux","ARM64","container"],"resources":{"memory":"2g","cpus":2,"pids":256},"httpEgress":["api.github.com"],"orchestrator":{"timeoutSeconds":60}},"kubernetes":{"ephemeralStorage":"20Gi","nodeSelector":{"dedicated":"ci"},"proxyResources":{"cpu":"500m","memory":"512Mi","ephemeralStorage":"2Gi"},"tolerations":[{"key":"dedicated","operator":"Equal","value":"ci","effect":"NoSchedule"}]}},{"repo":"acme/beta","namespace":"project-beta","maxConcurrent":1,"runnerConfig":{"runtime":"python:3.12","labels":["container"],"resources":{"memory":"1g","cpus":1,"pids":256}}}]`
	command := exec.Command(helm, "template", "shared", chart, "--set", "scope.name=shared", "--set", "auth.type=github_app", "--set-string", "auth.app.appId=123", "--set-string", "auth.app.installationId=456", "--set", "auth.app.privateKeySecretName=app-key", "--set-json", "scope.repos="+projects, "--set", "image.orchestrator.digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	rendered, err := command.CombinedOutput()
	require.NoError(t, err, string(rendered))
	decoder := yaml.NewDecoder(bytes.NewReader(rendered))
	scopeYAML := ""
	for {
		var doc struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
			Spec map[string]any    `yaml:"spec"`
		}
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if doc.Kind == "ConfigMap" {
			scopeYAML = doc.Data["scope.yml"]
		}
		if doc.Kind == "NetworkPolicy" {
			if rules, ok := doc.Spec["egress"].([]any); ok {
				for _, rule := range rules {
					for _, peer := range rule.(map[string]any)["to"].([]any) {
						block, ok := peer.(map[string]any)["ipBlock"].(map[string]any)
						if !ok || block["cidr"] != "0.0.0.0/0" {
							continue
						}
						expected := []string{}
						for _, cidr := range security.BlockedEgressCIDRs() {
							if !strings.Contains(cidr, ":") {
								expected = append(expected, cidr)
							}
						}
						require.ElementsMatch(t, expected, block["except"], "chart must mirror canonical blocked IPv4 destinations")
					}
				}
			}
		}
	}
	require.NotEmpty(t, scopeYAML)
	path := filepath.Join(t.TempDir(), "scope.yml")
	require.NoError(t, os.WriteFile(path, []byte(scopeYAML), 0o600))
	scope, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, int64(123), scope.Auth.AppID)
	require.Equal(t, int64(456), scope.Auth.InstallationID)
	key := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(key, []byte("fixture"), 0o440))
	scope.Auth.PrivateKeyFile = key
	require.NoError(t, scope.Validate())
	require.True(t, scope.SharedKubernetes())
	require.Len(t, scope.ProjectNamespaces(), 2)
	require.Equal(t, "20Gi", scope.Repos[0].Kubernetes.EphemeralStorage)
	require.Equal(t, "2Gi", scope.Repos[0].Kubernetes.ProxyResources.EphemeralStorage)
	require.Equal(t, 60, scope.Repos[0].RunnerConfig.Orchestrator.TimeoutSeconds)
	require.Equal(t, []string{"api.github.com"}, scope.Repos[0].RunnerConfig.HTTPEgress)
}
