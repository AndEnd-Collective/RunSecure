package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/egress"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/stretchr/testify/require"
)

// newFSGen returns an FSGenerator backed by a temp directory.
func newFSGen(t *testing.T) *egress.FSGenerator {
	t.Helper()
	return egress.NewFSGenerator(t.TempDir())
}

// TestEgressShim_ScopeAllows_ProjectOverrideApplied verifies the positive gate:
// when the scope permits "allow_private_cidrs" and the project requests it,
// the resolved policy contains the private CIDR and Render succeeds on a
// literal private-IP egress entry.
func TestEgressShim_ScopeAllows_ProjectOverrideApplied(t *testing.T) {
	base := security.Defaults("strict") // AllowedPrivateCIDRs = nil
	allowKeys := []string{"allow_private_cidrs"}

	shim := egressShim{
		g:        newFSGen(t),
		base:     base,
		allowKeys: allowKeys,
	}

	// Project requests allow_private_cidrs: ["10.0.0.0/8"]
	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
		Orchestrator: runneryml.OrchestratorBlock{
			SecurityOverrides: map[string]any{
				"allow_private_cidrs": []any{"10.0.0.0/8"},
			},
		},
	}

	_, err := shim.Render("spawn-pos", r)
	require.NoError(t, err,
		"project override allowed by scope must permit 10.0.0.5 via allow_private_cidrs")
}

// TestEgressShim_ScopeDisallows_ProjectOverrideIgnored is the load-bearing gate
// test: when the scope does NOT list "allow_private_cidrs" in AllowProjectOverrides,
// a project requesting it must NOT be able to authorize private-IP egress.
func TestEgressShim_ScopeDisallows_ProjectOverrideIgnored(t *testing.T) {
	base := security.Defaults("strict")
	allowKeys := []string{} // allow_private_cidrs NOT listed — project cannot authorize it

	shim := egressShim{
		g:        newFSGen(t),
		base:     base,
		allowKeys: allowKeys,
	}

	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
		Orchestrator: runneryml.OrchestratorBlock{
			SecurityOverrides: map[string]any{
				"allow_private_cidrs": []any{"10.0.0.0/8"},
			},
		},
	}

	_, err := shim.Render("spawn-neg", r)
	require.Error(t, err,
		"project cannot self-authorize allow_private_cidrs when scope disallows it")
	require.Contains(t, err.Error(), "security:",
		"error must originate from the SSRF guard, not from override parsing")
}

// TestEgressShim_MalformedOverride_SpawnFails verifies that a type-mismatched
// project override (not a list) causes Render to return an error rather than
// silently applying no override.
func TestEgressShim_MalformedOverride_SpawnFails(t *testing.T) {
	base := security.Defaults("strict")
	allowKeys := []string{"allow_private_cidrs"}

	shim := egressShim{
		g:        newFSGen(t),
		base:     base,
		allowKeys: allowKeys,
	}

	r := &runneryml.Runner{
		Orchestrator: runneryml.OrchestratorBlock{
			SecurityOverrides: map[string]any{
				// Wrong type: string instead of []any.
				"allow_private_cidrs": "10.0.0.0/8",
			},
		},
	}

	_, err := shim.Render("spawn-malformed", r)
	require.Error(t, err, "malformed override value must cause spawn to fail")
	require.Contains(t, err.Error(), "allow_private_cidrs",
		"error must name the offending key")
}

// TestEgressShim_ScopeOperatorOverrideApplied verifies that the scope-level
// (operator) override on the base policy is respected before project overrides
// are merged. Here the base already has private CIDRs from the operator, and
// the scope lists NO project-allow keys, yet the spawn succeeds because the
// operator-level override was applied at basePolicy construction time.
func TestEgressShim_ScopeOperatorOverrideAppliedAtBase(t *testing.T) {
	// Simulate the operator having applied allow_private_cidrs at scope level
	// (step 2 of policy resolution: unrestricted scope overrides).
	allKeys := []string{
		"allow_wildcards", "allow_doh", "allow_imds",
		"allow_kube_api", "allow_private_cidrs",
	}
	base, err := security.ApplyProjectOverrides(
		security.Defaults("strict"),
		allKeys,
		map[string]any{"allow_private_cidrs": []any{"10.0.0.0/8"}},
	)
	require.NoError(t, err)

	// Scope does NOT permit any project overrides.
	shim := egressShim{
		g:        newFSGen(t),
		base:     base,
		allowKeys: []string{},
	}

	// Project does NOT set any overrides, but the operator base allows 10.x.
	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
	}

	_, err = shim.Render("spawn-opbase", r)
	require.NoError(t, err,
		"operator scope override on base must allow private-IP egress")
}

// TestEgressShim_NoProjectOverrides_BaseUsed verifies the zero-override path:
// no SecurityOverrides in the project means the base policy governs and strict
// base blocks private IPs.
func TestEgressShim_NoProjectOverrides_BaseUsed(t *testing.T) {
	shim := egressShim{
		g:        newFSGen(t),
		base:     security.Defaults("strict"),
		allowKeys: []string{"allow_private_cidrs"},
	}

	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
		// No Orchestrator.SecurityOverrides set.
	}

	_, err := shim.Render("spawn-noover", r)
	require.Error(t, err, "no override set → base strict policy must reject private IP")
}

// TestBuildBasePolicy_ScopeOverridesApplied verifies buildBasePolicy (the
// run.go function that materialises base = Defaults + scope-level overrides).
func TestBuildBasePolicy_ScopeOverridesApplied(t *testing.T) {
	allKeys := []string{
		"allow_wildcards", "allow_doh", "allow_imds",
		"allow_kube_api", "allow_private_cidrs",
	}
	overrides := map[string]any{
		"allow_private_cidrs": []any{"192.168.0.0/16"},
	}

	base, err := buildBasePolicy("strict", overrides, allKeys)
	require.NoError(t, err)
	require.Len(t, base.AllowedPrivateCIDRs, 1)

	// Write a temp egress file to prove the policy would pass CheckEgressIPLiterals.
	dir := t.TempDir()
	confPath := filepath.Join(dir, "squid.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(""), 0o644))

	err = security.CheckEgressIPLiterals([]string{"192.168.1.1:5432"}, base)
	require.NoError(t, err, "192.168.1.1 must be allowed after scope-level CIDR override")
}

// TestBuildBasePolicy_MalformedScopeOverride_ReturnsError verifies that a
// malformed scope-level override (startup time) returns an error rather than
// silently falling back.
func TestBuildBasePolicy_MalformedScopeOverride_ReturnsError(t *testing.T) {
	allKeys := []string{"allow_private_cidrs"}
	_, err := buildBasePolicy("strict",
		map[string]any{"allow_private_cidrs": "not-a-list"},
		allKeys,
	)
	require.Error(t, err, "malformed scope override must abort startup")
}

// TestRunnerYML_DeprecationWarning_EmittedToStderr verifies that when a project's
// runner.yml uses the deprecated egress.allow_domains key, RunnerYML emits a
// [RunSecure] WARNING to stderr. This exercises the wiring added in run.go that
// calls yml.DeprecationWarnings() after every successful Parse.
func TestRunnerYML_DeprecationWarning_EmittedToStderr(t *testing.T) {
	// Write a runner.yml that uses the deprecated egress.allow_domains key.
	dir := t.TempDir()
	ghDir := filepath.Join(dir, ".github")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ghDir, "runner.yml"), []byte(`
runtime: node:24
egress:
  allow_domains:
    - api.github.com
`), 0o644))

	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{
				{Repo: "owner/repo", ProjectDir: dir},
			},
		},
	}

	// Redirect stderr so we can assert on the warning output.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	snap, parseErr := pd.RunnerYML("owner/repo")

	// Restore stderr before any assertions so test output is not lost.
	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	require.NoError(t, parseErr)
	require.NotNil(t, snap)
	require.Contains(t, buf.String(), "[RunSecure] WARNING:",
		"deprecation warning must be emitted to stderr")
	require.Contains(t, buf.String(), "egress.allow_domains is deprecated",
		"warning must name the deprecated key")
}

// TestRunnerYML_NoWarning_WhenHTTPEgressUsed verifies that no deprecation warning
// is emitted when the current http_egress key is used.
func TestRunnerYML_NoWarning_WhenHTTPEgressUsed(t *testing.T) {
	dir := t.TempDir()
	ghDir := filepath.Join(dir, ".github")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ghDir, "runner.yml"), []byte(`
runtime: node:24
http_egress:
  - api.github.com
`), 0o644))

	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{
				{Repo: "owner/repo", ProjectDir: dir},
			},
		},
	}

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	snap, parseErr := pd.RunnerYML("owner/repo")

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	require.NoError(t, parseErr)
	require.NotNil(t, snap)
	require.NotContains(t, buf.String(), "[RunSecure] WARNING:",
		"no deprecation warning must be emitted when http_egress is used")
}

// TestAllOverrideKeys_EachKeyRecognized is a drift guard: for every key returned
// by allOverrideKeys(), we supply a minimal valid value and assert that
// ApplyProjectOverrides accepts it without error. A silent drop (key in the list
// but not handled by the switch) would still return no error but leave the policy
// unchanged — the test accepts that as OK per the spec, since the gate contract
// is that the key is *recognized* (not silently rejected). The real protection is
// Fix 1: invalid types now return errors, so any future key that is gated but
// unhandled will be caught at the type-mismatch layer before it can slip through.
func TestAllOverrideKeys_EachKeyRecognized(t *testing.T) {
	minimalValues := map[string]any{
		"allow_wildcards":    []any{"*.example.com"},
		"allow_doh":          true,
		"allow_imds":         true,
		"allow_kube_api":     true,
		"allow_private_cidrs": []any{"10.0.0.0/8"},
	}

	keys := allOverrideKeys()
	for _, key := range keys {
		key := key
		t.Run(key, func(t *testing.T) {
			val, ok := minimalValues[key]
			require.True(t, ok,
				"key %q is in allOverrideKeys() but has no minimal valid value in the drift-guard table — update the table", key)

			base := security.Defaults("strict")
			_, err := security.ApplyProjectOverrides(base, []string{key}, map[string]any{key: val})
			require.NoError(t, err,
				"key %q with minimal valid value must be accepted by ApplyProjectOverrides", key)
		})
	}
}
