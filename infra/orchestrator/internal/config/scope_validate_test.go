package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeScope(t *testing.T, mut func(*Scope)) *Scope {
	t.Helper()
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_x"), 0o400))
	projDir := filepath.Join(dir, "proj")
	require.NoError(t, os.MkdirAll(filepath.Join(projDir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projDir, ".github", "runner.yml"), []byte("runtime: node:24\n"), 0o644))

	s := &Scope{
		APIVersion:          SupportedAPIVersion,
		Name:                "test",
		GlobalMaxRunners:    8,
		PollIntervalSeconds: 15,
		SecurityProfile:     "strict",
		Auth:                AuthBlock{Type: "pat", PATFile: patFile},
		OrchEgress:          OrchEgressBlock{AllowDomains: []string{"api.github.com"}},
		Repos: []RepoBlock{{
			Repo: "o/r", ProjectDir: projDir, MaxConcurrent: 3,
		}},
	}
	if mut != nil {
		mut(s)
	}
	return s
}

func TestValidate_HappyPath(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, s.Validate())
}

func TestValidate_NameRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Name = "" })
	require.ErrorContains(t, s.Validate(), "name")
}

func TestValidate_PollIntervalFloor(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 3 })
	require.ErrorContains(t, s.Validate(), "poll_interval_seconds")
}

// Mutation kill: scope_validate.go:18 — `< 5` boundary. Mutation `<= 5`
// would also reject 5; mutation `< 4` would accept 4. Cover both ends.
func TestValidate_PollIntervalExactlyFive_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 5 })
	require.NoError(t, s.Validate(),
		"poll_interval_seconds=5 is the lower bound and must be accepted")
}

func TestValidate_PollIntervalFour_Rejected(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 4 })
	require.Error(t, s.Validate())
}

func TestValidate_SecurityProfileWhitelist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.SecurityProfile = "yolo" })
	require.ErrorContains(t, s.Validate(), "security_profile")
}

func TestValidate_CustomProfileRequiresOverrides(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.SecurityProfile = "custom" })
	require.ErrorContains(t, s.Validate(), "security_overrides")
}

func TestValidate_AuthTypeMustBePAT(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.Type = "github_app" })
	require.ErrorContains(t, s.Validate(), "auth.type")
}

func TestValidate_PATFileRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.PATFile = "" })
	require.ErrorContains(t, s.Validate(), "pat_file")
}

func TestValidate_PATFileMustExist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.PATFile = "/nonexistent" })
	require.Error(t, s.Validate())
}

func TestValidate_PATFileMode0400Required(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, os.Chmod(s.Auth.PATFile, 0o644))
	require.ErrorContains(t, s.Validate(), "mode 0400")
}

func TestValidate_ApiGithubComRequiredInAllowDomains(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.OrchEgress.AllowDomains = []string{"example.com"} })
	require.ErrorContains(t, s.Validate(), "api.github.com")
}

func TestValidate_ReposNonEmpty(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos = nil })
	require.ErrorContains(t, s.Validate(), "repo")
}

func TestValidate_RepoNameRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].Repo = "" })
	require.ErrorContains(t, s.Validate(), "repos[0].repo")
}

func TestValidate_MaxConcurrentPositive(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].MaxConcurrent = 0 })
	require.ErrorContains(t, s.Validate(), "max_concurrent")
}

func TestValidate_ProjectDirRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].ProjectDir = "" })
	require.ErrorContains(t, s.Validate(), "project_dir")
}

func TestValidate_ProjectDirMustExist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].ProjectDir = "/nonexistent" })
	require.ErrorContains(t, s.Validate(), "project_dir")
}

func TestValidate_RunnerYmlMustExist(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, os.Remove(filepath.Join(s.Repos[0].ProjectDir, ".github", "runner.yml")))
	require.ErrorContains(t, s.Validate(), "runner.yml")
}

func TestValidate_GlobalMaxRunnersPositive(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.GlobalMaxRunners = 0 })
	require.ErrorContains(t, s.Validate(), "global_max_runners")
}

// --- backend field ---

// TestValidate_Backend_Empty_DefaultsToCompose verifies that omitting backend
// is equivalent to setting it to "compose" — the zero value is normalised.
func TestValidate_Backend_Empty_DefaultsToCompose(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "" })
	require.NoError(t, s.Validate())
	require.Equal(t, "compose", s.Backend,
		"empty backend must be normalised to 'compose'")
}

// TestValidate_Backend_Compose_Accepted verifies the explicit "compose" value.
func TestValidate_Backend_Compose_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "compose" })
	require.NoError(t, s.Validate())
}

// TestValidate_Backend_Kube_Accepted verifies that "kube" is a valid backend
// value (Phase 2 will wire it; validation must accept it now).
func TestValidate_Backend_Kube_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "kube" })
	require.NoError(t, s.Validate())
}

// TestValidate_Backend_Invalid_Rejected verifies that unknown backend values
// are rejected with an informative error.
func TestValidate_Backend_Invalid_Rejected(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "bogus" })
	require.ErrorContains(t, s.Validate(), "backend")
}

// TestValidate_Backend_Invalid_Rejected_Docker verifies "docker" is not a
// valid alias (the accepted values are precisely "compose" and "kube").
func TestValidate_Backend_Invalid_Rejected_Docker(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "docker" })
	require.ErrorContains(t, s.Validate(), "backend")
}
