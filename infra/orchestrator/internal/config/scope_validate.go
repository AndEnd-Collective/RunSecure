package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var validProfiles = map[string]bool{"strict": true, "standard": true, "permissive": true, "custom": true}

// validBackends is the set of backend names accepted by Validate.
// An empty backend field is normalised to "compose" by Validate before
// any other check so callers can omit the field entirely.
var validBackends = map[string]bool{"compose": true, "kube": true}

// Validate enforces spec §4.2 invariants. Fail-closed; orchestrator refuses
// to start if any rule fails.
func (s *Scope) Validate() error {
	// Normalise: empty backend defaults to "compose".
	if s.Backend == "" {
		s.Backend = "compose"
	}
	if !validBackends[s.Backend] {
		return fmt.Errorf("config: backend must be 'compose' or 'kube' (got %q)", s.Backend)
	}
	if s.Name == "" {
		return errors.New("config: name is required")
	}
	if s.PollIntervalSeconds < 5 {
		return fmt.Errorf("config: poll_interval_seconds must be >= 5 (got %d)", s.PollIntervalSeconds)
	}
	if !validProfiles[s.SecurityProfile] {
		return fmt.Errorf("config: security_profile must be one of strict|standard|permissive|custom (got %q)", s.SecurityProfile)
	}
	if s.SecurityProfile == "custom" && len(s.SecurityOverrides) == 0 {
		return errors.New("config: security_profile=custom requires non-empty security_overrides")
	}
	switch s.Auth.Type {
	case "pat":
		if s.Auth.PATFile == "" {
			return errors.New("config: auth.pat_file is required")
		}
		info, err := os.Stat(s.Auth.PATFile)
		if err != nil {
			return fmt.Errorf("config: auth.pat_file %s: %w", s.Auth.PATFile, err)
		}
		if info.Mode().Perm() != 0o400 {
			return fmt.Errorf("config: auth.pat_file %s must be mode 0400 (got %o)", s.Auth.PATFile, info.Mode().Perm())
		}
	case "github_app":
		if s.Auth.AppID <= 0 {
			return errors.New("config: auth.app_id is required for github_app auth")
		}
		if s.Auth.InstallationID <= 0 {
			return errors.New("config: auth.installation_id is required for github_app auth")
		}
		if s.Auth.PrivateKeyFile == "" {
			return errors.New("config: auth.private_key_file is required for github_app auth")
		}
		info, err := os.Stat(s.Auth.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("config: auth.private_key_file %s: %w", s.Auth.PrivateKeyFile, err)
		}
		if info.Mode().Perm() != 0o400 {
			return fmt.Errorf("config: auth.private_key_file %s must be mode 0400 (got %o)", s.Auth.PrivateKeyFile, info.Mode().Perm())
		}
	default:
		return fmt.Errorf("config: auth.type must be 'pat' or 'github_app' (got %q)", s.Auth.Type)
	}
	if !containsStringSlice(s.OrchEgress.AllowDomains, "api.github.com") {
		return errors.New("config: orch_egress.allow_domains must include api.github.com (otherwise orchestrator is offline)")
	}
	if len(s.Repos) == 0 {
		return errors.New("config: at least one repo entry required")
	}
	for i, r := range s.Repos {
		if r.Repo == "" {
			return fmt.Errorf("config: repos[%d].repo is required", i)
		}
		if r.MaxConcurrent <= 0 {
			return fmt.Errorf("config: repos[%d].max_concurrent must be > 0", i)
		}
		// project_dir (bind-mount) is required for the compose backend only;
		// the kube backend fetches runner.yml via the GitHub API instead.
		if s.Backend == "compose" {
			if r.ProjectDir == "" {
				return fmt.Errorf("config: repos[%d].project_dir is required (Compose backend)", i)
			}
			if info, err := os.Stat(r.ProjectDir); err != nil || !info.IsDir() {
				return fmt.Errorf("config: repos[%d].project_dir %s: not a directory", i, r.ProjectDir)
			}
			runnerYml := filepath.Join(r.ProjectDir, ".github", "runner.yml")
			if _, err := os.Stat(runnerYml); err != nil {
				return fmt.Errorf("config: repos[%d]: missing runner.yml at %s", i, runnerYml)
			}
		}
	}
	if s.GlobalMaxRunners <= 0 {
		return errors.New("config: global_max_runners must be > 0")
	}
	// Sum of per-repo caps may exceed global_max_runners — that's intentional
	// fairness (global wins). Not an error.
	return nil
}

func containsStringSlice(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
