package config

import (
	"errors"
	"fmt"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"k8s.io/apimachinery/pkg/api/resource"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
	secretMode := os.FileMode(0o400)
	if s.Backend == "kube" {
		// Kubernetes Secret projections remain root-owned and apply fsGroup as
		// the group owner. 0440 is the least-privilege mode readable by the
		// non-root workload without granting world access.
		secretMode = 0o440
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
		if info.Mode().Perm() != secretMode {
			return fmt.Errorf("config: auth.pat_file %s must be mode %04o (got %o)", s.Auth.PATFile, secretMode, info.Mode().Perm())
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
		if info.Mode().Perm() != secretMode {
			return fmt.Errorf("config: auth.private_key_file %s must be mode %04o (got %o)", s.Auth.PrivateKeyFile, secretMode, info.Mode().Perm())
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
	if err := s.validateProjects(); err != nil {
		return err
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

var repoIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var runnerRuntime = regexp.MustCompile(`^(node|python|rust)(:[A-Za-z0-9][A-Za-z0-9_.-]*)?$`)
var runnerMemory = regexp.MustCompile(`^[1-9][0-9]*[kKmMgG]$`)
var runnerLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.=-]*$`)
var immutableImage = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`)

func (s *Scope) validateProjects() error {
	shared := s.SharedKubernetes()
	if shared && s.Backend != "kube" {
		return errors.New("config: project namespaces require kube backend")
	}
	if shared && (len(kubevalidation.IsDNS1123Label("runsecure-"+s.Name)) != 0) {
		return errors.New("config: invalid controller namespace")
	}
	repos, namespaces := map[string]bool{}, map[string]bool{}
	for i := range s.Repos {
		r := &s.Repos[i]
		if !shared {
			continue
		}
		identity := strings.ToLower(r.Repo)
		if !repoIdentity.MatchString(r.Repo) || repos[identity] {
			return fmt.Errorf("config: invalid or duplicate repo %q", r.Repo)
		}
		repos[identity] = true
		if r.Namespace == "" || len(kubevalidation.IsDNS1123Label(r.Namespace)) != 0 || r.Namespace == "default" || strings.HasPrefix(r.Namespace, "kube-") || r.Namespace == "runsecure-"+s.Name || namespaces[r.Namespace] {
			return fmt.Errorf("config: invalid, missing or duplicate project namespace %q", r.Namespace)
		}
		namespaces[r.Namespace] = true
		if err := validateApprovedRunner(r); err != nil {
			return fmt.Errorf("config: repos[%d]: %w", i, err)
		}
	}
	return nil
}

func validateApprovedRunner(r *RepoBlock) error {
	runner := r.RunnerConfig
	if runner == nil {
		return errors.New("runner_config required for shared Kubernetes")
	}
	if !runnerRuntime.MatchString(runner.Runtime) {
		return errors.New("runner_config.runtime must select node, python or rust")
	}
	if !runnerMemory.MatchString(runner.Resources.Memory) || runner.Resources.CPUs < 1 || runner.Resources.CPUs > 128 || runner.Resources.PIDs < 1 || runner.Resources.PIDs > 32768 {
		return errors.New("runner_config.resources require positive bounded memory, cpus and pids")
	}
	memory := runner.Resources.Memory
	count, err := strconv.ParseInt(memory[:len(memory)-1], 10, 64)
	if err != nil || count > (512<<30)/(map[byte]int64{'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}[byte(strings.ToLower(memory[len(memory)-1:])[0])]) {
		return errors.New("runner_config.resources.memory exceeds 512g")
	}
	if len(runner.Labels) == 0 || len(runner.Labels) > 98 {
		return errors.New("runner_config.labels require 1 to 98 labels")
	}
	labels := map[string]bool{}
	arch := ""
	for _, label := range runner.Labels {
		lower := strings.ToLower(label)
		if len(label) > 255 || !runnerLabel.MatchString(label) || labels[lower] {
			return errors.New("runner_config.labels contains invalid or duplicate label")
		}
		labels[lower] = true
		candidate := ""
		switch lower {
		case "arm64":
			candidate = "arm64"
		case "x64":
			candidate = "amd64"
		case "arm", "x86", "windows", "macos":
			return errors.New("runner_config.labels unsupported OS or architecture")
		}
		if candidate != "" {
			if arch != "" && candidate != arch {
				return errors.New("runner_config.labels has conflicting architectures")
			}
			arch = candidate
		}
	}
	if arch == "" {
		arch = "amd64"
	}
	if runner.Orchestrator.SeccompProfile != "" {
		return errors.New("custom seccomp profiles unsupported; use RuntimeDefault")
	}
	if runner.Orchestrator.TimeoutSeconds < 0 || runner.Orchestrator.TimeoutSeconds > 86400 {
		return errors.New("runner_config timeout must be between 0 and 86400 seconds")
	}
	if runner.Orchestrator.TimeoutSeconds == 0 {
		runner.Orchestrator.TimeoutSeconds = 21600
	}
	if err := runner.ValidateEgress(); err != nil {
		return err
	}
	if r.RunnerImage != "" && !immutableImage.MatchString(r.RunnerImage) {
		return errors.New("runner_image must be immutable image@sha256 digest")
	}
	return validatePodSettings(&r.Kubernetes, arch)
}

func validatePodSettings(settings *backend.KubePodSettings, arch string) error {
	if settings.NodeSelector == nil {
		settings.NodeSelector = map[string]string{}
	}
	if len(settings.NodeSelector) > 16 || len(settings.Tolerations) > 16 {
		return errors.New("kubernetes placement exceeds 16 entries")
	}
	for key, value := range settings.NodeSelector {
		if len(kubevalidation.IsQualifiedName(key)) != 0 || len(kubevalidation.IsValidLabelValue(value)) != 0 {
			return errors.New("kubernetes.node_selector invalid label")
		}
	}
	if selected := settings.NodeSelector["kubernetes.io/arch"]; selected != "" && selected != arch {
		return errors.New("kubernetes.node_selector architecture conflicts with runner labels")
	}
	if selected := settings.NodeSelector["kubernetes.io/os"]; selected != "" && selected != "linux" {
		return errors.New("kubernetes.node_selector OS must be linux")
	}
	settings.NodeSelector["kubernetes.io/arch"], settings.NodeSelector["kubernetes.io/os"] = arch, "linux"
	for i := range settings.Tolerations {
		tol := &settings.Tolerations[i]
		if tol.Operator == "" {
			tol.Operator = "Equal"
		}
		if tol.Key == "" || len(kubevalidation.IsQualifiedName(tol.Key)) != 0 || len(kubevalidation.IsValidLabelValue(tol.Value)) != 0 || (tol.Operator != "Equal" && tol.Operator != "Exists") || (tol.Operator == "Exists" && tol.Value != "") || (tol.Effect != "NoSchedule" && tol.Effect != "PreferNoSchedule" && tol.Effect != "NoExecute") || (tol.TolerationSeconds != nil && (tol.Effect != "NoExecute" || *tol.TolerationSeconds < 0 || *tol.TolerationSeconds > 86400)) {
			return errors.New("kubernetes.tolerations invalid bounded toleration")
		}
	}
	if settings.EphemeralStorage == "" {
		settings.EphemeralStorage = "10Gi"
	}
	if settings.ProxyResources.CPU == "" {
		settings.ProxyResources.CPU = "250m"
	}
	if settings.ProxyResources.Memory == "" {
		settings.ProxyResources.Memory = "256Mi"
	}
	if settings.ProxyResources.EphemeralStorage == "" {
		settings.ProxyResources.EphemeralStorage = "1Gi"
	}
	for _, item := range []struct{ value, max string }{{settings.EphemeralStorage, "1Ti"}, {settings.ProxyResources.CPU, "8"}, {settings.ProxyResources.Memory, "8Gi"}, {settings.ProxyResources.EphemeralStorage, "100Gi"}} {
		quantity, err := resource.ParseQuantity(item.value)
		if err != nil || quantity.Sign() <= 0 || quantity.Cmp(resource.MustParse(item.max)) > 0 {
			return errors.New("kubernetes resource quantity must be positive and bounded")
		}
	}
	return nil
}
