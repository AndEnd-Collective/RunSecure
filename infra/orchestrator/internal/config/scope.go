// Package config loads and validates orchestrator scope configuration.
package config

import (
	"fmt"
	"os"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"gopkg.in/yaml.v3"
)

// SupportedAPIVersion is the only accepted apiVersion field value.
// Bumping requires a migration guide for users.
const SupportedAPIVersion = "runsecure.io/v1alpha1"

// Scope is one orchestrator deployment unit. One Scope = one compose stack.
type Scope struct {
	APIVersion            string          `yaml:"apiVersion"`
	Name                  string          `yaml:"name"`
	Description           string          `yaml:"description"`
	Backend               string          `yaml:"backend"` // "compose" (default) or "kube"
	GlobalMaxRunners      int             `yaml:"global_max_runners"`
	PollIntervalSeconds   int             `yaml:"poll_interval_seconds"`
	SecurityProfile       string          `yaml:"security_profile"`
	SecurityOverrides     map[string]any  `yaml:"security_overrides"`
	AllowProjectOverrides []string        `yaml:"allow_project_overrides"`
	Auth                  AuthBlock       `yaml:"auth"`
	OrchEgress            OrchEgressBlock `yaml:"orch_egress"`
	Repos                 []RepoBlock     `yaml:"repos"`
}

type AuthBlock struct {
	Type           string `yaml:"type"`             // "pat" or "github_app"
	PATFile        string `yaml:"pat_file"`         // required when type=pat
	AppID          int64  `yaml:"app_id"`           // required when type=github_app
	InstallationID int64  `yaml:"installation_id"`  // required when type=github_app
	PrivateKeyFile string `yaml:"private_key_file"` // required when type=github_app (mode 0400)
}

type OrchEgressBlock struct {
	AllowDomains []string `yaml:"allow_domains"`
}

type RepoBlock struct {
	sharedSettingsDeclared bool
	Namespace              string                  `yaml:"namespace,omitempty"`
	RunnerConfig           *runneryml.Runner       `yaml:"runner_config,omitempty"`
	RunnerImage            string                  `yaml:"runner_image,omitempty"`
	Kubernetes             backend.KubePodSettings `yaml:"kubernetes,omitempty"`
	Repo                   string                  `yaml:"repo"`        // "owner/name"
	ProjectDir             string                  `yaml:"project_dir"` // Compose-only (bind-mount)
	MaxConcurrent          int                     `yaml:"max_concurrent"`
}

// UnmarshalYAML retains shared-only declarations even when empty, so an
// incomplete enrollment cannot silently select repository-controlled policy.
func (r *RepoBlock) UnmarshalYAML(node *yaml.Node) error {
	type plainRepo RepoBlock
	var decoded plainRepo
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	*r = RepoBlock(decoded)
	for name := range fields {
		switch name {
		case "runner_config", "runner_image", "kubernetes":
			r.sharedSettingsDeclared = true
		}
	}
	return nil
}

// Load reads and parses a scope YAML. Does NOT validate semantically — see
// Validate() in scope_validate.go.
func Load(path string) (*Scope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var s Scope
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if s.APIVersion == "" {
		return nil, fmt.Errorf("config: %s: apiVersion is required (expected %s)", path, SupportedAPIVersion)
	}
	if s.APIVersion != SupportedAPIVersion {
		return nil, fmt.Errorf("config: %s: unsupported apiVersion %q (expected %s)", path, s.APIVersion, SupportedAPIVersion)
	}
	return &s, nil
}

// SharedKubernetes reports explicit enrollment or shared-only configuration
// intent. Validation requires every such project to have a namespace.
func (s *Scope) SharedKubernetes() bool {
	for _, r := range s.Repos {
		if r.Namespace != "" || r.sharedSettingsDeclared || r.RunnerConfig != nil || r.RunnerImage != "" ||
			r.Kubernetes.NodeSelector != nil || r.Kubernetes.Tolerations != nil || r.Kubernetes.EphemeralStorage != "" ||
			r.Kubernetes.ProxyResources != (backend.KubeProxyResources{}) {
			return true
		}
	}
	return false
}

// ProjectNamespaces returns the operator-approved mapping for shared mode.
func (s *Scope) ProjectNamespaces() map[string]string {
	if !s.SharedKubernetes() {
		return nil
	}
	out := make(map[string]string, len(s.Repos))
	for _, r := range s.Repos {
		out[r.Repo] = r.Namespace
	}
	return out
}
