// Package runneryml parses the project's .github/runner.yml. Unknown fields
// are tolerated so additions in other consumers don't break us; missing
// fields under `orchestrator:` get defaults.
package runneryml

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultTimeoutSeconds is A2's default wall-clock cap (6 hours).
const DefaultTimeoutSeconds = 21600

type Runner struct {
	Runtime      string            `yaml:"runtime"`
	Labels       []string          `yaml:"labels"`
	Version      string            `yaml:"version"`
	Resources    Resources         `yaml:"resources"`
	Egress       Egress            `yaml:"egress"`
	Orchestrator OrchestratorBlock `yaml:"orchestrator"`
}

type Resources struct {
	Memory string `yaml:"memory"`
	CPUs   int    `yaml:"cpus"`
	PIDs   int    `yaml:"pids"`
}

type Egress struct {
	AllowDomains []string `yaml:"allow_domains"`
}

type OrchestratorBlock struct {
	TimeoutSeconds    int               `yaml:"timeout_seconds"`
	SecurityOverrides SecurityOverrides `yaml:"security_overrides"`
	SeccompProfile    string            `yaml:"seccomp_profile"`
}

type SecurityOverrides struct {
	AllowWildcards []string `yaml:"allow_wildcards"`
	AllowDoH       any      `yaml:"allow_doh"` // bool or []string
	AllowIMDS      bool     `yaml:"allow_imds"`
	AllowKubeAPI   bool     `yaml:"allow_kube_api"`
}

func Parse(path string) (*Runner, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runneryml: read %s: %w", path, err)
	}
	var r Runner
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("runneryml: parse %s: %w", path, err)
	}
	if r.Orchestrator.TimeoutSeconds <= 0 {
		r.Orchestrator.TimeoutSeconds = DefaultTimeoutSeconds
	}
	return &r, nil
}
