// Package runneryml parses the project's .github/runner.yml. Unknown fields
// are tolerated so additions in other consumers don't break us; missing
// fields under `orchestrator:` get defaults.
package runneryml

import (
	"fmt"
	"os"
	"regexp"
	"strings"

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
	HTTPEgress   []string          `yaml:"http_egress"`
	TCPEgress    []string          `yaml:"tcp_egress"`
	DNS          DNSConfig         `yaml:"dns"`
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

type DNSConfig struct {
	Host          *bool    `yaml:"host"`
	Servers       []string `yaml:"servers"`
	HostsFile     string   `yaml:"hosts_file"`
	WhitelistFile string   `yaml:"whitelist_file"`
	LogQueries    *bool    `yaml:"log_queries"`
}

type OrchestratorBlock struct {
	TimeoutSeconds    int            `yaml:"timeout_seconds"`
	SecurityOverrides map[string]any `yaml:"security_overrides"`
	SeccompProfile    string         `yaml:"seccomp_profile"`
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

// ResolvedHTTPEgress returns HTTPEgress if non-empty, otherwise falls back to
// the deprecated Egress.AllowDomains for backward compatibility.
func (r *Runner) ResolvedHTTPEgress() []string {
	if len(r.HTTPEgress) > 0 {
		return r.HTTPEgress
	}
	return r.Egress.AllowDomains
}

// DeprecationWarnings returns a slice of human-readable deprecation messages
// for any deprecated fields that are in use. The slice is empty when no
// deprecated fields are active. The orchestrator emits each entry to stderr
// via fmt.Fprintln after every Parse call.
//
// Current deprecations:
//   - egress.allow_domains → http_egress (deprecated since 2.0.0; honored as
//     an alias for one release cycle).
func (r *Runner) DeprecationWarnings() []string {
	if len(r.Egress.AllowDomains) > 0 && len(r.HTTPEgress) == 0 {
		return []string{
			"runner.yml: egress.allow_domains is deprecated; rename the key to http_egress. " +
				"Backward-compatibility alias will be removed in the next major release.",
		}
	}
	return nil
}

var (
	reHostPort = regexp.MustCompile(`^[a-zA-Z0-9.-]+:[0-9]{1,5}$`)
	reDomain   = regexp.MustCompile(`^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
)

// ValidateEgress checks tcp_egress and http_egress for validity:
// - TCP entries must be host:port format with no duplicated ports
// - Ports 80 and 443 are reserved for HTTP(S)
// - HTTP domain format must be valid (no injection characters)
func (r *Runner) ValidateEgress() error {
	seen := map[string]bool{}
	for _, e := range r.TCPEgress {
		if !reHostPort.MatchString(e) {
			return fmt.Errorf("invalid tcp_egress entry %q (want host:port, no metacharacters)", e)
		}
		port := e[strings.LastIndex(e, ":")+1:]
		if port == "80" || port == "443" {
			return fmt.Errorf("tcp_egress port %s reserved; use http_egress", port)
		}
		if seen[port] {
			return fmt.Errorf("tcp_egress port %s duplicated (one backend per port)", port)
		}
		seen[port] = true
	}
	for _, d := range r.ResolvedHTTPEgress() {
		if !reDomain.MatchString(d) {
			return fmt.Errorf("invalid http_egress domain %q", d)
		}
	}
	return nil
}
