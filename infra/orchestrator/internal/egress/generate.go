// Package egress generates per-spawn squid.conf, haproxy.cfg, and dnsmasq.conf
// files. This is the Go port of the existing infra/scripts/generate-egress-conf.sh
// — the shell script is preserved for `run.sh` and `bootstrap-self-runner.sh`;
// the orchestrator does NOT shell out to it because the distroless orchestrator
// image has no shell.
//
// Output: a directory containing the three config files. Caller mounts it
// read-only into the per-spawn proxy containers.
package egress

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// Generator renders configs for a spawn.
type Generator interface {
	Render(spawnID string, r *runneryml.Runner, policy security.Policy) (configDir string, err error)
}

// FSGenerator writes to a target directory on disk.
type FSGenerator struct {
	BaseDir string // root dir under which per-spawn dirs are created
}

func NewFSGenerator(baseDir string) *FSGenerator {
	return &FSGenerator{BaseDir: baseDir}
}

// Render creates baseDir/<spawnID>/{squid.conf,haproxy.cfg,dnsmasq.conf}.
func (g *FSGenerator) Render(spawnID string, r *runneryml.Runner, policy security.Policy) (string, error) {
	dir := filepath.Join(g.BaseDir, spawnID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("egress: mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "squid.conf"), RenderSquid(r, policy), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "haproxy.cfg"), RenderHAProxy(r, policy), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "dnsmasq.conf"), RenderDNSMasq(r, policy), 0o644); err != nil {
		return "", err
	}
	return dir, nil
}
