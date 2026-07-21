package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
)

type dockerClientCtor func(string) (docker.Client, error)

// initializeBackend constructs and reconciles only the backend selected by the
// validated scope. Compose retains its Docker-specific recovered-container and
// network cleanup. Kubernetes uses the in-cluster API exclusively and cleans
// exact recovered runner registrations before deleting their owning Secrets.
func initializeBackend(
	ctx context.Context,
	s *config.Scope,
	repoNames []string,
	gh coldStartGitHub,
	dockerCtor dockerClientCtor,
	kubeCtor func() (backend.Backend, error),
) (backend.Backend, docker.Client, error) {
	switch s.Backend {
	case "kube":
		if err := validateKubeEnvironment(); err != nil {
			return nil, nil, err
		}
		be, err := selectBackend(s, nil, kubeCtor)
		if err != nil {
			return nil, nil, err
		}
		if err := cleanupRecoveredKubeSpawns(ctx, s.Name, repoNames, be, gh); err != nil {
			return nil, nil, err
		}
		return be, nil, nil
	case "compose", "":
		dc, err := dockerCtor(envOr("DOCKER_HOST", "tcp://socket-proxy:2375"))
		if err != nil {
			return nil, nil, err
		}
		be, err := selectBackend(s, dc, kubeCtor)
		if err != nil {
			return nil, nil, err
		}
		if err := cleanupRecoveredSpawns(ctx, s.Name, repoNames, dc, gh); err != nil {
			return nil, nil, err
		}
		if err := cleanupRecoveredComposeNetworks(ctx, s.Name, dc); err != nil {
			return nil, nil, err
		}
		return be, dc, nil
	default:
		return nil, nil, fmt.Errorf("unsupported backend %q", s.Backend)
	}
}

func validateKubeEnvironment() error {
	if err := validateKubeImageEnvironment(); err != nil {
		return err
	}
	for _, name := range []string{
		"RUNSECURE_KUBE_DNS_CIDR",
		"RUNSECURE_KUBE_API_SERVER_CIDR",
	} {
		if err := validateKubeCIDR(name, os.Getenv(name)); err != nil {
			return err
		}
	}
	port, err := strconv.Atoi(os.Getenv("RUNSECURE_KUBE_API_SERVER_PORT"))
	if err != nil || port < 1 || port > 65535 {
		return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PORT must be an integer from 1 to 65535")
	}
	return nil
}

func validateKubeCIDR(name, value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix != prefix.Masked() {
		return fmt.Errorf("kube backend: %s must be an exact IPv4 /32", name)
	}
	return nil
}

type recoveredNetworkCleaner interface {
	ListNetworksForScope(context.Context, string) ([]docker.Network, error)
	DeleteNetwork(context.Context, string) error
}

func cleanupRecoveredComposeNetworks(
	ctx context.Context,
	scope string,
	dc recoveredNetworkCleaner,
) error {
	nets, err := dc.ListNetworksForScope(ctx, scope)
	if err != nil {
		return fmt.Errorf("cold-start: list recovered networks: %w", err)
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].ID < nets[j].ID })
	for _, network := range nets {
		if network.ID == "" {
			return errors.New("cold-start: recovered network has empty ID")
		}
		if err := dc.DeleteNetwork(ctx, network.ID); err != nil {
			return fmt.Errorf("cold-start: delete recovered network %s: %w", network.ID, err)
		}
	}
	return nil
}

func validateKubeImageEnvironment() error {
	for _, name := range []string{
		"RUNSECURE_PROXY_IMAGE",
		"RUNSECURE_RUNNER_IMAGE_DEFAULT",
		"RUNSECURE_RUNNER_IMAGE_NODE",
		"RUNSECURE_RUNNER_IMAGE_PYTHON",
		"RUNSECURE_RUNNER_IMAGE_RUST",
	} {
		if err := validateImmutableImageRef(name, os.Getenv(name)); err != nil {
			return err
		}
	}
	return nil
}

func validateImmutableImageRef(name, value string) error {
	const marker = "@sha256:"
	pos := strings.LastIndex(value, marker)
	if pos <= 0 || pos+len(marker)+64 != len(value) ||
		strings.Contains(value[:pos], "@") || strings.ContainsAny(value[:pos], " \t\r\n") {
		return fmt.Errorf("kube backend: %s must be an immutable image@sha256 digest", name)
	}
	for _, char := range value[pos+len(marker):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return fmt.Errorf("kube backend: %s must be an immutable image@sha256 digest", name)
		}
	}
	return nil
}
