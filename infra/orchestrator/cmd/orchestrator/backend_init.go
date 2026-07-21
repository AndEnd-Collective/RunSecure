package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

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
	if err := validateKubeAPIServerPeers(
		os.Getenv("RUNSECURE_KUBE_API_SERVER_PEERS"),
	); err != nil {
		return err
	}
	if err := validateKubeCIDRs(
		"RUNSECURE_KUBE_DNS_SERVICE_CIDRS",
		os.Getenv("RUNSECURE_KUBE_DNS_SERVICE_CIDRS"),
	); err != nil {
		return err
	}
	if errs := kubevalidation.IsDNS1123Label(os.Getenv("RUNSECURE_KUBE_DNS_NAMESPACE")); len(errs) != 0 {
		return errors.New("kube backend: RUNSECURE_KUBE_DNS_NAMESPACE must be a DNS-1123 label")
	}
	if errs := kubevalidation.IsQualifiedName(os.Getenv("RUNSECURE_KUBE_DNS_POD_LABEL_KEY")); len(errs) != 0 {
		return errors.New("kube backend: RUNSECURE_KUBE_DNS_POD_LABEL_KEY must be a Kubernetes label key")
	}
	dnsLabelValue := os.Getenv("RUNSECURE_KUBE_DNS_POD_LABEL_VALUE")
	if dnsLabelValue == "" {
		return errors.New("kube backend: RUNSECURE_KUBE_DNS_POD_LABEL_VALUE must not be empty")
	}
	if errs := kubevalidation.IsValidLabelValue(dnsLabelValue); len(errs) != 0 {
		return errors.New("kube backend: RUNSECURE_KUBE_DNS_POD_LABEL_VALUE must be a Kubernetes label value")
	}
	return nil
}

type kubeAPIServerPeer struct {
	CIDR string `json:"cidr"`
	Port int    `json:"port"`
}

func validateKubeAPIServerPeers(value string) error {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var peers []kubeAPIServerPeer
	if err := decoder.Decode(&peers); err != nil {
		return fmt.Errorf("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS must be a JSON array of exact cidr/port pairs: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return err
	}
	seen := make(map[kubeAPIServerPeer]struct{}, len(peers))
	for _, peer := range peers {
		prefix, err := netip.ParsePrefix(peer.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix != prefix.Masked() {
			return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS must contain exact IPv4 /32 CIDRs")
		}
		if peer.Port < 1 || peer.Port > 65535 {
			return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS ports must be from 1 to 65535")
		}
		canonical := kubeAPIServerPeer{CIDR: prefix.String(), Port: peer.Port}
		if _, ok := seen[canonical]; ok {
			return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS must contain unique pairs")
		}
		seen[canonical] = struct{}{}
	}
	if len(peers) == 0 {
		return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS must contain at least one pair")
	}
	return nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("kube backend: RUNSECURE_KUBE_API_SERVER_PEERS must contain exactly one JSON value")
	}
	return nil
}

func validateKubeCIDRs(name, value string) error {
	values := strings.Split(value, ",")
	if value == "" {
		values = nil
	}
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, cidr := range values {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix != prefix.Masked() {
			return fmt.Errorf("kube backend: %s must contain only exact IPv4 /32 values", name)
		}
		if _, ok := seen[prefix]; ok {
			return fmt.Errorf("kube backend: %s must contain unique CIDRs", name)
		}
		seen[prefix] = struct{}{}
	}
	if len(values) == 0 {
		return fmt.Errorf("kube backend: %s must contain at least one exact IPv4 /32", name)
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
