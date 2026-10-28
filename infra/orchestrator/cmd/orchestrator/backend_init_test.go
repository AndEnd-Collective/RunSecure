package main

import (
	"context"
	"errors"
	"fmt"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"k8s.io/client-go/kubernetes/fake"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/stretchr/testify/require"
)

func setValidKubeImages(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"RUNSECURE_PROXY_IMAGE",
		"RUNSECURE_RUNNER_IMAGE_DEFAULT",
		"RUNSECURE_RUNNER_IMAGE_NODE",
		"RUNSECURE_RUNNER_IMAGE_PYTHON",
		"RUNSECURE_RUNNER_IMAGE_RUST",
	} {
		t.Setenv(name, "registry.example/runsecure/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	t.Setenv("RUNSECURE_KUBE_DNS_NAMESPACE", "kube-system")
	t.Setenv("RUNSECURE_KUBE_DNS_POD_LABEL_KEY", "k8s-app")
	t.Setenv("RUNSECURE_KUBE_DNS_POD_LABEL_VALUE", "kube-dns")
	t.Setenv("RUNSECURE_KUBE_DNS_SERVICE_CIDRS", "10.96.0.10/32")
	t.Setenv("RUNSECURE_KUBE_API_SERVER_PEERS", `[{"cidr":"10.96.0.1/32","port":443},{"cidr":"172.18.0.2/32","port":6443}]`)
}

func TestInitializeBackendKubeNeverConstructsDocker(t *testing.T) {
	setValidKubeImages(t)
	be := &startupFakeBackend{name: "kube"}
	dockerCalled := false
	dockerCtor := func(string) (docker.Client, error) {
		dockerCalled = true
		return nil, errors.New("Docker must not be constructed")
	}
	s := &config.Scope{Backend: "kube", Name: "portable"}

	got, dc, err := initializeBackend(
		context.Background(), s, []string{"owner/repo"},
		&fakeColdStartGitHub{}, dockerCtor,
		func() (backend.Backend, error) { return be, nil },
	)

	require.NoError(t, err)
	require.Same(t, be, got)
	require.Nil(t, dc)
	require.False(t, dockerCalled)
}

func TestInitializeBackendKubeFailsBeforeConstructionOnMutableImage(t *testing.T) {
	setValidKubeImages(t)
	t.Setenv("RUNSECURE_RUNNER_IMAGE_PYTHON", "registry.example/python:latest")
	kubeCalled := false
	dockerCalled := false
	s := &config.Scope{Backend: "kube", Name: "portable"}

	_, _, err := initializeBackend(
		context.Background(), s, []string{"owner/repo"},
		&fakeColdStartGitHub{},
		func(string) (docker.Client, error) {
			dockerCalled = true
			return nil, nil
		},
		func() (backend.Backend, error) {
			kubeCalled = true
			return &startupFakeBackend{name: "kube"}, nil
		},
	)

	require.ErrorContains(t, err, "RUNSECURE_RUNNER_IMAGE_PYTHON")
	require.False(t, dockerCalled)
	require.False(t, kubeCalled)
}

func TestValidateImmutableImageRef(t *testing.T) {
	valid := "registry.example:5000/path/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	require.NoError(t, validateImmutableImageRef("IMAGE", valid))
	for _, value := range []string{
		"", "image:latest", "@sha256:" + valid,
		"image@sha256:abcd",
		"image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
	} {
		require.Error(t, validateImmutableImageRef("IMAGE", value), value)
	}
}

func TestValidateKubeEnvironmentRejectsNetworkDependencies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "RUNSECURE_KUBE_DNS_NAMESPACE", value: ""},
		{name: "RUNSECURE_KUBE_DNS_NAMESPACE", value: "KUBE_SYSTEM"},
		{name: "RUNSECURE_KUBE_DNS_POD_LABEL_KEY", value: "bad key"},
		{name: "RUNSECURE_KUBE_DNS_POD_LABEL_VALUE", value: ""},
		{name: "RUNSECURE_KUBE_DNS_POD_LABEL_VALUE", value: "invalid value"},
		{name: "RUNSECURE_KUBE_DNS_SERVICE_CIDRS", value: ""},
		{name: "RUNSECURE_KUBE_DNS_SERVICE_CIDRS", value: "10.96.0.0/24"},
		{name: "RUNSECURE_KUBE_DNS_SERVICE_CIDRS", value: "10.96.0.10/32,10.96.0.10/32"},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: "not-json"},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: "[]"},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: `[{"cidr":"10.96.0.0/24","port":443}]`},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: `[{"cidr":"10.96.0.1/32","port":0}]`},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: `[{"cidr":"10.96.0.1/32","port":443},{"cidr":"10.96.0.1/32","port":443}]`},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: `[{"cidr":"10.96.0.1/32","port":443,"extra":true}]`},
		{name: "RUNSECURE_KUBE_API_SERVER_PEERS", value: `[{"cidr":"10.96.0.1/32","port":443}] {}`},
	} {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			setValidKubeImages(t)
			t.Setenv(tc.name, tc.value)
			require.Error(t, validateKubeEnvironment())
		})
	}
}

type fakeNetworkCleaner struct {
	networks []docker.Network
	listErr  error
	deleteAt string
	deleted  []string
}

func (f *fakeNetworkCleaner) ListNetworksForScope(context.Context, string) ([]docker.Network, error) {
	return f.networks, f.listErr
}

func (f *fakeNetworkCleaner) DeleteNetwork(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	if id == f.deleteAt {
		return errors.New("delete denied")
	}
	return nil
}

func TestCleanupRecoveredComposeNetworksSortedAndFailClosed(t *testing.T) {
	f := &fakeNetworkCleaner{networks: []docker.Network{{ID: "b"}, {ID: "a"}}}
	require.NoError(t, cleanupRecoveredComposeNetworks(context.Background(), "scope", f))
	require.Equal(t, []string{"a", "b"}, f.deleted)

	f = &fakeNetworkCleaner{listErr: errors.New("socket denied")}
	require.ErrorContains(t, cleanupRecoveredComposeNetworks(context.Background(), "scope", f), "list recovered")
	require.Empty(t, f.deleted)

	f = &fakeNetworkCleaner{networks: []docker.Network{{ID: ""}}}
	require.ErrorContains(t, cleanupRecoveredComposeNetworks(context.Background(), "scope", f), "empty ID")
	require.Empty(t, f.deleted)

	f = &fakeNetworkCleaner{networks: []docker.Network{{ID: "a"}}, deleteAt: "a"}
	require.ErrorContains(t, cleanupRecoveredComposeNetworks(context.Background(), "scope", f), "delete recovered")
}

func TestSelectBackendComposeRejectsNilDocker(t *testing.T) {
	_, err := selectBackend(&config.Scope{Backend: "compose"}, nil, func() (backend.Backend, error) {
		return nil, errors.New("must not be called")
	})
	require.ErrorContains(t, err, "requires a Docker client")
}

func approvedStartupScope(t *testing.T) *config.Scope {
	t.Helper()
	pat := filepath.Join(t.TempDir(), "pat")
	require.NoError(t, os.WriteFile(pat, []byte("fixture"), 0o440))
	return &config.Scope{APIVersion: config.SupportedAPIVersion, Name: "shared", Backend: "kube", GlobalMaxRunners: 2, PollIntervalSeconds: 5, SecurityProfile: "strict", Auth: config.AuthBlock{Type: "pat", PATFile: pat}, OrchEgress: config.OrchEgressBlock{AllowDomains: []string{"api.github.com"}}, AllowProjectOverrides: []string{"allow_wildcards"}, Repos: []config.RepoBlock{{Repo: "acme/alpha", Namespace: "project-alpha", MaxConcurrent: 1, RunnerConfig: &runneryml.Runner{Runtime: "node:24", Labels: []string{"self-hosted", "Linux", "X64", "container"}, Resources: runneryml.Resources{Memory: "1g", CPUs: 1, PIDs: 256}}}}}
}

func TestInitializeSharedBackendRejectsInvalidPolicyBeforeExternalMutations(t *testing.T) {
	cases := []struct {
		name     string
		override any
		ports    []string
		http     []string
		want     string
	}{
		{name: "forbidden private HTTP literal", http: []string{"10.1.2.3"}, want: "literal IP"},
		{name: "forbidden metadata TCP literal", ports: []string{"169.254.169.254:5432"}, want: "literal IP"},
		{name: "malformed allowed override", override: 123, want: "security"},
		{name: "zero TCP port", ports: []string{"db.example.com:0"}, want: "tcp_egress"},
		{name: "overflow TCP port", ports: []string{"db.example.com:65536"}, want: "tcp_egress"},
		{name: "reserved alias", ports: []string{"db.example.com:00443"}, want: "tcp_egress"},
		{name: "duplicate alias", ports: []string{"a:5432", "b:05432"}, want: "tcp_egress"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidKubeImages(t)
			s := approvedStartupScope(t)
			s.Repos[0].RunnerConfig.TCPEgress = tc.ports
			s.Repos[0].RunnerConfig.HTTPEgress = tc.http
			if tc.override != nil {
				s.Repos[0].RunnerConfig.Orchestrator.SecurityOverrides = map[string]any{"allow_wildcards": tc.override}
			}
			cs := fake.NewSimpleClientset()
			gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{"acme/alpha": {ownedRecoveredRunner(42, "rs-recovered-runner", "shared")}}}
			constructorCalls := 0
			_, _, err := initializeBackend(context.Background(), s, []string{"acme/alpha"}, gh, func(string) (docker.Client, error) { t.Fatal("Docker initialized"); return nil, nil }, func() (backend.Backend, error) {
				constructorCalls++
				return backendkube.NewForProjects(kube.NewClient(cs), s.Name, s.ProjectNamespaces())
			})
			require.ErrorContains(t, err, tc.want)
			require.Zero(t, constructorCalls, "reject approved policy before backend construction")
			require.Empty(t, cs.Actions(), "no Kubernetes API operation")
			require.Empty(t, gh.listedRepos, "no GitHub recovery API operation")
			require.Empty(t, gh.deletedIDs, "no GitHub mutation")
		})
	}
}

func TestInitializeSharedBackendAcceptsValidEffectivePolicyAndTCP(t *testing.T) {
	setValidKubeImages(t)
	s := approvedStartupScope(t)
	s.SecurityOverrides = map[string]any{"allow_imds": false, "allow_private_cidrs": []any{"10.0.0.0/8"}}
	s.Repos[0].RunnerConfig.Orchestrator.SecurityOverrides = map[string]any{"allow_wildcards": []any{"*.example.org"}, "allow_kube_api": "unpermitted and ignored"}
	s.Repos[0].RunnerConfig.TCPEgress = []string{"db.example.com:5432", "cache.example.com:65535", "10.1.2.3:6379"}
	s.Repos[0].RunnerConfig.HTTPEgress = []string{"10.2.3.4"}
	cs := fake.NewSimpleClientset()
	gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{"acme/alpha": {ownedRecoveredRunner(42, "rs-recovered-runner", "shared")}}}
	_, _, err := initializeBackend(context.Background(), s, []string{"acme/alpha"}, gh, nil, func() (backend.Backend, error) {
		return backendkube.NewForProjects(kube.NewClient(cs), s.Name, s.ProjectNamespaces())
	})
	require.NoError(t, err)
	require.NotEmpty(t, cs.Actions())
	require.Equal(t, []int64{42}, gh.deletedIDs, "valid policy permits normal recovery")
}

func TestInitializeSharedBackendRevalidatesNormalizedSelectorBoundary(t *testing.T) {
	for _, explicitMandatory := range []bool{false, true} {
		for _, customCount := range []int{14, 15} {
			t.Run(fmt.Sprintf("custom-%d-explicit-%t", customCount, explicitMandatory), func(t *testing.T) {
				setValidKubeImages(t)
				s := approvedStartupScope(t)
				selectors := map[string]string{}
				for i := 0; i < customCount; i++ {
					selectors[fmt.Sprintf("custom-%d", i)] = "ci"
				}
				if explicitMandatory {
					selectors["kubernetes.io/arch"] = "amd64"
					selectors["kubernetes.io/os"] = "linux"
				}
				s.Repos[0].Kubernetes.NodeSelector = selectors
				firstValidation := s.Validate()
				cs := fake.NewSimpleClientset()
				gh := &fakeColdStartGitHub{}
				constructorCalls := 0
				initialize := func() error {
					_, _, err := initializeBackend(context.Background(), s, []string{"acme/alpha"}, gh, nil, func() (backend.Backend, error) {
						constructorCalls++
						return backendkube.NewForProjects(kube.NewClient(cs), s.Name, s.ProjectNamespaces())
					})
					return err
				}
				if customCount > 14 {
					require.ErrorContains(t, firstValidation, "placement exceeds 16")
					require.ErrorContains(t, initialize(), "placement exceeds 16")
					require.Zero(t, constructorCalls)
					require.Empty(t, cs.Actions())
					require.Empty(t, gh.listedRepos)
					require.Empty(t, gh.deletedIDs)
					return
				}
				require.NoError(t, firstValidation)
				require.Len(t, selectors, 16)
				require.NoError(t, initialize(), "production initializes a previously validated boundary scope")
				require.Equal(t, 1, constructorCalls)
				require.NotEmpty(t, cs.Actions())
				require.Equal(t, []string{"acme/alpha"}, gh.listedRepos)
			})
		}
	}
}
