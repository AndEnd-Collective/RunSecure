package main

import (
	"context"
	"errors"
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
	t.Setenv("RUNSECURE_KUBE_DNS_CIDR", "10.96.0.10/32")
	t.Setenv("RUNSECURE_KUBE_API_SERVER_CIDR", "10.96.0.1/32")
	t.Setenv("RUNSECURE_KUBE_API_SERVER_PORT", "443")
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
		{name: "RUNSECURE_KUBE_DNS_CIDR", value: ""},
		{name: "RUNSECURE_KUBE_DNS_CIDR", value: "10.96.0.10/24"},
		{name: "RUNSECURE_KUBE_API_SERVER_CIDR", value: "not-a-cidr"},
		{name: "RUNSECURE_KUBE_API_SERVER_CIDR", value: "10.96.0.0/24"},
		{name: "RUNSECURE_KUBE_API_SERVER_PORT", value: "0"},
		{name: "RUNSECURE_KUBE_API_SERVER_PORT", value: "65536"},
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
