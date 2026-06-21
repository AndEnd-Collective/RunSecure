package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeClient is an in-process fake that records CreateContainerRequest per
// role (keyed by the runsecure.role label), so tests can inspect exactly what
// was sent to Docker without spinning up an HTTP server.
type fakeClient struct {
	mu      sync.Mutex
	created map[string]CreateContainerRequest // role → request
	started []string                          // IDs in start order
}

func newFakeClient() *fakeClient {
	return &fakeClient{created: map[string]CreateContainerRequest{}}
}

func (f *fakeClient) CreateContainer(_ context.Context, r CreateContainerRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := r.Labels["runsecure.role"]
	f.created[role] = r
	return "id-" + role, nil
}

func (f *fakeClient) StartContainer(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, id)
	return nil
}

func (f *fakeClient) InspectContainer(_ context.Context, id string) (Inspect, error) {
	return Inspect{ID: id, State: "exited", ExitCode: 0}, nil
}

func (f *fakeClient) DeleteContainer(_ context.Context, _ string, _ bool) error { return nil }

func (f *fakeClient) CreateNetwork(_ context.Context, r CreateNetworkRequest) (string, error) {
	return "net-" + r.Name, nil
}

func (f *fakeClient) DeleteNetwork(_ context.Context, _ string) error { return nil }

func (f *fakeClient) ListContainersForScope(_ context.Context, _ string) ([]Container, error) {
	return nil, nil
}

// hasEnv reports whether kv (e.g. "HTTP_PROXY=http://proxy:3128") is present
// in the env slice.
func hasEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// TestSpawn_ProxyDualHomed_RunnerInternalOnly verifies the two-container
// design: proxy is dual-homed (internal + egress), runner is internal only.
// SECURITY: runner must never be attached to the egress network.
func TestSpawn_ProxyDualHomed_RunnerInternalOnly(t *testing.T) {
	fc := newFakeClient()
	_, err := Spawn(context.Background(), fc, SpawnInputs{
		SpawnID: "s1", NetworkID: "net-int", EgressNetwork: "spawn-egress",
		RunnerImage: "r@sha256:x", ProxyImage: "p@sha256:y", EnableDNSMasq: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := fc.created["proxy"]
	if proxy.NetworkingConfig == nil {
		t.Fatal("proxy must have NetworkingConfig")
	}
	if _, ok := proxy.NetworkingConfig.EndpointsConfig["spawn-egress"]; !ok {
		t.Fatal("proxy not attached to spawn-egress")
	}
	if !hasEnv(proxy.Env, "ENABLE_HAPROXY=true") {
		t.Fatal("ENABLE_HAPROXY not set")
	}
	if !hasEnv(proxy.Env, "ENABLE_DNSMASQ=true") {
		t.Fatal("ENABLE_DNSMASQ not set when EnableDNSMasq=true")
	}
	runner := fc.created["runner"]
	if runner.NetworkingConfig == nil {
		t.Fatal("runner must have NetworkingConfig")
	}
	if _, ok := runner.NetworkingConfig.EndpointsConfig["spawn-egress"]; ok {
		t.Fatal("SECURITY: runner attached to spawn-egress")
	}
	if !hasEnv(runner.Env, "HTTP_PROXY=http://proxy:3128") {
		t.Fatal("runner HTTP_PROXY not set")
	}
	if !hasEnv(runner.Env, "HTTPS_PROXY=http://proxy:3128") {
		t.Fatal("runner HTTPS_PROXY not set")
	}
	if !hasEnv(runner.Env, "NO_PROXY=localhost") {
		t.Fatal("runner NO_PROXY not set")
	}
	// Start order: proxy must come before runner.
	if len(fc.started) < 2 || fc.started[0] != "id-proxy" {
		t.Fatalf("proxy must start before runner; start order: %v", fc.started)
	}
}

// TestSpawn_ProxyGetsEgressVolumeRO_RunnerDoesNot verifies the egress-config
// delivery design: the proxy mounts the shared named egress volume read-only
// and reads its per-spawn config files from a spawn-scoped subdirectory; the
// runner gets NO volume mount whatsoever.
// SECURITY: the runner must never mount the egress volume.
func TestSpawn_ProxyGetsEgressVolumeRO_RunnerDoesNot(t *testing.T) {
	fc := newFakeClient()
	_, err := Spawn(context.Background(), fc, SpawnInputs{
		SpawnID: "s1", NetworkID: "net-int", EgressNetwork: "spawn-egress",
		EgressVolume: "myscope-egress-configs", EgressMountPath: "/var/run/runsecure/egress",
		RunnerImage: "r@sha256:x", ProxyImage: "p@sha256:y", EnableDNSMasq: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := fc.created["proxy"]
	wantBind := "myscope-egress-configs:/var/run/runsecure/egress:ro"
	foundBind := false
	for _, b := range proxy.HostConfig.Binds {
		if b == wantBind {
			foundBind = true
		}
	}
	if !foundBind {
		t.Fatalf("proxy Binds must contain %q, got %v", wantBind, proxy.HostConfig.Binds)
	}
	for _, kv := range []string{
		"SQUID_CFG=/var/run/runsecure/egress/s1/squid.conf",
		"HAPROXY_CFG=/var/run/runsecure/egress/s1/haproxy.cfg",
		"DNSMASQ_CFG=/var/run/runsecure/egress/s1/dnsmasq.conf",
	} {
		if !hasEnv(proxy.Env, kv) {
			t.Fatalf("proxy env must contain %q, got %v", kv, proxy.Env)
		}
	}
	runner := fc.created["runner"]
	if len(runner.HostConfig.Binds) != 0 {
		t.Fatalf("SECURITY: runner must have no Binds, got %v", runner.HostConfig.Binds)
	}
}

func TestSpawn_HappyPath(t *testing.T) {
	createdNames := []string{}
	started := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			createdNames = append(createdNames, r.URL.Query().Get("name"))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "id-" + r.URL.Query().Get("name")})
		case strings.HasSuffix(r.URL.Path, "/start"):
			started = append(started, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1.44/containers/"), "/start"))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	ids, err := Spawn(context.Background(), c, SpawnInputs{
		Scope: "s", Repo: "o/r", SpawnID: "x1",
		NetworkID: "net-id", RunnerImage: "img-r@sha256:rr", ProxyImage: "img-p@sha256:pp",
		ResourcesMemory: 1 << 30, ResourcesNanoCPUs: 2_000_000_000, ResourcesPIDs: 2048,
		JITConfigB64: "b64", EgressVolume: "vol", EgressMountPath: "/mnt/e",
	})
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.Contains(t, ids, "runner")
	require.Contains(t, ids, "proxy")
	require.Equal(t, 2, len(createdNames))
	require.Equal(t, 2, len(started))
}

func TestSpawn_PolicyDeniedOnRunner_RollsBack(t *testing.T) {
	var deleteCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			name := r.URL.Query().Get("name")
			if strings.Contains(name, "runner") {
				// Simulate socket-proxy 403 on the runner.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":"validation_failed"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "id-" + name})
		case http.MethodDelete:
			atomic.AddInt64(&deleteCount, 1)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)

	_, err := Spawn(context.Background(), c, SpawnInputs{
		SpawnID: "x", NetworkID: "n", RunnerImage: "r", ProxyImage: "p",
	})
	require.Error(t, err)
	require.GreaterOrEqual(t, atomic.LoadInt64(&deleteCount), int64(1), "must roll back the proxy container")
}

// Bug #4 regression: SeccompProfilePath must end up in the runner
// container's HostConfig.SecurityOpt as `seccomp=<path>`.
func TestSpawn_SeccompProfile_AppliedToRunner(t *testing.T) {
	var runnerBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/containers/create") {
			name := r.URL.Query().Get("name")
			if strings.Contains(name, "runner") {
				_ = json.NewDecoder(r.Body).Decode(&runnerBody)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "id-" + name})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/start") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)

	_, err := Spawn(context.Background(), c, SpawnInputs{
		SpawnID:            "x",
		NetworkID:          "n",
		RunnerImage:        "r@sha256:r",
		ProxyImage:         "p@sha256:p",
		SeccompProfilePath: "/host/seccomp/node-runner.json",
	})
	require.NoError(t, err)
	require.NotNil(t, runnerBody, "runner create body captured")
	hc := runnerBody["HostConfig"].(map[string]any)
	secopts := hc["SecurityOpt"].([]any)

	foundSeccomp := false
	for _, s := range secopts {
		if str, ok := s.(string); ok && str == "seccomp=/host/seccomp/node-runner.json" {
			foundSeccomp = true
		}
	}
	require.True(t, foundSeccomp, "SecurityOpt must include seccomp=<path>: %v", secopts)
}

// Cover docker.Spawn's proxy create-error rollback.
func TestSpawn_ProxyCreateFails_RollsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			name := r.URL.Query().Get("name")
			if strings.Contains(name, "proxy") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":"x"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "id-" + name})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	_, err := Spawn(context.Background(), c, SpawnInputs{
		SpawnID: "x", NetworkID: "n", RunnerImage: "r@sha256:r", ProxyImage: "p@sha256:p",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "create proxy")
}

// TestSpawn_ProxyTmpfsHasNoexecNosuid verifies that every tmpfs mount on the
// proxy container carries noexec and nosuid. Without these flags a process
// running as the proxy user could drop and execute a binary from /tmp or
// exploit a setuid binary that happened to land on the mount, undermining the
// cap_drop:ALL + no-new-privileges hardening.
// nodev is also required: device nodes are never needed in runtime dirs and
// creating one would otherwise allow bypassing block/char device access rules.
func TestSpawn_ProxyTmpfsHasNoexecNosuid(t *testing.T) {
	fc := newFakeClient()
	_, err := Spawn(context.Background(), fc, SpawnInputs{
		SpawnID: "s1", NetworkID: "net-int", EgressNetwork: "spawn-egress",
		RunnerImage: "r@sha256:x", ProxyImage: "p@sha256:y",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := fc.created["proxy"]
	if len(proxy.HostConfig.Tmpfs) == 0 {
		t.Fatal("proxy must have tmpfs mounts")
	}
	required := []string{"noexec", "nosuid", "nodev"}
	for path, opts := range proxy.HostConfig.Tmpfs {
		for _, flag := range required {
			if !strings.Contains(opts, flag) {
				t.Errorf("proxy tmpfs %s: missing %s (opts=%q)", path, flag, opts)
			}
		}
	}
}

func TestSpawn_StartFails_RollsBack(t *testing.T) {
	var deleteCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "id-" + r.URL.Query().Get("name")})
		case strings.HasSuffix(r.URL.Path, "/start"):
			// Fail on the runner's start.
			if strings.Contains(r.URL.Path, "runner") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			atomic.AddInt64(&deleteCount, 1)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)

	_, err := Spawn(context.Background(), c, SpawnInputs{
		SpawnID: "x", NetworkID: "n", RunnerImage: "r@sha256:r", ProxyImage: "p@sha256:p",
	})
	require.Error(t, err)
	require.GreaterOrEqual(t, atomic.LoadInt64(&deleteCount), int64(2), "both containers must be torn down on start failure")
}
