package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		JITConfigB64: "b64", EgressConfigDir: "/tmp/x",
	})
	require.NoError(t, err)
	require.Len(t, ids, 4)
	require.Contains(t, ids, "runner")
	require.Contains(t, ids, "squid")
	require.Contains(t, ids, "haproxy")
	require.Contains(t, ids, "dnsmasq")
	require.Equal(t, 4, len(createdNames))
	require.Equal(t, 4, len(started))
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
	require.GreaterOrEqual(t, atomic.LoadInt64(&deleteCount), int64(3), "must roll back the 3 proxy containers")
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
	require.GreaterOrEqual(t, atomic.LoadInt64(&deleteCount), int64(4), "all 4 containers must be torn down on start failure")
}
