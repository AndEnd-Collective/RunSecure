package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/stretchr/testify/require"
)

// Mutation kill: proxy.go transportIdleConnTimeout — `60 * time.Second`.
// Exact-value assert covers the multiplication so the mutation lands in
// a tracked function body.
func TestTransportIdleConnTimeout(t *testing.T) {
	require.Equal(t, 60*time.Second, transportIdleConnTimeout())
}

// startFakeDockerd creates a Unix socket that serves canned 200 responses
// for any request. Returns the socket path.
//
// Note: macOS sockaddr_un.sun_path is 104 bytes. Test names in t.TempDir()
// paths can exceed this, so we use a short os.MkdirTemp pattern instead.
func startFakeDockerd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rs-d")
	require.NoError(t, err)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read upstream body: %v", err)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "path": r.URL.Path, "body": string(body)})
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close(); _ = os.RemoveAll(dir) })
	return sock
}

func setupServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dockerSock := startFakeDockerd(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	srv := httptest.NewServer(New(dockerSock, allow))
	t.Cleanup(srv.Close)
	return srv, dockerSock
}

func TestServer_AllowedRoute_PassesThroughToDockerd(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Get(srv.URL + "/v1.43/info")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), `"ok":true`)
}

func TestServer_DisallowedRoute_403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/containers/abc/exec", "application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	var denied denyBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&denied))
	require.Equal(t, "route_not_allowed", denied.Code)
}

func TestServer_ContainerCreate_PrivilegedRejected(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Image": "ghcr.io/test/runner@sha256:ff",
		"User":  "1001:0",
		"HostConfig": map[string]any{
			"Privileged":  true,
			"CapDrop":     []any{"ALL"},
			"SecurityOpt": []any{"no-new-privileges:true"},
		},
	})
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_NetworkCreate_NotInternalRejected(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{"Name": "x", "Driver": "bridge", "Internal": false})
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_ContainerCreate_HappyPath(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Image": "ghcr.io/test/runner@sha256:ff",
		"User":  "1001:0",
		"HostConfig": map[string]any{
			"CapDrop":     []any{"ALL"},
			"SecurityOpt": []any{"no-new-privileges:true"},
			"NetworkMode": "rs-net-test",
		},
	})
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_NetworkCreate_HappyPath(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Name":       "rs-net-test",
		"Driver":     "bridge",
		"Internal":   true,
		"Attachable": false,
		"Labels": map[string]string{
			"runsecure.scope":    "test",
			"runsecure.repo":     "owner/repo",
			"runsecure.spawn_id": "spawn-1",
		},
	})
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_SetLogger_Captures(t *testing.T) {
	logged := 0
	s := New("", nil)
	s.SetLogger(func(format string, args ...any) { logged++ })
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/disallowed", nil)
	s.ServeHTTP(rr, r)
	require.Equal(t, 1, logged)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestServer_ContainerCreate_MalformedBodyReturns403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader([]byte("{ not json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_NetworkCreate_MalformedBodyReturns403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader([]byte("not json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// errReader fails on first Read. Used to exercise the body-read-failed
// path of ServeHTTP via direct handler invocation (not over the wire —
// net/http aborts the request before the response is observable).
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, ioErrBoom{} }
func (errReader) Close() error               { return nil }

type ioErrBoom struct{}

func (ioErrBoom) Error() string { return "boom" }

func TestServer_ContainerCreate_BodyReadFails_400(t *testing.T) {
	dockerSock := startFakeDockerd(t)
	allow := loadAllowAllImagesForServer(t)
	s := New(dockerSock, allow)

	r := httptest.NewRequest(http.MethodPost, "/v1.43/containers/create", errReader{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestServer_NetworkCreate_BodyReadFails_400(t *testing.T) {
	dockerSock := startFakeDockerd(t)
	allow := loadAllowAllImagesForServer(t)
	s := New(dockerSock, allow)

	r := httptest.NewRequest(http.MethodPost, "/v1.43/networks/create", errReader{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

// loadAllowAllImagesForServer is a tiny helper to build a digest allowlist
// without going through setupServer (which also starts an httptest server).
func loadAllowAllImagesForServer(t *testing.T) *imageallow.Allowlist {
	t.Helper()
	dir, err := os.MkdirTemp("", "rs-a")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	return allow
}

func TestServer_UpstreamError_502(t *testing.T) {
	// Point at a nonexistent socket path so the reverse-proxy transport fails.
	allowDir, err := os.MkdirTemp("", "rs-a")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(allowDir) })
	path := filepath.Join(allowDir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	srv := httptest.NewServer(New("/nonexistent/sock", allow))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1.43/info")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// These requests must be rejected before they can reach the Docker socket.
func TestServer_ContainerCreate_StrictBoundary(t *testing.T) {
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "spawn-egress")
	t.Setenv("RUNSECURE_EGRESS_VOLUME", "scope-egress-configs")
	srv, _ := setupServer(t)
	base, err := json.Marshal(minimalValidBody())
	require.NoError(t, err)
	withField := func(key string, value any, host bool) string {
		body := minimalValidBody()
		if host {
			body["HostConfig"].(map[string]any)[key] = value
		} else {
			body[key] = value
		}
		encoded, marshalErr := json.Marshal(body)
		require.NoError(t, marshalErr)
		return string(encoded)
	}
	cases := map[string]string{
		"casefold host config":        strings.TrimSuffix(string(base), "}") + `,"hostconfig":{"Privileged":true}}`,
		"duplicate host config":       strings.TrimSuffix(string(base), "}") + `,"HostConfig":{"Privileged":true}}`,
		"nested casefold privileged":  strings.Replace(string(base), `"Privileged":false`, `"Privileged":false,"privileged":true`, 1),
		"nested duplicate capdrop":    strings.Replace(string(base), `"CapDrop":["ALL"]`, `"CapDrop":["ALL"],"CapDrop":[]`, 1),
		"escaped duplicate":           strings.TrimSuffix(string(base), "}") + `,"\u0055ser":"0:0"}`,
		"single lowercase field":      strings.Replace(string(base), `"Privileged":false`, `"privileged":true`, 1),
		"ambiguous labels":            withField("Labels", map[string]any{"runsecure.role": "proxy", "RUNSECURE.ROLE": "runner"}, false),
		"root uid":                    withField("User", "0:0", false),
		"root name":                   withField("User", "root", false),
		"leading zero root":           withField("User", "0000:1001", false),
		"unknown named identity":      withField("User", "runner", false),
		"signed identity":             withField("User", "+1001:0", false),
		"invalid identity":            withField("User", "1001:0:0", false),
		"host root":                   withField("Binds", []string{"/:/host:ro"}, true),
		"host traversal":              withField("Binds", []string{"/tmp/../:/host:ro"}, true),
		"host outside denylist":       withField("Binds", []string{"/opt/data:/data:ro"}, true),
		"mount object":                withField("Mounts", []any{map[string]any{"Type": "bind", "Source": "/", "Target": "/host"}}, true),
		"volumes from":                withField("VolumesFrom", []string{"other-container:ro"}, true),
		"device requests":             withField("DeviceRequests", []any{map[string]any{"Count": -1, "Capabilities": [][]string{{"gpu"}}}}, true),
		"device cgroup rules":         withField("DeviceCgroupRules", []string{"a *:* rwm"}, true),
		"alternate runtime":           withField("Runtime", "other", true),
		"rootfs mount":                withField("Volumes", map[string]any{"/host": map[string]any{}}, false),
		"unknown endpoint options":    withField("NetworkingConfig", map[string]any{"EndpointsConfig": map[string]any{"rs-net-test": map[string]any{"DriverOpts": map[string]string{"x": "y"}}}}, false),
		"container network namespace": withField("NetworkMode", "container:other", true),
		"container pid namespace":     withField("PidMode", "container:other", true),
		"shareable ipc":               withField("IpcMode", "shareable", true),
		"unsupported seccomp path":    withField("SecurityOpt", []string{"no-new-privileges:true", "seccomp=/etc/runsecure/seccomp.json"}, true),

		"permissive seccomp JSON":  withField("SecurityOpt", []string{"no-new-privileges:true", `seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`}, true),
		"unconfined apparmor":      withField("SecurityOpt", []string{"no-new-privileges:true", "apparmor=unconfined"}, true),
		"disabled labels":          withField("SecurityOpt", []string{"no-new-privileges:true", "label=disable"}, true),
		"ambiguous unicode labels": withField("Labels", map[string]string{"K": "a", "\u212a": "b"}, false),

		"unconfined security option":   withField("SecurityOpt", []string{"no-new-privileges:true", "seccomp=unconfined"}, true),
		"conflicting privilege option": withField("SecurityOpt", []string{"no-new-privileges:true", "no-new-privileges:false"}, true),
		"invalid binds type":           withField("Binds", []any{42}, true),
		"invalid privilege type":       withField("Privileged", "false", true),
		"unsafe tmpfs":                 withField("Tmpfs", map[string]string{"/tmp": "exec,suid,dev"}, true),
		"uid overflow":                 withField("User", "2147483648:0", false),
		"duplicate security option":    withField("SecurityOpt", []string{"no-new-privileges:true", "no-new-privileges:true"}, true),
		"duplicate tmpfs option":       withField("Tmpfs", map[string]string{"/tmp": "noexec,nosuid,nodev,size=1m,size=2m"}, true),
		"tmpfs flag assigned value":    withField("Tmpfs", map[string]string{"/tmp": "noexec,nosuid,nodev,noexec=true"}, true),
		"tmpfs flag with value":        withField("Tmpfs", map[string]string{"/tmp": "noexec,nosuid,nodev=1,nodev"}, true),
		"tmpfs missing size value":     withField("Tmpfs", map[string]string{"/tmp": "noexec,nosuid,nodev,size="}, true),
		"tmpfs unsupported option":     withField("Tmpfs", map[string]string{"/tmp": "noexec,nosuid,nodev,exec"}, true),
		"tmpfs invalid path":           withField("Tmpfs", map[string]string{"/tmp/../": "noexec,nosuid,nodev"}, true),
		"null endpoint":                withField("NetworkingConfig", map[string]any{"EndpointsConfig": map[string]any{"rs-net-test": nil}}, false),
		"non object root":              `[]`,
		"unfinished object":            `{"Image":`,
		"unfinished array":             `{"Env":[`,
		"unfinished nested object":     `{"Labels":{"key":"value"`,
		"unfinished nested array":      `{"Env":["value"`,
		"malformed object key":         `{"Labels":{1:2}}`,
		"invalid utf8":                 string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
		"deep nested arrays":           strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),

		"trailing json": string(base) + `{}`,
	}
	for _, bind := range []string{"scope-egress-configs:/mnt/e:ro,rw", "scope-egress-configs:/mnt/e:rprivate", "scope-egress-configs:/mnt/../e:ro", "scope-egress-configs:relative:ro", "scope-egress-configs:/:ro"} {
		body := minimalValidBody()
		body["Labels"] = map[string]string{"runsecure.role": "proxy"}
		body["HostConfig"].(map[string]any)["Binds"] = []string{bind}
		encoded, marshalErr := json.Marshal(body)
		require.NoError(t, marshalErr)
		cases["invalid volume "+bind] = string(encoded)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp, requestErr := http.Post(srv.URL+"/v1.43/containers/create", "application/json", strings.NewReader(body))
			require.NoError(t, requestErr)
			defer resp.Body.Close()
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
		})
	}
}

func TestServer_ContainerCreate_OrchestratorPayloads(t *testing.T) {
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "spawn-egress")
	t.Setenv("RUNSECURE_EGRESS_VOLUME", "scope-egress-configs")
	srv, _ := setupServer(t)
	for name, body := range map[string]string{
		"runner": `{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0","Env":["HTTP_PROXY=http://proxy:3128"],"Entrypoint":["/usr/local/bin/runner-entrypoint.sh"],"Labels":{"runsecure.role":"runner","runsecure.scope":"test","runsecure.repo":"owner/repo","runsecure.spawn_id":"x"},"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"NetworkMode":"rs-net-test","Memory":1073741824,"NanoCpus":1000000000,"PidsLimit":256,"Tmpfs":{"/tmp":"noexec,nosuid,nodev,size=512m"}},"NetworkingConfig":{"EndpointsConfig":{"rs-net-test":{}}}}`,
		"proxy":  `{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0","Env":["SQUID_CFG=/mnt/e/x/squid.conf"],"Labels":{"runsecure.role":"proxy"},"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"NetworkMode":"rs-net-test","ReadonlyRootfs":true,"Binds":["scope-egress-configs:/mnt/e:ro"],"Tmpfs":{"/var/run/squid":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750","/var/log/squid":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750","/var/spool/squid":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750","/var/lib/haproxy":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750","/run":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750","/tmp":"noexec,nosuid,nodev,uid=1001,gid=1001,mode=750"}},"NetworkingConfig":{"EndpointsConfig":{"rs-net-test":{"Aliases":["proxy"]},"spawn-egress":{}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Post(srv.URL+"/containers/create", "application/json", strings.NewReader(body))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var forwarded struct{ Body string }
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&forwarded))
			require.Equal(t, body, forwarded.Body)
		})
	}
}

func TestServer_NetworkCreate_StrictBoundary(t *testing.T) {
	srv, _ := setupServer(t)
	base := `{"Name":"rs-net-test","Driver":"bridge","Internal":true,"Attachable":false,"Labels":{"runsecure.scope":"test","runsecure.repo":"owner/repo","runsecure.spawn_id":"x"}}`
	for name, body := range map[string]string{
		"duplicate internal":      strings.TrimSuffix(base, "}") + `,"internal":false}`,
		"unknown options":         strings.TrimSuffix(base, "}") + `,"Options":{"com.docker.network.bridge.name":"host-bridge"}}`,
		"single lowercase driver": strings.Replace(base, `"Driver":"bridge"`, `"Driver":"bridge","driver":"host"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Post(srv.URL+"/networks/create", "application/json", strings.NewReader(body))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
		})
	}
}

// Opt in with a local Docker socket and an already available manifest-pinned
// image. Containers are only created and inspected, never started. Cleanup is
// registered as soon as each test-owned resource exists.
func TestServer_DockerDecoderBoundary(t *testing.T) {
	socket := os.Getenv("RUNSECURE_DOCKER_TEST_SOCKET")
	image := os.Getenv("RUNSECURE_DOCKER_TEST_IMAGE")
	if socket == "" || image == "" {
		t.Skip("requires explicit Docker socket and manifest-pinned test image")
	}
	require.Contains(t, image, "@sha256:")
	suffix := time.Now().Format("20060102150405.000000000")
	network := "rs-boundary-" + suffix
	volume := "rs-boundary-volume-" + suffix
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "")
	t.Setenv("RUNSECURE_EGRESS_VOLUME", volume)
	allowPath := filepath.Join(t.TempDir(), "allow.txt")
	require.NoError(t, os.WriteFile(allowPath, []byte(image+"\n"), 0o600))
	allow, err := imageallow.Load(allowPath)
	require.NoError(t, err)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	direct := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	call := func(t *testing.T, client *http.Client, method, url string, body any, want int) []byte {
		t.Helper()
		var data []byte
		if body != nil {
			var err error
			data, err = json.Marshal(body)
			require.NoError(t, err)
		}
		request, err := http.NewRequest(method, url, bytes.NewReader(data))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		result, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, want, response.StatusCode, string(result))
		return result
	}
	server := httptest.NewServer(New(socket, allow))
	defer server.Close()
	labels := map[string]string{"runsecure.scope": "socket-boundary-test", "runsecure.repo": "test/test", "runsecure.spawn_id": suffix}
	networkBody := map[string]any{"Name": network, "Driver": "bridge", "Internal": true, "Attachable": false, "Labels": labels}
	networkResult := call(t, server.Client(), http.MethodPost, server.URL+"/networks/create", networkBody, http.StatusCreated)
	var createdNetwork struct{ ID string }
	require.NoError(t, json.Unmarshal(networkResult, &createdNetwork))
	t.Cleanup(func() {
		call(t, direct, http.MethodDelete, "http://docker/networks/"+createdNetwork.ID, nil, http.StatusNoContent)
	})
	call(t, direct, http.MethodPost, "http://docker/volumes/create", map[string]any{"Name": volume, "Labels": labels}, http.StatusCreated)
	t.Cleanup(func() { call(t, direct, http.MethodDelete, "http://docker/volumes/"+volume, nil, http.StatusNoContent) })
	for _, role := range []string{"runner", "proxy"} {
		t.Run(role, func(t *testing.T) {
			body := minimalValidBody()
			body["Image"] = image
			body["Labels"] = map[string]string{"runsecure.role": role}
			hc := body["HostConfig"].(map[string]any)
			hc["NetworkMode"] = network
			hc["Tmpfs"] = map[string]string{"/tmp": "noexec,nosuid,nodev,size=512m"}
			hc["ReadonlyRootfs"] = role == "proxy"
			if role == "proxy" {
				hc["Binds"] = []string{volume + ":/mnt/e:ro"}
			}
			result := call(t, server.Client(), http.MethodPost, server.URL+"/containers/create", body, http.StatusCreated)
			var created struct{ ID string }
			require.NoError(t, json.Unmarshal(result, &created))
			defer call(t, direct, http.MethodDelete, "http://docker/containers/"+created.ID+"?force=true", nil, http.StatusNoContent)
			result = call(t, server.Client(), http.MethodGet, server.URL+"/containers/"+created.ID+"/json", nil, http.StatusOK)
			var effective struct {
				Config     struct{ User string }
				HostConfig hostConfig
				State      struct{ Running bool }
				Mounts     []struct {
					Type, Name, Destination string
					RW                      bool
				}
			}
			require.NoError(t, json.Unmarshal(result, &effective))
			require.Equal(t, "1001:0", effective.Config.User)
			require.False(t, effective.State.Running)
			require.False(t, effective.HostConfig.Privileged)
			require.Equal(t, []string{"ALL"}, effective.HostConfig.CapDrop)
			require.Equal(t, []string{"no-new-privileges:true"}, effective.HostConfig.SecurityOpt)
			require.Equal(t, network, effective.HostConfig.NetworkMode)
			require.Equal(t, role == "proxy", effective.HostConfig.ReadonlyRootfs)
			if role == "proxy" {
				require.Len(t, effective.Mounts, 1)
				require.Equal(t, "volume", effective.Mounts[0].Type)
				require.Equal(t, volume, effective.Mounts[0].Name)
				require.Equal(t, "/mnt/e", effective.Mounts[0].Destination)
				require.False(t, effective.Mounts[0].RW)
			} else {
				require.Empty(t, effective.Mounts)
			}
		})
	}
}

func TestServer_DockerCasefoldDifferential(t *testing.T) {
	socket := os.Getenv("RUNSECURE_DOCKER_TEST_SOCKET")
	image := os.Getenv("RUNSECURE_DOCKER_TEST_IMAGE")
	if socket == "" || image == "" {
		t.Skip("requires explicit Docker socket and manifest-pinned test image")
	}
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "")
	t.Setenv("RUNSECURE_EGRESS_VOLUME", "")
	allowPath := filepath.Join(t.TempDir(), "allow.txt")
	require.NoError(t, os.WriteFile(allowPath, []byte(image+"\n"), 0o600))
	allow, err := imageallow.Load(allowPath)
	require.NoError(t, err)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	direct := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	body := minimalValidBody()
	body["Image"] = image
	hc := body["HostConfig"].(map[string]any)
	hc["NetworkMode"] = ""
	hc["ReadonlyRootfs"] = true
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	// This toggles only a filesystem setting on a never-started non-root
	// container; no host mount, elevated privilege or namespace is requested.
	ambiguous := strings.TrimSuffix(string(encoded), "}") + `,"hostconfig":{"ReadonlyRootfs":false}}`
	response, err := direct.Post("http://docker/containers/create", "application/json", strings.NewReader(ambiguous))
	require.NoError(t, err)
	defer response.Body.Close()
	result, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, response.StatusCode, string(result))
	var created struct{ ID string }
	require.NoError(t, json.Unmarshal(result, &created))
	t.Cleanup(func() {
		request, err := http.NewRequest(http.MethodDelete, "http://docker/containers/"+created.ID+"?force=true", nil)
		require.NoError(t, err)
		response, err := direct.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusNoContent, response.StatusCode)
	})
	response, err = direct.Get("http://docker/containers/" + created.ID + "/json")
	require.NoError(t, err)
	defer response.Body.Close()
	var effective struct {
		HostConfig hostConfig
		Config     struct{ User string }
		State      struct{ Running bool }
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&effective))
	require.False(t, effective.HostConfig.ReadonlyRootfs, "the daemon merges the lowercase HostConfig alias")
	require.False(t, effective.State.Running)
	require.False(t, effective.HostConfig.Privileged)
	require.Equal(t, "1001:0", effective.Config.User)
	// The actual proxy rejects the same ambiguous representation before use.
	server := httptest.NewServer(New(socket, allow))
	defer server.Close()
	response, err = server.Client().Post(server.URL+"/containers/create", "application/json", strings.NewReader(ambiguous))
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusForbidden, response.StatusCode)
}
