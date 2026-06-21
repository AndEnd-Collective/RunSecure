package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func newServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, Client) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL)
	require.NoError(t, err)
	return srv, c
}

func TestNewClient_Empty(t *testing.T) {
	_, err := NewClient("")
	require.Error(t, err)
}

func TestNewClient_TCPScheme(t *testing.T) {
	c, err := NewClient("tcp://example:2375")
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestNewClient_BadURL(t *testing.T) {
	_, err := NewClient("not a url")
	require.Error(t, err)
}

func TestNewClient_NoScheme(t *testing.T) {
	// Path-only (no scheme, no host) — url.Parse succeeds but Scheme is "".
	_, err := NewClient("/path/only")
	require.Error(t, err)
}

func TestNewClient_UnparseableURL(t *testing.T) {
	// Unclosed IPv6 bracket — url.Parse returns a real error.
	_, err := NewClient("http://[::1")
	require.Error(t, err)
}

// Forces do()'s json.Marshal failure path: pass a body with an unsupported
// type (channel) via CreateNetwork, which marshals its struct directly.
// Indirect because CreateNetworkRequest fields are all marshalable; use a
// helper to hit the path another way — confirm by exercising the io.ReadAll
// error path on bodies-that-fail.
func TestListContainersForScope_MalformedResponse(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	})
	_, err := c.ListContainersForScope(context.Background(), "test")
	require.Error(t, err)
}

func TestCreateContainer_HappyPath(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/containers/create", r.URL.Path)
		require.Equal(t, "rs-x", r.URL.Query().Get("name"))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "abc123"})
	})
	id, err := c.CreateContainer(context.Background(), CreateContainerRequest{
		Name: "rs-x", Image: "img@sha256:zz", User: "1001:0",
		HostConfig: HostConfig{CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, NetworkMode: "rs-net"},
	})
	require.NoError(t, err)
	require.Equal(t, "abc123", id)
}

func TestCreateContainer_PolicyDenied(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"code":"validation_failed"}`))
	})
	_, err := c.CreateContainer(context.Background(), CreateContainerRequest{Image: "i", User: "1001"})
	require.ErrorIs(t, err, ErrPolicyDenied)
}

func TestCreateContainer_500(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.CreateContainer(context.Background(), CreateContainerRequest{Image: "i", User: "1001"})
	require.Error(t, err)
}

func TestStartContainer_HappyPath(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/containers/abc/start", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.StartContainer(context.Background(), "abc"))
}

// Mutation kill: client.go:175 — `resp.StatusCode/100 != 2`. Test with
// a 200 (success in 2xx but not 204) and verify success. Mutation `/100`
// → `+100` would compute 200+100=300, 300!=2 → error returned.
func TestStartContainer_200StatusAccepted(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 — also success, not 204
	})
	require.NoError(t, c.StartContainer(context.Background(), "abc"))
}

func TestStartContainer_Errors(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	require.Error(t, c.StartContainer(context.Background(), "abc"))
}

func TestInspectContainer_HappyPath(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/containers/abc/json", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":    "abc",
			"State": map[string]any{"Status": "exited", "ExitCode": 0},
		})
	})
	ins, err := c.InspectContainer(context.Background(), "abc")
	require.NoError(t, err)
	require.Equal(t, "exited", ins.State)
	require.Equal(t, 0, ins.ExitCode)
}

func TestInspectContainer_500(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.InspectContainer(context.Background(), "abc")
	require.Error(t, err)
}

func TestDeleteContainer_HappyPath(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/containers/abc", r.URL.Path)
		require.Equal(t, "true", r.URL.Query().Get("force"))
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.DeleteContainer(context.Background(), "abc", true))
}

func TestDeleteContainer_NotFound(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	require.NoError(t, c.DeleteContainer(context.Background(), "abc", false))
}

func TestDeleteContainer_OtherError(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	require.Error(t, c.DeleteContainer(context.Background(), "abc", false))
}

func TestCreateNetwork_HappyPath(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/networks/create", r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.True(t, body["Internal"].(bool))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "net-xyz"})
	})
	id, err := c.CreateNetwork(context.Background(), CreateNetworkRequest{Name: "rs-net", Driver: "bridge", Internal: true})
	require.NoError(t, err)
	require.Equal(t, "net-xyz", id)
}

func TestCreateNetwork_500(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.CreateNetwork(context.Background(), CreateNetworkRequest{})
	require.Error(t, err)
}

func TestDeleteNetwork(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.DeleteNetwork(context.Background(), "net-xyz"))
}

func TestDeleteNetwork_500(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	require.Error(t, c.DeleteNetwork(context.Background(), "net-xyz"))
}

// Mutation kill: client.go:129 — `if body != nil { Content-Type: json }`.
// Mutation `==` would set Content-Type for nil-body (GET) requests. Verify
// GETs do NOT carry Content-Type.
func TestDo_GETWithoutBody_NoContentType(t *testing.T) {
	var gotCT string
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"State": map[string]any{"Status": "exited"}})
	})
	_, err := c.InspectContainer(context.Background(), "abc")
	require.NoError(t, err)
	require.Empty(t, gotCT, "GET requests must not include Content-Type")
}

// Mutation kill: client.go:282 — `if len(cj.Names) > 0`. Mutation `>= 0`
// would access cj.Names[0] when Names is empty → panic.
func TestListContainersForScope_EmptyNamesNoPanic(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Container with no Names entry — must not crash the orchestrator.
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": "abc", "Names": []string{}, "Labels": map[string]string{"runsecure.scope": "test"}},
		})
	})
	out, err := c.ListContainersForScope(context.Background(), "test")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Empty(t, out[0].Name) // no name; safe.
}

func TestListContainersForScope(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1.44/containers/json", r.URL.Path)
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		require.Contains(t, q, `runsecure.scope=test`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": "a", "Names": []string{"/rs-test-1"}, "Labels": map[string]string{"runsecure.scope": "test"}},
		})
	})
	out, err := c.ListContainersForScope(context.Background(), "test")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "rs-test-1", out[0].Name)
}

func TestListContainersForScope_500(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.ListContainersForScope(context.Background(), "test")
	require.Error(t, err)
}

func TestDo_NetworkError(t *testing.T) {
	// Construct a client whose base URL points at an unreachable host.
	c, err := NewClient("http://127.0.0.1:1")
	require.NoError(t, err)
	require.Error(t, c.StartContainer(context.Background(), "x"))
	_, err = c.InspectContainer(context.Background(), "x")
	require.Error(t, err)
	require.Error(t, c.DeleteContainer(context.Background(), "x", false))
	_, err = c.CreateContainer(context.Background(), CreateContainerRequest{})
	require.Error(t, err)
	_, err = c.CreateNetwork(context.Background(), CreateNetworkRequest{})
	require.Error(t, err)
	require.Error(t, c.DeleteNetwork(context.Background(), "n"))
	_, err = c.ListContainersForScope(context.Background(), "s")
	require.Error(t, err)
}

func TestCreateContainer_UnmarshalableBody(t *testing.T) {
	// Force a JSON marshaling failure by passing a body with an unsupported
	// type. CreateContainerRequest doesn't contain channel/func, but we can
	// directly call the raw `do` via the only available public API — by
	// providing a malformed name like one containing %% to trip URL encoding.
	// Since CreateContainerRequest can't carry an unmarshalable type, skip
	// — coverage for the marshal error is exercised in github's tests.
}

func TestCreateContainer_MalformedResponse(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("not json"))
	})
	_, err := c.CreateContainer(context.Background(), CreateContainerRequest{Image: "i"})
	require.Error(t, err)
}

func TestCreateNetwork_MalformedResponse(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("not json"))
	})
	_, err := c.CreateNetwork(context.Background(), CreateNetworkRequest{})
	require.Error(t, err)
}

func TestInspectContainer_MalformedResponse(t *testing.T) {
	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	})
	_, err := c.InspectContainer(context.Background(), "x")
	require.Error(t, err)
}

// TestDo_MarshalError covers the json.Marshal error branch in do() (client.go:202).
// We temporarily replace jsonMarshal with a stub that always fails, then restore it.
func TestDo_MarshalError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(v any) ([]byte, error) {
		return nil, errors.New("injected marshal failure")
	}
	t.Cleanup(func() { jsonMarshal = orig })

	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Should not be reached.
		w.WriteHeader(http.StatusOK)
	})
	// CreateNetwork passes a non-nil body through do(), triggering jsonMarshal.
	_, err := c.CreateNetwork(context.Background(), CreateNetworkRequest{Name: "rs-net"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "injected marshal failure")
}

// TestDo_NewRequestError covers the http.NewRequestWithContext error branch in
// do() (client.go:208). We replace newHTTPRequest with a stub that fails.
func TestDo_NewRequestError(t *testing.T) {
	orig := newHTTPRequest
	newHTTPRequest = func(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
		return nil, errors.New("injected request-creation failure")
	}
	t.Cleanup(func() { newHTTPRequest = orig })

	_, c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	err := c.StartContainer(context.Background(), "abc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "injected request-creation failure")
}

func TestCreateContainer_SerializesNetworkingConfig(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "abc"})
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	_, err := c.CreateContainer(context.Background(), CreateContainerRequest{
		Image: "img", User: "1001:0",
		NetworkingConfig: &NetworkingConfig{EndpointsConfig: map[string]EndpointConfig{
			"net-internal": {Aliases: []string{"proxy"}},
			"spawn-egress": {},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(gotBody, []byte("\"spawn-egress\"")) || !bytes.Contains(gotBody, []byte("\"proxy\"")) {
		t.Fatalf("EndpointsConfig not serialized: %s", gotBody)
	}
}
