// Package docker wraps the Docker Engine API via the socket-proxy.
// All requests go through DOCKER_HOST (tcp://socket-proxy:2375); the
// orchestrator never touches /var/run/docker.sock directly.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPolicyDenied is returned when the socket-proxy refuses a request
// (HTTP 403 with a JSON deny body).
var ErrPolicyDenied = errors.New("docker: socket-proxy policy denied")

// Client speaks the Docker Engine API through the socket-proxy.
type Client interface {
	CreateContainer(ctx context.Context, req CreateContainerRequest) (id string, err error)
	StartContainer(ctx context.Context, id string) error
	InspectContainer(ctx context.Context, id string) (Inspect, error)
	DeleteContainer(ctx context.Context, id string, force bool) error
	CreateNetwork(ctx context.Context, req CreateNetworkRequest) (id string, err error)
	DeleteNetwork(ctx context.Context, id string) error
	ListContainersForScope(ctx context.Context, scope string) ([]Container, error)
}

type CreateContainerRequest struct {
	Name              string              `json:"-"`
	Image             string              `json:"Image"`
	User              string              `json:"User"`
	Env               []string            `json:"Env,omitempty"`
	Cmd               []string            `json:"Cmd,omitempty"`
	Labels            map[string]string   `json:"Labels,omitempty"`
	HostConfig        HostConfig          `json:"HostConfig"`
	NetworkingConfig  *NetworkingConfig   `json:"NetworkingConfig,omitempty"`
}

type NetworkingConfig struct {
	EndpointsConfig map[string]EndpointConfig `json:"EndpointsConfig"`
}

type EndpointConfig struct {
	Aliases []string `json:"Aliases,omitempty"`
}

type HostConfig struct {
	CapDrop      []string          `json:"CapDrop"`
	SecurityOpt  []string          `json:"SecurityOpt"`
	NetworkMode  string            `json:"NetworkMode"`
	Memory       int64             `json:"Memory,omitempty"`
	NanoCPUs     int64             `json:"NanoCpus,omitempty"`
	PidsLimit    int64             `json:"PidsLimit,omitempty"`
	ReadonlyRootfs bool            `json:"ReadonlyRootfs,omitempty"`
	Tmpfs        map[string]string `json:"Tmpfs,omitempty"`
	Binds        []string          `json:"Binds,omitempty"`
	AutoRemove   bool              `json:"AutoRemove,omitempty"`
}

type CreateNetworkRequest struct {
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
}

type Inspect struct {
	ID       string
	State    string // "running", "exited", ...
	ExitCode int
}

type Container struct {
	ID     string
	Name   string
	Labels map[string]string
}

// NewClient constructs a Client. dockerHost is a TCP URL such as
// "tcp://socket-proxy:2375". A trailing slash, scheme, or path is OK.
func NewClient(dockerHost string) (Client, error) {
	if dockerHost == "" {
		return nil, errors.New("docker: DOCKER_HOST is required")
	}
	base, err := normalizeHost(dockerHost)
	if err != nil {
		return nil, err
	}
	return &httpClient{
		base: base,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func normalizeHost(dh string) (string, error) {
	// Accept tcp://host:port or http://host:port forms.
	if strings.HasPrefix(dh, "tcp://") {
		dh = "http://" + dh[len("tcp://"):]
	}
	u, err := url.Parse(dh)
	if err != nil {
		return "", fmt.Errorf("docker: parse DOCKER_HOST: %w", err)
	}
	if u.Scheme == "" {
		return "", errors.New("docker: DOCKER_HOST must include a scheme")
	}
	// Docker Engine 25.0+ (Jan 2024) requires API ≥ v1.44; older clients
	// get HTTP 400 with "client version X is too old". v1.44 is the floor
	// across all currently-supported daemons.
	u.Path = "/v1.44"
	return u.String(), nil
}

type httpClient struct {
	base string
	hc   *http.Client
}

func (c *httpClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", ErrPolicyDenied, string(body))
	}
	return resp, nil
}

type createResp struct {
	ID string `json:"Id"`
}

func (c *httpClient) CreateContainer(ctx context.Context, r CreateContainerRequest) (string, error) {
	path := "/containers/create"
	if r.Name != "" {
		path += "?name=" + url.QueryEscape(r.Name)
	}
	resp, err := c.do(ctx, http.MethodPost, path, r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("docker: containers/create: status %d: %s", resp.StatusCode, string(b))
	}
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", err
	}
	return cr.ID, nil
}

func (c *httpClient) StartContainer(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: start %s: status %d: %s", id, resp.StatusCode, string(b))
	}
	return nil
}

type inspectResp struct {
	ID    string `json:"Id"`
	State struct {
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
}

func (c *httpClient) InspectContainer(ctx context.Context, id string) (Inspect, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return Inspect{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return Inspect{}, fmt.Errorf("docker: inspect %s: status %d", id, resp.StatusCode)
	}
	var ir inspectResp
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return Inspect{}, err
	}
	return Inspect{ID: ir.ID, State: ir.State.Status, ExitCode: ir.State.ExitCode}, nil
}

func (c *httpClient) DeleteContainer(ctx context.Context, id string, force bool) error {
	path := "/containers/" + id
	if force {
		path += "?force=true"
	}
	resp, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("docker: delete %s: status %d", id, resp.StatusCode)
	}
	return nil
}

type netCreateResp struct {
	ID string `json:"Id"`
}

func (c *httpClient) CreateNetwork(ctx context.Context, r CreateNetworkRequest) (string, error) {
	resp, err := c.do(ctx, http.MethodPost, "/networks/create", r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("docker: networks/create: status %d: %s", resp.StatusCode, string(b))
	}
	var nr netCreateResp
	if err := json.NewDecoder(resp.Body).Decode(&nr); err != nil {
		return "", err
	}
	return nr.ID, nil
}

func (c *httpClient) DeleteNetwork(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/networks/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("docker: delete network %s: status %d", id, resp.StatusCode)
	}
	return nil
}

type containerJSON struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

func (c *httpClient) ListContainersForScope(ctx context.Context, scope string) ([]Container, error) {
	// Only return RUNNING containers — exited ones are stale and would
	// inflate the cold-start in-flight count. Status filtering server-side
	// avoids returning hundreds of stopped containers from prior runs.
	filter := fmt.Sprintf(`{"label":["runsecure.scope=%s"],"status":["running"]}`, scope)
	path := "/containers/json?filters=" + url.QueryEscape(filter)
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("docker: containers/json: status %d", resp.StatusCode)
	}
	var arr []containerJSON
	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(arr))
	for _, cj := range arr {
		name := ""
		if len(cj.Names) > 0 {
			name = strings.TrimPrefix(cj.Names[0], "/")
		}
		out = append(out, Container{ID: cj.ID, Name: name, Labels: cj.Labels})
	}
	return out, nil
}
