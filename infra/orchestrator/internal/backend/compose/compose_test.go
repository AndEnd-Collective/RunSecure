package compose

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
)

// ---------------------------------------------------------------------------
// Fake docker.Client
// ---------------------------------------------------------------------------

type fakeDocker struct {
	mu sync.Mutex

	// CreateContainer behaviour: if errOnRole is set and the container's
	// runsecure.role label matches, CreateContainer returns that error.
	errOnRole string
	errCreate error

	// Created containers: role → request (keyed by runsecure.role label).
	created map[string]docker.CreateContainerRequest
	started []string

	// Network state.
	networkID       string
	networksDeleted []string

	// DeleteContainer records.
	containersDeleted []string

	// InspectContainer behaviour: first call returns inspectFirst, subsequent
	// calls return inspectRest. If inspectErr is set every call returns it.
	inspectFirst docker.Inspect
	inspectRest  docker.Inspect
	inspectErr   error
	inspectCalls int

	// ListContainersForScope results.
	listResult []docker.Container
	listErr    error
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{
		created:   map[string]docker.CreateContainerRequest{},
		networkID: "net-fake-id",
	}
}

func (f *fakeDocker) CreateNetwork(_ context.Context, r docker.CreateNetworkRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.networkID, nil
}

func (f *fakeDocker) DeleteNetwork(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networksDeleted = append(f.networksDeleted, id)
	return nil
}

func (f *fakeDocker) CreateContainer(_ context.Context, r docker.CreateContainerRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := r.Labels["runsecure.role"]
	if f.errOnRole != "" && role == f.errOnRole {
		if f.errCreate != nil {
			return "", f.errCreate
		}
		return "", errors.New("fake: forced create error")
	}
	f.created[role] = r
	return "cid-" + role, nil
}

func (f *fakeDocker) StartContainer(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, id)
	return nil
}

func (f *fakeDocker) InspectContainer(_ context.Context, id string) (docker.Inspect, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inspectErr != nil {
		return docker.Inspect{}, f.inspectErr
	}
	f.inspectCalls++
	if f.inspectCalls == 1 {
		return f.inspectFirst, nil
	}
	return f.inspectRest, nil
}

func (f *fakeDocker) DeleteContainer(_ context.Context, id string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containersDeleted = append(f.containersDeleted, id)
	return nil
}

func (f *fakeDocker) ListContainersForScope(_ context.Context, _ string) ([]docker.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listResult, f.listErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func minimalInput() backend.SpawnInput {
	return backend.SpawnInput{
		Scope:         "myscope",
		Repo:          "owner/repo",
		SpawnID:       "sp1",
		RunnerImage:   "runner@sha256:r",
		ProxyImage:    "proxy@sha256:p",
		EgressNetwork: "myscope-spawn-egress",
		EgressVolume:  "myscope-egress-configs",
	}
}

// ---------------------------------------------------------------------------
// Spawn tests
// ---------------------------------------------------------------------------

// TestSpawn_HappyPath verifies that a successful spawn returns a Handle with
// "runner", "proxy", and "network" keys in Refs, and that the backend label
// is "compose".
func TestSpawn_HappyPath(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)

	h, err := b.Spawn(context.Background(), minimalInput())
	if err != nil {
		t.Fatalf("Spawn returned unexpected error: %v", err)
	}

	if h.Backend != "compose" {
		t.Errorf("Handle.Backend = %q, want %q", h.Backend, "compose")
	}
	if h.SpawnID != "sp1" {
		t.Errorf("Handle.SpawnID = %q, want %q", h.SpawnID, "sp1")
	}
	if _, ok := h.Refs["runner"]; !ok {
		t.Error("Handle.Refs must contain 'runner'")
	}
	if _, ok := h.Refs["proxy"]; !ok {
		t.Error("Handle.Refs must contain 'proxy'")
	}
	if _, ok := h.Refs["network"]; !ok {
		t.Error("Handle.Refs must contain 'network'")
	}
	if h.Refs["network"] != fd.networkID {
		t.Errorf("Handle.Refs['network'] = %q, want %q", h.Refs["network"], fd.networkID)
	}
}

// TestSpawn_RunnerIsInternalOnly verifies the core security property:
// the runner container is NEVER attached to the egress network.
func TestSpawn_RunnerIsInternalOnly(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)

	_, err := b.Spawn(context.Background(), minimalInput())
	if err != nil {
		t.Fatalf("Spawn returned error: %v", err)
	}

	runner, ok := fd.created["runner"]
	if !ok {
		t.Fatal("runner container was not created")
	}
	if runner.NetworkingConfig == nil {
		t.Fatal("runner NetworkingConfig is nil")
	}
	if _, attached := runner.NetworkingConfig.EndpointsConfig["myscope-spawn-egress"]; attached {
		t.Fatal("SECURITY: runner must not be attached to the egress network")
	}
}

// TestSpawn_ProxyIsDualHomed verifies that the proxy container is attached to
// both the internal network and the egress network.
func TestSpawn_ProxyIsDualHomed(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)

	_, err := b.Spawn(context.Background(), minimalInput())
	if err != nil {
		t.Fatalf("Spawn returned error: %v", err)
	}

	proxy, ok := fd.created["proxy"]
	if !ok {
		t.Fatal("proxy container was not created")
	}
	if proxy.NetworkingConfig == nil {
		t.Fatal("proxy NetworkingConfig is nil")
	}
	if _, attached := proxy.NetworkingConfig.EndpointsConfig["myscope-spawn-egress"]; !attached {
		t.Fatal("proxy must be attached to the egress network")
	}
}

// TestSpawn_RollsBackNetworkOnSpawnError verifies that when docker.Spawn
// fails (simulated by failing to create the runner container), the network is
// deleted before returning the error.
func TestSpawn_RollsBackNetworkOnSpawnError(t *testing.T) {
	fd := newFakeDocker()
	fd.errOnRole = "runner"

	b := New(fd)
	_, err := b.Spawn(context.Background(), minimalInput())
	if err == nil {
		t.Fatal("expected Spawn to return an error when runner create fails")
	}

	fd.mu.Lock()
	deleted := fd.networksDeleted
	fd.mu.Unlock()

	found := false
	for _, id := range deleted {
		if id == fd.networkID {
			found = true
		}
	}
	if !found {
		t.Errorf("network %q was not deleted after spawn failure; deleted: %v", fd.networkID, deleted)
	}
}

// TestSpawn_RollsBackNetworkOnNetworkCreateError is a sanity check: if
// CreateNetwork itself fails, we return an error and do not attempt to spawn
// containers.
func TestSpawn_NetworkCreateFail(t *testing.T) {
	fd := newFakeDocker()
	// Override CreateNetwork to return an error.
	fd2 := &failNetworkDocker{inner: fd}
	b := New(fd2)
	_, err := b.Spawn(context.Background(), minimalInput())
	if err == nil {
		t.Fatal("expected Spawn to return an error when CreateNetwork fails")
	}
	// No containers should have been created.
	fd.mu.Lock()
	numCreated := len(fd.created)
	fd.mu.Unlock()
	if numCreated != 0 {
		t.Errorf("no containers should be created when network creation fails, got %d", numCreated)
	}
}

// failNetworkDocker wraps fakeDocker but always fails CreateNetwork.
type failNetworkDocker struct{ inner *fakeDocker }

func (f *failNetworkDocker) CreateNetwork(_ context.Context, _ docker.CreateNetworkRequest) (string, error) {
	return "", errors.New("fake: network create failed")
}
func (f *failNetworkDocker) DeleteNetwork(ctx context.Context, id string) error {
	return f.inner.DeleteNetwork(ctx, id)
}
func (f *failNetworkDocker) CreateContainer(ctx context.Context, r docker.CreateContainerRequest) (string, error) {
	return f.inner.CreateContainer(ctx, r)
}
func (f *failNetworkDocker) StartContainer(ctx context.Context, id string) error {
	return f.inner.StartContainer(ctx, id)
}
func (f *failNetworkDocker) InspectContainer(ctx context.Context, id string) (docker.Inspect, error) {
	return f.inner.InspectContainer(ctx, id)
}
func (f *failNetworkDocker) DeleteContainer(ctx context.Context, id string, force bool) error {
	return f.inner.DeleteContainer(ctx, id, force)
}
func (f *failNetworkDocker) ListContainersForScope(ctx context.Context, scope string) ([]docker.Container, error) {
	return f.inner.ListContainersForScope(ctx, scope)
}

// ---------------------------------------------------------------------------
// WaitForExit tests
// ---------------------------------------------------------------------------

// TestWaitForExit_AlreadyExited verifies that when the runner has already
// exited before WaitForExit is called, it returns immediately with the correct
// exit code (no timeout).
func TestWaitForExit_AlreadyExited(t *testing.T) {
	fd := newFakeDocker()
	fd.inspectFirst = docker.Inspect{State: "exited", ExitCode: 42}

	b := New(fd)
	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs:    map[string]string{"runner": "cid-runner", "network": "net-id"},
	}

	code, timedOut := b.WaitForExit(context.Background(), h, 5*time.Second)
	if timedOut {
		t.Error("expected timedOut=false when runner already exited")
	}
	if code != 42 {
		t.Errorf("exitCode = %d, want 42", code)
	}
}

// TestWaitForExit_TimesOut verifies that when the runner never exits,
// WaitForExit returns timedOut=true after the timeout elapses.
func TestWaitForExit_TimesOut(t *testing.T) {
	fd := newFakeDocker()
	// InspectContainer always returns "running" (never exits).
	fd.inspectFirst = docker.Inspect{State: "running", ExitCode: 0}
	fd.inspectRest = docker.Inspect{State: "running", ExitCode: 0}

	b := New(fd)
	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs:    map[string]string{"runner": "cid-runner", "network": "net-id"},
	}

	_, timedOut := b.WaitForExit(context.Background(), h, 10*time.Millisecond)
	if !timedOut {
		t.Error("expected timedOut=true when runner never exits within timeout")
	}
}

// TestWaitForExit_ExitsAfterOnePoll verifies that WaitForExit returns the exit
// code when the runner transitions to "exited" on the second inspect call.
func TestWaitForExit_ExitsAfterOnePoll(t *testing.T) {
	fd := newFakeDocker()
	fd.inspectFirst = docker.Inspect{State: "running", ExitCode: 0}
	fd.inspectRest = docker.Inspect{State: "exited", ExitCode: 0}

	b := New(fd)
	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs:    map[string]string{"runner": "cid-runner", "network": "net-id"},
	}

	code, timedOut := b.WaitForExit(context.Background(), h, 5*time.Second)
	if timedOut {
		t.Error("expected timedOut=false")
	}
	if code != 0 {
		t.Errorf("exitCode = %d, want 0", code)
	}
}

// TestWaitForExit_ContextCancelled verifies that cancelling the context causes
// WaitForExit to return without timing out.
func TestWaitForExit_ContextCancelled(t *testing.T) {
	fd := newFakeDocker()
	// Always returns running.
	fd.inspectFirst = docker.Inspect{State: "running"}
	fd.inspectRest = docker.Inspect{State: "running"}

	b := New(fd)
	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs:    map[string]string{"runner": "cid-runner", "network": "net-id"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately after calling WaitForExit in a goroutine.
	done := make(chan struct {
		code     int
		timedOut bool
	}, 1)
	go func() {
		code, timedOut := b.WaitForExit(ctx, h, 30*time.Second)
		done <- struct {
			code     int
			timedOut bool
		}{code, timedOut}
	}()
	cancel()
	result := <-done
	if result.timedOut {
		t.Error("expected timedOut=false on context cancellation")
	}
}

// ---------------------------------------------------------------------------
// Teardown tests
// ---------------------------------------------------------------------------

// TestTeardown_DeletesContainersAndNetwork verifies that Teardown deletes
// every container in Refs (except the "network" key) and deletes the network.
func TestTeardown_DeletesContainersAndNetwork(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)

	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs: map[string]string{
			"runner":  "cid-runner",
			"proxy":   "cid-proxy",
			"network": "net-id",
		},
	}

	if err := b.Teardown(context.Background(), h, true); err != nil {
		t.Fatalf("Teardown returned unexpected error: %v", err)
	}

	fd.mu.Lock()
	deleted := fd.containersDeleted
	deletedNets := fd.networksDeleted
	fd.mu.Unlock()

	wantContainers := map[string]bool{"cid-runner": true, "cid-proxy": true}
	for _, id := range deleted {
		delete(wantContainers, id)
	}
	if len(wantContainers) > 0 {
		t.Errorf("these containers were not deleted: %v; deleted: %v", wantContainers, deleted)
	}

	foundNet := false
	for _, id := range deletedNets {
		if id == "net-id" {
			foundNet = true
		}
	}
	if !foundNet {
		t.Errorf("network 'net-id' was not deleted; networks deleted: %v", deletedNets)
	}
}

// TestTeardown_NetworkKeyNotTreatedAsContainer verifies that the "network"
// entry in Refs is not passed to DeleteContainer.
func TestTeardown_NetworkKeyNotTreatedAsContainer(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)

	h := backend.Handle{
		SpawnID: "sp1",
		Backend: "compose",
		Refs: map[string]string{
			"runner":  "cid-runner",
			"network": "net-id",
		},
	}

	if err := b.Teardown(context.Background(), h, false); err != nil {
		t.Fatalf("Teardown returned error: %v", err)
	}

	fd.mu.Lock()
	deleted := fd.containersDeleted
	fd.mu.Unlock()

	for _, id := range deleted {
		if id == "net-id" {
			t.Errorf("DeleteContainer was called with network ID 'net-id'")
		}
	}
}

// ---------------------------------------------------------------------------
// Reconcile tests
// ---------------------------------------------------------------------------

// TestReconcile_GroupsBySpawnID verifies that containers with the same
// runsecure.spawn_id are grouped into a single Handle.
func TestReconcile_GroupsBySpawnID(t *testing.T) {
	fd := newFakeDocker()
	fd.listResult = []docker.Container{
		{ID: "cid-proxy1", Labels: map[string]string{
			"runsecure.scope":    "myscope",
			"runsecure.repo":     "owner/repo",
			"runsecure.spawn_id": "sp1",
			"runsecure.role":     "proxy",
		}},
		{ID: "cid-runner1", Labels: map[string]string{
			"runsecure.scope":    "myscope",
			"runsecure.repo":     "owner/repo",
			"runsecure.spawn_id": "sp1",
			"runsecure.role":     "runner",
		}},
		{ID: "cid-runner2", Labels: map[string]string{
			"runsecure.scope":    "myscope",
			"runsecure.repo":     "owner/repo",
			"runsecure.spawn_id": "sp2",
			"runsecure.role":     "runner",
		}},
	}

	b := New(fd)
	handles, err := b.Reconcile(context.Background(), "myscope")
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(handles) != 2 {
		t.Fatalf("expected 2 handles, got %d", len(handles))
	}

	bySpawn := map[string]backend.Handle{}
	for _, h := range handles {
		bySpawn[h.SpawnID] = h
	}

	h1, ok := bySpawn["sp1"]
	if !ok {
		t.Fatal("no handle for spawn sp1")
	}
	if h1.Refs["proxy"] != "cid-proxy1" {
		t.Errorf("sp1 proxy ref = %q, want %q", h1.Refs["proxy"], "cid-proxy1")
	}
	if h1.Refs["runner"] != "cid-runner1" {
		t.Errorf("sp1 runner ref = %q, want %q", h1.Refs["runner"], "cid-runner1")
	}
	if h1.Backend != "compose" {
		t.Errorf("handle backend = %q, want 'compose'", h1.Backend)
	}

	h2, ok := bySpawn["sp2"]
	if !ok {
		t.Fatal("no handle for spawn sp2")
	}
	if h2.Refs["runner"] != "cid-runner2" {
		t.Errorf("sp2 runner ref = %q, want %q", h2.Refs["runner"], "cid-runner2")
	}
}

// TestReconcile_SkipsContainersWithoutSpawnIDOrRole ensures containers
// missing required labels are not grouped into any handle.
func TestReconcile_SkipsContainersWithoutSpawnIDOrRole(t *testing.T) {
	fd := newFakeDocker()
	fd.listResult = []docker.Container{
		{ID: "cid-nolabels", Labels: map[string]string{}},
		{ID: "cid-norole", Labels: map[string]string{
			"runsecure.spawn_id": "sp1",
		}},
		{ID: "cid-nospawnid", Labels: map[string]string{
			"runsecure.role": "runner",
		}},
		// This one is valid.
		{ID: "cid-runner", Labels: map[string]string{
			"runsecure.spawn_id": "sp2",
			"runsecure.role":     "runner",
		}},
	}

	b := New(fd)
	handles, err := b.Reconcile(context.Background(), "myscope")
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if len(handles) != 1 {
		t.Fatalf("expected 1 handle, got %d: %+v", len(handles), handles)
	}
	if handles[0].SpawnID != "sp2" {
		t.Errorf("expected SpawnID=sp2, got %q", handles[0].SpawnID)
	}
}

// TestReconcile_EmptyScope returns an empty slice without error when there are
// no containers.
func TestReconcile_EmptyScope(t *testing.T) {
	fd := newFakeDocker()
	fd.listResult = nil

	b := New(fd)
	handles, err := b.Reconcile(context.Background(), "myscope")
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("expected 0 handles, got %d", len(handles))
	}
}

// TestReconcile_ListError propagates errors from ListContainersForScope.
func TestReconcile_ListError(t *testing.T) {
	fd := newFakeDocker()
	fd.listErr = errors.New("fake: list failed")

	b := New(fd)
	_, err := b.Reconcile(context.Background(), "myscope")
	if err == nil {
		t.Fatal("expected Reconcile to return an error when list fails")
	}
}

// ---------------------------------------------------------------------------
// Name test
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	fd := newFakeDocker()
	b := New(fd)
	if b.Name() != "compose" {
		t.Errorf("Name() = %q, want 'compose'", b.Name())
	}
}
