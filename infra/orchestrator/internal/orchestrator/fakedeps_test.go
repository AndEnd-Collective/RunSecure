package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/clock"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

// ------------- fake github wired to a real httptest.Server ----------------

type fakeGitHubBackend struct {
	mu              sync.Mutex
	queuedFor       map[string]int
	queueErrCode    map[string]int // map repo → HTTP status to return
	jitOnRunnerID   int64
	jitLabels       []string
	jitMismatch     bool
	deletedRunners  map[int64]bool
	createCalled    int
	deleteCalled    int
	rlLimit         int
	rlRemaining     int
	rlReset         string
	rlAfterResponse bool // include X-RateLimit-Remaining=0 in 403 response
}

func newFakeGH() *fakeGitHubBackend {
	return &fakeGitHubBackend{
		queuedFor:      map[string]int{},
		queueErrCode:   map[string]int{},
		deletedRunners: map[int64]bool{},
		jitOnRunnerID:  100,
		rlLimit:        5000,
		rlRemaining:    4999,
	}
}

func (g *fakeGitHubBackend) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()

		w.Header().Set("X-RateLimit-Limit", fmt.Sprint(g.rlLimit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprint(g.rlRemaining))
		if g.rlReset != "" {
			w.Header().Set("X-RateLimit-Reset", g.rlReset)
		}

		// /repos/o/r/actions/runs?status=queued
		if strings.Contains(r.URL.Path, "/actions/runs") && r.Method == http.MethodGet {
			// Extract owner/repo
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) < 4 {
				w.WriteHeader(404)
				return
			}
			repo := parts[2] + "/" + parts[3]
			if code, ok := g.queueErrCode[repo]; ok {
				if g.rlAfterResponse {
					w.Header().Set("X-RateLimit-Remaining", "0")
				}
				w.WriteHeader(code)
				return
			}
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count": g.queuedFor[repo],
			})
			return
		}
		// /repos/o/r/actions/runners/generate-jitconfig
		if strings.HasSuffix(r.URL.Path, "/generate-jitconfig") && r.Method == http.MethodPost {
			g.createCalled++
			labels := []map[string]any{}
			labelSet := g.jitLabels
			if labelSet == nil {
				// Echo back what was requested unless explicitly told to mismatch.
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if reqLabels, ok := body["labels"].([]any); ok && !g.jitMismatch {
					for _, l := range reqLabels {
						labels = append(labels, map[string]any{"name": l})
					}
				}
				if g.jitMismatch {
					labels = []map[string]any{{"name": "bogus"}}
				}
			} else {
				for _, l := range labelSet {
					labels = append(labels, map[string]any{"name": l})
				}
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"runner": map[string]any{
					"id":     g.jitOnRunnerID,
					"labels": labels,
				},
				"encoded_jit_config": "b64-jit",
			})
			return
		}
		// DELETE /repos/o/r/actions/runners/<id>
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete {
			g.deleteCalled++
			parts := strings.Split(r.URL.Path, "/")
			if id := parts[len(parts)-1]; id != "" {
				var n int64
				fmt.Sscanf(id, "%d", &n)
				g.deletedRunners[n] = true
			}
			w.WriteHeader(204)
			return
		}
		// /repos/o/r (validation ping)
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})
	}
}

// ------------- fake docker -----------------------------------------------

type fakeDockerClient struct {
	mu               sync.Mutex
	createErr        map[string]error // role → err to return on CreateContainer
	startErr         map[string]error // role → err on StartContainer
	created          map[string]bool  // role → true once created
	started          map[string]bool
	forceDeleted     map[string]bool
	netCreated       int
	netDeleted       int
	inspectExitCode  int
	inspectExitDelay time.Duration // simulate "never exits"
	inspectAfter     time.Time     // exited after this wall-clock time
}

func newFakeDocker() *fakeDockerClient {
	return &fakeDockerClient{
		createErr:    map[string]error{},
		startErr:     map[string]error{},
		created:      map[string]bool{},
		started:      map[string]bool{},
		forceDeleted: map[string]bool{},
	}
}

func (f *fakeDockerClient) CreateContainer(ctx context.Context, r docker.CreateContainerRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := r.Labels["runsecure.role"]
	if err, ok := f.createErr[role]; ok {
		return "", err
	}
	f.created[role] = true
	return "id-" + role, nil
}
func (f *fakeDockerClient) StartContainer(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := strings.TrimPrefix(id, "id-")
	if err, ok := f.startErr[role]; ok {
		return err
	}
	f.started[role] = true
	return nil
}
func (f *fakeDockerClient) InspectContainer(ctx context.Context, id string) (docker.Inspect, error) {
	if f.inspectExitDelay > 0 {
		return docker.Inspect{ID: id, State: "running"}, nil
	}
	return docker.Inspect{ID: id, State: "exited", ExitCode: f.inspectExitCode}, nil
}
func (f *fakeDockerClient) DeleteContainer(ctx context.Context, id string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := strings.TrimPrefix(id, "id-")
	f.forceDeleted[role] = force
	return nil
}
func (f *fakeDockerClient) CreateNetwork(ctx context.Context, r docker.CreateNetworkRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netCreated++
	return "net-" + r.Name, nil
}
func (f *fakeDockerClient) DeleteNetwork(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netDeleted++
	return nil
}
func (f *fakeDockerClient) ListContainersForScope(ctx context.Context, scope string) ([]docker.Container, error) {
	return nil, nil
}

// ------------- in-memory emitter + fake breakers/buckets ------------------

type fakeBreakers struct {
	mu     sync.Mutex
	open   map[string]bool
	failed map[string]int
	closed map[string]int
}

func newFakeBreakers() *fakeBreakers {
	return &fakeBreakers{open: map[string]bool{}, failed: map[string]int{}, closed: map[string]int{}}
}

func (b *fakeBreakers) IsOpen(repo string) bool { b.mu.Lock(); defer b.mu.Unlock(); return b.open[repo] }
func (b *fakeBreakers) MaybeHalfOpen(repo string) bool { return false }
func (b *fakeBreakers) RecordSuccess(repo string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed[repo]++
	b.open[repo] = false
}
func (b *fakeBreakers) RecordFailure(repo string) (bool, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed[repo]++
	return false, b.failed[repo]
}

type fakeBucket struct{ taken atomic.Int64 }

func (f *fakeBucket) TryTake() bool { f.taken.Add(1); return true }

type fakeEgress struct{ tempBase string }

func (f *fakeEgress) Render(spawnID string, r *runneryml.Runner) (string, error) {
	dir := filepath.Join(f.tempBase, spawnID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, fn := range []string{"squid.conf", "haproxy.cfg", "dnsmasq.conf"} {
		_ = os.WriteFile(filepath.Join(dir, fn), []byte("# generated"), 0o644)
	}
	return dir, nil
}

// ------------- combined deps shim --------------------------------------

type spawnDeps struct {
	gh          *github.Client
	dc          *fakeDockerClient
	em          *cornerstone.Emitter
	emBuf       *bytes.Buffer
	clk         *clock.Fake
	eg          *fakeEgress
	st          *state.State
	scopeName   string
	globalCap   int
	repoCap     int
	runnerYML   *runneryml.Runner
	imageDigest string
	proxyDigest string
	breakers    *fakeBreakers
	bucket      TokenBucket
}

func (d *spawnDeps) GitHub() *github.Client       { return d.gh }
func (d *spawnDeps) Docker() docker.Client        { return d.dc }
func (d *spawnDeps) Emit() *cornerstone.Emitter   { return d.em }
func (d *spawnDeps) Clock() ClockLike             { return d.clk }
func (d *spawnDeps) Egress() EgressGenerator      { return d.eg }
func (d *spawnDeps) RunnerYML(_ string) (*RunnerYMLSnapshot, error) {
	return &RunnerYMLSnapshot{YML: d.runnerYML, ImageDigest: d.imageDigest}, nil
}
func (d *spawnDeps) State() StateLike              { return d.st }
func (d *spawnDeps) GlobalMaxRunners() int         { return d.globalCap }
func (d *spawnDeps) RepoMaxConcurrent(_ string) int { return d.repoCap }
func (d *spawnDeps) ScopeName() string              { return d.scopeName }
func (d *spawnDeps) ProxyImageDigest() string       { return d.proxyDigest }
func (d *spawnDeps) RunnerImageDigestFor(_ string) string { return d.imageDigest }
func (d *spawnDeps) SeccompProfileHostPath(_ string) string { return "/seccomp/p.json" }
func (d *spawnDeps) RateLimiter() TokenBucket      { return d.bucket }
func (d *spawnDeps) Breakers() BreakerMap          { return d.breakers }

func newSpawnDeps(t *testing.T) *spawnDeps {
	t.Helper()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// default: JIT happy-path, queued=0, runner id 42.
		switch {
		case strings.HasSuffix(r.URL.Path, "/generate-jitconfig"):
			w.WriteHeader(201)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			labels := []map[string]any{}
			if l, ok := body["labels"].([]any); ok {
				for _, x := range l {
					labels = append(labels, map[string]any{"name": x})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"runner":             map[string]any{"id": 42, "labels": labels},
				"encoded_jit_config": "b64",
			})
		case strings.Contains(r.URL.Path, "/actions/runs"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"total_count":0}`))
		case strings.Contains(r.URL.Path, "/actions/runners/"):
			w.WriteHeader(204)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(ghSrv.Close)

	patDir := t.TempDir()
	patFile := filepath.Join(patDir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	gh, err := github.NewClient(ghSrv.URL, patFile)
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	em := cornerstone.NewEmitter(buf, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))

	return &spawnDeps{
		gh:        gh,
		dc:        newFakeDocker(),
		em:        em,
		emBuf:     buf,
		clk:       clock.NewFake(time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)),
		eg:        &fakeEgress{tempBase: t.TempDir()},
		st:        state.New(),
		scopeName: "s",
		globalCap: 10,
		repoCap:   5,
		runnerYML: &runneryml.Runner{
			Runtime:   "node:24",
			Labels:    []string{"self-hosted", "Linux"},
			Resources: runneryml.Resources{Memory: "8g", CPUs: 4, PIDs: 2048},
			Orchestrator: runneryml.OrchestratorBlock{TimeoutSeconds: 60},
		},
		imageDigest: "ghcr.io/test/runner@sha256:rr",
		proxyDigest: "ghcr.io/test/proxy@sha256:pp",
		breakers:    newFakeBreakers(),
		bucket:      &fakeBucket{},
	}
}

func (d *spawnDeps) emitted(name string) bool {
	return strings.Contains(d.emBuf.String(), name)
}

func (d *spawnDeps) requireEmitted(t *testing.T, names ...string) {
	t.Helper()
	out := d.emBuf.String()
	for _, n := range names {
		require.Contains(t, out, n, "expected event %s not emitted", n)
	}
}

// errPolicyDenied is a docker.ErrPolicyDenied-wrapped error usable in spawn tests.
func errPolicyDenied(detail string) error {
	return fmt.Errorf("%w: %s", docker.ErrPolicyDenied, detail)
}

var _ = errors.New // keep `errors` import used

// Wrap the upstream sentinels so classifyJITError tests have stable, named
// values to call.
var (
	testGithubErr_LabelMismatch = github.ErrJITLabelMismatch
	testGithubErr_AuthFailed    = github.ErrAuthFailed
	testGithubErr_RateLimited   = github.ErrRateLimited
)
