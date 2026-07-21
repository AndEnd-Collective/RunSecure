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

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
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
	mu                 sync.Mutex
	queuedFor          map[string]int
	queuedJobIDs       map[string][]int64
	inProgressFor      map[string]int
	queueErrCode       map[string]int // map repo → HTTP status to return
	jitOnRunnerID      int64
	jitLabels          []string
	jitRequestedLabels []string
	jitMismatch        bool
	jitErrCode         int
	deletedRunners     map[int64]bool
	createCalled       int
	deleteCalled       int
	deleteErrCode      int
	deleteErrUntil     int
	rlLimit            int
	rlRemaining        int
	rlReset            string
	rlAfterResponse    bool // include X-RateLimit-Remaining=0 in 403 response
	runnerStatus       string
	runnerBusy         bool
	runnerErrCode      int
	runnerGetCalled    int
	runnerErrAfter     int
	runnerErrUntil     int
	runnerBlock        bool
	runnerStatusAfter  string
	runnerBusyAfter    bool
	runnerChangeAfter  int
	jobRunnerID        int64
	jobRunnerName      string
	jobStatus          string
	jobConclusion      string
	jobErrCode         int
	jobErrUntil        int
	jobGetCalled       int
	jobResponseDelay   time.Duration
	jobChangeAfter     int
	jobStatusAfter     string
	jobRunnerIDAfter   int64
	jobRunnerNameAfter string
	recentRunID        int64
	recentRunCount     int
	recentJobID        int64
	recentJobRunnerID  int64
	recentJobName      string
	recentJobStatus    string
	beforeJobsResponse func()
}

func newFakeGH() *fakeGitHubBackend {
	return &fakeGitHubBackend{
		queuedFor:      map[string]int{},
		queuedJobIDs:   map[string][]int64{},
		inProgressFor:  map[string]int{},
		queueErrCode:   map[string]int{},
		deletedRunners: map[int64]bool{},
		jitOnRunnerID:  100,
		jobRunnerID:    100,
		jobRunnerName:  "runner",
		jobStatus:      "in_progress",
		rlLimit:        5000,
		rlRemaining:    4999,
		runnerStatus:   "online",
		runnerBusy:     true,
		recentJobID:    99001,
	}
}

func assignedCandidate() []github.WorkflowJob {
	return []github.WorkflowJob{{ID: 9001, RunID: 7001}}
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

		// /repos/o/r/actions/runs/<id>/jobs?filter=latest
		if strings.Contains(r.URL.Path, "/actions/runs/") && strings.HasSuffix(r.URL.Path, "/jobs") && r.Method == http.MethodGet {
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
			if g.beforeJobsResponse != nil {
				g.beforeJobsResponse()
				g.beforeJobsResponse = nil
			}
			runID := parts[len(parts)-2]
			if g.recentRunID > 0 && runID == fmt.Sprint(g.recentRunID) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{
					"id": g.recentJobID, "name": "later-dependent", "status": g.recentJobStatus,
					"runner_id": g.recentJobRunnerID, "runner_name": g.recentJobName,
				}}})
				return
			}
			count := g.queuedFor[repo]
			explicitIDs, hasExplicitIDs := g.queuedJobIDs[repo]
			if hasExplicitIDs {
				count = len(explicitIDs)
			}
			if runID == "2" {
				count = g.inProgressFor[repo]
				hasExplicitIDs = false
			}
			if r.URL.Query().Get("page") != "1" {
				count = 0
			}
			jobs := make([]map[string]any, 0, count)
			for i := 0; i < count; i++ {
				id := int64(i + 1)
				if hasExplicitIDs {
					id = explicitIDs[i]
				}
				if runID == "2" {
					id += 100000
				}
				jobs = append(jobs, map[string]any{
					"id": id, "name": fmt.Sprintf("job-%d", id), "status": "queued",
					"labels": []string{"self-hosted", "Linux"},
				})
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
			return
		}
		// /repos/o/r/actions/runs?status=queued|in_progress
		if strings.HasSuffix(r.URL.Path, "/actions/runs") && r.Method == http.MethodGet {
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) < 4 {
				w.WriteHeader(http.StatusNotFound)
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
			count := g.queuedFor[repo]
			if explicitIDs, ok := g.queuedJobIDs[repo]; ok {
				count = len(explicitIDs)
			}
			runID := 1
			if r.URL.Query().Get("status") == "in_progress" {
				count = g.inProgressFor[repo]
				runID = 2
			}
			runs := []map[string]any{}
			if r.URL.Query().Get("status") == "completed" && g.recentRunCount > 0 {
				for i := 0; i < g.recentRunCount; i++ {
					id := int64(7000 + i)
					if i == 0 && g.recentRunID > 0 {
						id = g.recentRunID
					}
					runs = append(runs, map[string]any{"id": id})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
				return
			}
			if count > 0 {
				runs = append(runs, map[string]any{"id": runID})
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
			return
		}
		// /repos/o/r/actions/runners/generate-jitconfig
		if strings.HasSuffix(r.URL.Path, "/generate-jitconfig") && r.Method == http.MethodPost {
			g.createCalled++
			if g.jitErrCode != 0 {
				if g.rlAfterResponse {
					w.Header().Set("X-RateLimit-Remaining", "0")
				}
				w.WriteHeader(g.jitErrCode)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			g.jitRequestedLabels = nil
			if reqLabels, ok := body["labels"].([]any); ok {
				for _, label := range reqLabels {
					if value, ok := label.(string); ok {
						g.jitRequestedLabels = append(g.jitRequestedLabels, value)
					}
				}
			}
			labels := []map[string]any{}
			labelSet := g.jitLabels
			if labelSet == nil {
				// Echo back what was requested unless explicitly told to mismatch.
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
		// GET /repos/o/r/actions/jobs/<id>
		if strings.Contains(r.URL.Path, "/actions/jobs/") && r.Method == http.MethodGet {
			g.jobGetCalled++
			if g.jobResponseDelay > 0 {
				delay := g.jobResponseDelay
				g.mu.Unlock()
				select {
				case <-time.After(delay):
				case <-r.Context().Done():
				}
				g.mu.Lock()
				if r.Context().Err() != nil {
					return
				}
			}
			if g.jobErrCode != 0 && (g.jobErrUntil == 0 || g.jobGetCalled <= g.jobErrUntil) {
				w.WriteHeader(g.jobErrCode)
				return
			}
			parts := strings.Split(r.URL.Path, "/")
			var jobID int64
			_, _ = fmt.Sscanf(parts[len(parts)-1], "%d", &jobID)
			status, runnerID, runnerName := g.jobStatus, g.jobRunnerID, g.jobRunnerName
			if g.jobChangeAfter > 0 && g.jobGetCalled >= g.jobChangeAfter {
				status = g.jobStatusAfter
				runnerID = g.jobRunnerIDAfter
				runnerName = g.jobRunnerNameAfter
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": jobID, "status": status, "conclusion": g.jobConclusion,
				"runner_id": runnerID, "runner_name": runnerName,
			})
			return
		}
		// DELETE /repos/o/r/actions/runners/<id>
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete {
			g.deleteCalled++
			if g.deleteErrCode != 0 && (g.deleteErrUntil == 0 || g.deleteCalled <= g.deleteErrUntil) {
				w.WriteHeader(g.deleteErrCode)
				return
			}
			parts := strings.Split(r.URL.Path, "/")
			if id := parts[len(parts)-1]; id != "" {
				var n int64
				fmt.Sscanf(id, "%d", &n)
				g.deletedRunners[n] = true
			}
			w.WriteHeader(204)
			return
		}
		// GET /repos/o/r/actions/runners/<id>
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodGet {
			g.runnerGetCalled++
			if g.runnerBlock {
				g.mu.Unlock()
				<-r.Context().Done()
				g.mu.Lock()
				return
			}
			if g.runnerErrCode != 0 &&
				(g.runnerErrAfter == 0 || g.runnerGetCalled >= g.runnerErrAfter) &&
				(g.runnerErrUntil == 0 || g.runnerGetCalled <= g.runnerErrUntil) {
				w.WriteHeader(g.runnerErrCode)
				return
			}
			status, busy := g.runnerStatus, g.runnerBusy
			if g.runnerChangeAfter > 0 && g.runnerGetCalled >= g.runnerChangeAfter {
				status, busy = g.runnerStatusAfter, g.runnerBusyAfter
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": g.jitOnRunnerID, "name": "runner", "status": status, "busy": busy,
			})
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
	netCreateErr     error // injected error for CreateNetwork
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
	if f.netCreateErr != nil {
		return "", f.netCreateErr
	}
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

func (f *fakeDockerClient) ListNetworksForScope(ctx context.Context, scope string) ([]docker.Network, error) {
	return nil, nil
}

// ------------- in-memory emitter + fake breakers/buckets ------------------

type fakeBreakers struct {
	mu            sync.Mutex
	open          map[string]bool
	halfOpen      map[string]bool
	allowHalfOpen map[string]bool
	failed        map[string]int
	closed        map[string]int
}

func newFakeBreakers() *fakeBreakers {
	return &fakeBreakers{
		open: map[string]bool{}, halfOpen: map[string]bool{}, allowHalfOpen: map[string]bool{},
		failed: map[string]int{}, closed: map[string]int{},
	}
}

func (b *fakeBreakers) IsOpen(repo string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open[repo]
}
func (b *fakeBreakers) MaybeHalfOpen(repo string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open[repo] && b.allowHalfOpen[repo] {
		b.open[repo] = false
		b.halfOpen[repo] = true
		return true
	}
	return false
}
func (b *fakeBreakers) RecordSuccess(repo string) (closed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	wasOpen := b.open[repo] || b.halfOpen[repo]
	b.closed[repo]++
	b.open[repo] = false
	b.halfOpen[repo] = false
	b.failed[repo] = 0
	return wasOpen
}
func (b *fakeBreakers) RecordFailure(repo string) (opened bool, count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	wasOpen := b.open[repo]
	b.failed[repo]++
	if b.halfOpen[repo] || (!wasOpen && b.failed[repo] >= 5) {
		b.open[repo] = true
		b.halfOpen[repo] = false
		return true, b.failed[repo]
	}
	return false, b.failed[repo]
}

type fakeBucket struct{ taken atomic.Int64 }

func (f *fakeBucket) TryTake() bool { f.taken.Add(1); return true }

type fakeEgress struct {
	tempBase            string
	renderErr           error
	allowedPrivateCIDRs []string // returned as the second Render return value
}

func (f *fakeEgress) Render(spawnID string, r *runneryml.Runner) (string, []string, error) {
	if f.renderErr != nil {
		return "", nil, f.renderErr
	}
	dir := filepath.Join(f.tempBase, spawnID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	for _, fn := range []string{"squid.conf", "haproxy.cfg", "dnsmasq.conf"} {
		_ = os.WriteFile(filepath.Join(dir, fn), []byte("# generated"), 0o644)
	}
	return dir, f.allowedPrivateCIDRs, nil
}

// ------------- fake backend -------------------------------------------

// fakeBackend implements backend.Backend for unit tests. It records every
// Spawn / WaitForExit / Teardown call so tests can assert invocation order
// and count. By default Spawn succeeds and WaitForExit returns (0, false).
type fakeBackend struct {
	mu sync.Mutex

	// Spawn controls.
	spawnErr           error // if non-nil, Spawn returns this error
	spawnPartialHandle bool  // return an owned handle alongside spawnErr
	spawnCalls         []backend.SpawnInput
	spawnHandles       []backend.Handle // handles returned by Spawn (one per call)

	// WaitForExit controls.
	waitCalls    []backend.Handle
	waitExitCode int
	waitTimedOut bool

	// Teardown controls.
	teardownErr   error
	teardownErrs  []error
	teardownCalls []struct {
		handle backend.Handle
		force  bool
		ctxErr error
	}
	// inspectExitDelay simulates a runner that never exits (WaitForExit blocks
	// until timeout fires). When non-zero WaitForExit returns (-1, true).
	inspectExitDelay time.Duration
	waitDelay        time.Duration
}

func newFakeBackend() *fakeBackend { return &fakeBackend{} }

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Spawn(_ context.Context, in backend.SpawnInput) (backend.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spawnCalls = append(f.spawnCalls, in)
	h := backend.Handle{
		SpawnID: in.SpawnID,
		Backend: "fake",
		Refs: map[string]string{
			"runner":  "id-runner",
			"proxy":   "id-proxy",
			"network": "net-fake",
		},
	}
	if f.spawnErr != nil {
		if f.spawnPartialHandle {
			return h, f.spawnErr
		}
		return backend.Handle{}, f.spawnErr
	}
	f.spawnHandles = append(f.spawnHandles, h)
	return h, nil
}

func (f *fakeBackend) WaitForExit(_ context.Context, h backend.Handle, _ time.Duration) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.waitCalls = append(f.waitCalls, h)
	if f.waitDelay > 0 {
		time.Sleep(f.waitDelay)
		return f.waitExitCode, f.waitTimedOut
	}
	if f.inspectExitDelay > 0 {
		// Simulate never-exiting runner: block briefly then return timedOut.
		// Use a small real sleep so callers that advance a fake clock can drive
		// the timeout in Execute; fakeBackend itself does not consult the clock.
		time.Sleep(f.inspectExitDelay)
		return -1, true
	}
	return f.waitExitCode, f.waitTimedOut
}

func (f *fakeBackend) Teardown(ctx context.Context, h backend.Handle, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.teardownCalls = append(f.teardownCalls, struct {
		handle backend.Handle
		force  bool
		ctxErr error
	}{h, force, ctx.Err()})
	if len(f.teardownErrs) > 0 {
		err := f.teardownErrs[0]
		f.teardownErrs = f.teardownErrs[1:]
		return err
	}
	return f.teardownErr
}

func (f *fakeBackend) Reconcile(_ context.Context, _ string) ([]backend.Handle, error) {
	return nil, nil
}

// spawnCount returns the number of Spawn calls recorded.
func (f *fakeBackend) spawnCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.spawnCalls)
}

// waitCount returns the number of WaitForExit calls recorded.
func (f *fakeBackend) waitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waitCalls)
}

// teardownCount returns the number of Teardown calls recorded.
func (f *fakeBackend) teardownCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.teardownCalls)
}

// ------------- combined deps shim --------------------------------------

type spawnDeps struct {
	gh             *github.Client
	dc             *fakeDockerClient
	be             *fakeBackend
	em             *cornerstone.Emitter
	emBuf          *bytes.Buffer
	clk            *clock.Fake
	eg             *fakeEgress
	st             *state.State
	scopeName      string
	globalCap      int
	repoCap        int
	runnerYML      *runneryml.Runner
	runnerYMLErr   error
	imageDigest    string // snapshot.ImageDigest
	fallbackDigest string // RunnerImageDigestFor(...) — defaults to imageDigest
	proxyDigest    string
	breakers       *fakeBreakers
	bucket         TokenBucket
	lifecycle      LifecycleTiming
	version        string
	buildSHA       string
	rlMu           sync.Mutex
	rateLimit      github.RateLimit
	ratePaused     atomic.Bool
}

func (d *spawnDeps) GitHub() *github.Client     { return d.gh }
func (d *spawnDeps) Docker() docker.Client      { return d.dc }
func (d *spawnDeps) Backend() backend.Backend   { return d.be }
func (d *spawnDeps) Emit() *cornerstone.Emitter { return d.em }
func (d *spawnDeps) Clock() ClockLike           { return d.clk }
func (d *spawnDeps) Egress() EgressGenerator    { return d.eg }
func (d *spawnDeps) RunnerYMLContext(_ context.Context, _ string) (*RunnerYMLSnapshot, error) {
	if d.runnerYMLErr != nil {
		return nil, d.runnerYMLErr
	}
	return &RunnerYMLSnapshot{YML: d.runnerYML, ImageDigest: d.imageDigest}, nil
}
func (d *spawnDeps) State() StateLike               { return d.st }
func (d *spawnDeps) GlobalMaxRunners() int          { return d.globalCap }
func (d *spawnDeps) RepoMaxConcurrent(_ string) int { return d.repoCap }
func (d *spawnDeps) ScopeName() string              { return d.scopeName }
func (d *spawnDeps) ProxyImageDigest() string       { return d.proxyDigest }
func (d *spawnDeps) RunnerImageDigestFor(_ string) string {
	if d.fallbackDigest != "" {
		return d.fallbackDigest
	}
	return d.imageDigest
}
func (d *spawnDeps) SeccompProfileHostPath(_ string) string { return "/seccomp/p.json" }
func (d *spawnDeps) RateLimiter() TokenBucket               { return d.bucket }
func (d *spawnDeps) RateLimitContextFor(_ string) (int, int, string) {
	d.rlMu.Lock()
	defer d.rlMu.Unlock()
	reset := ""
	if d.rateLimit.ResetUnix != 0 {
		reset = time.Unix(d.rateLimit.ResetUnix, 0).Format(time.RFC3339)
	}
	return d.rateLimit.Remaining, d.rateLimit.Limit, reset
}
func (d *spawnDeps) RecordRateLimit(_ string, lim github.RateLimit) {
	d.rlMu.Lock()
	d.rateLimit = lim
	d.rlMu.Unlock()
}
func (d *spawnDeps) MarkRateLimited(_ string) bool {
	d.st.SetRateLimited(true)
	return !d.ratePaused.Swap(true)
}
func (d *spawnDeps) LifecycleTiming() LifecycleTiming { return d.lifecycle }
func (d *spawnDeps) Version() string                  { return d.version }
func (d *spawnDeps) BuildSHA() string                 { return d.buildSHA }

func newSpawnDeps(t *testing.T) *spawnDeps {
	t.Helper()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Default: JIT happy-path with one exact in-progress job on runner 42.
		// Lifecycle assignment is deliberately job-ID correlated, so the fixture
		// must expose the same runner through the workflow-jobs API.
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
		case strings.Contains(r.URL.Path, "/actions/runs/") && strings.HasSuffix(r.URL.Path, "/jobs"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"jobs":[{"id":9001,"status":"in_progress","runner_id":42,"runner_name":"runner"}]}`))
		case strings.HasSuffix(r.URL.Path, "/actions/runs"):
			w.WriteHeader(200)
			if r.URL.Query().Get("status") == "in_progress" {
				_, _ = w.Write([]byte(`{"workflow_runs":[{"id":7001}]}`))
			} else {
				_, _ = w.Write([]byte(`{"workflow_runs":[]}`))
			}
		case strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodGet:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"id":42,"name":"runner","status":"online","busy":true}`))
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
		be:        newFakeBackend(),
		em:        em,
		emBuf:     buf,
		clk:       clock.NewFake(time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)),
		eg:        &fakeEgress{tempBase: t.TempDir()},
		st:        state.New(),
		scopeName: "s",
		globalCap: 10,
		repoCap:   5,
		runnerYML: &runneryml.Runner{
			Runtime:      "node:24",
			Labels:       []string{"self-hosted", "Linux"},
			Resources:    runneryml.Resources{Memory: "8g", CPUs: 4, PIDs: 2048},
			Orchestrator: runneryml.OrchestratorBlock{TimeoutSeconds: 60},
		},
		imageDigest: "ghcr.io/test/runner@sha256:rr",
		proxyDigest: "ghcr.io/test/proxy@sha256:pp",
		breakers:    newFakeBreakers(),
		bucket:      &fakeBucket{},
		lifecycle: LifecycleTiming{
			OnlineTimeout: 100 * time.Millisecond, AssignmentTimeout: 200 * time.Millisecond,
			PollInterval: time.Millisecond, CleanupRetryInterval: time.Millisecond,
		},
		version:  "v-test",
		buildSHA: "sha-test",
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
