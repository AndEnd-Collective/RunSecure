package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/auth"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/compose"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/clock"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/egress"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/server"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
)

//coverage:ignore Run is the production wiring; covered by integration tests
func Run(ctx context.Context, scopePath string) (runErr error) {
	s, err := config.Load(scopePath)
	if err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}

	clk := clock.System()
	em := cornerstone.NewEmitter(os.Stdout, cornerstone.SystemClock, cornerstone.SystemUUID)
	// Bug #3 fix: respect RUNSECURE_GITHUB_BASE_URL for integration tests
	// (mock-github) and future GitHub Enterprise deployments.
	baseURL := envOr("RUNSECURE_GITHUB_BASE_URL", github.DefaultBaseURL)
	provider, err := buildAuthProvider(s, baseURL)
	if err != nil {
		return err
	}
	gh, err := github.NewClientWithProvider(baseURL, provider)
	if err != nil {
		return err
	}
	st := state.New()
	repoNames := make([]string, 0, len(s.Repos))
	for _, repo := range s.Repos {
		repoNames = append(repoNames, repo.Repo)
	}
	st.Configure(repoNames, s.GlobalMaxRunners, s.GlobalMaxRunners, version, buildSHA)
	serverDeps := newServerDeps(st, clk, s.PollIntervalSeconds)
	gh.SetRequestObserver(serverDeps.recordAPICall)

	// Bind liveness before cold-start reconciliation. Recovered runner cleanup
	// performs bounded-but-sequential GitHub and backend calls and must not be
	// killed by a liveness probe merely because it legitimately outlasts three
	// poll intervals. /readyz remains fail-closed because BackendReady has not
	// been installed and no repository has completed a demand refresh.
	serverCtx, stopServer := context.WithCancel(ctx)
	srv := server.New(":8080", ":8081", serverDeps, em)
	serverDone, err := srv.Start(serverCtx)
	if err != nil {
		stopServer()
		return fmt.Errorf("orchestrator: start management server: %w", err)
	}
	serverStopped := false
	var serverRunErr error
	waitServer := func() error {
		if !serverStopped {
			serverRunErr = <-serverDone
			serverStopped = true
		}
		return serverRunErr
	}
	defer func() {
		stopServer()
		if !serverStopped {
			if err := waitServer(); err != nil {
				runErr = errors.Join(runErr,
					fmt.Errorf("orchestrator: management server: %w", err))
			}
		}
	}()

	// Initialize and reconcile only the selected runtime backend. Kubernetes
	// deployments intentionally have no Docker socket-proxy or DOCKER_HOST;
	// constructing a Docker client there made a valid Helm deployment fail
	// before the in-cluster backend was selected.
	be, dc, err := initializeBackend(
		ctx, s, repoNames, gh, docker.NewClient, productionKubeCtor,
	)
	if err != nil {
		return fmt.Errorf("orchestrator: backend init: %w", err)
	}

	// Build everything the poll + spawn deps need.
	intentCh := make(chan orchestrator.SpawnIntent, 32)
	// B1 rate limiter — token bucket protecting against unbounded burst.
	// Defaults: 5 tokens/sec sustained, burst 10. The burst allows initial
	// fan-out when the orchestrator first sees a queued backlog; sustained
	// rate prevents a runaway poll loop from spawning thousands.
	rl := state.NewTokenBucket(5, 10, time.Now)
	brks := newBreakerMap()
	eg := egress.NewFSGenerator(envOr("RUNSECURE_EGRESS_BASE_DIR", orchestrator.EgressMountPath))
	basePolicy, err := buildBasePolicy(s.SecurityProfile, s.SecurityOverrides, allOverrideKeys())
	if err != nil {
		return fmt.Errorf("orchestrator: scope security_overrides invalid: %w", err)
	}
	serverDeps.setBackendReady(func(ctx context.Context) error {
		_, err := be.Reconcile(ctx, s.Name)
		return err
	})
	pdeps := &productionDeps{
		gh:          gh,
		dc:          dc,
		be:          be,
		em:          em,
		clk:         clk,
		st:          st,
		eg:          eg,
		basePolicy:  basePolicy,
		allowKeys:   s.AllowProjectOverrides,
		bucket:      rl,
		brks:        brks,
		intents:     intentCh,
		scopeRef:    s,
		serverDeps:  serverDeps,
		runnerCache: map[string]*orchestrator.RunnerYMLSnapshot{},
	}
	serverDeps.breakerSnap = brks.snapshot

	scopeRef := orchestrator.ScopeRef{
		Name:             s.Name,
		GlobalMaxRunners: s.GlobalMaxRunners,
		PollIntervalSec:  s.PollIntervalSeconds,
	}
	for _, r := range s.Repos {
		scopeRef.Repos = append(scopeRef.Repos, orchestrator.RepoRef{
			Repo: r.Repo, MaxConcurrent: r.MaxConcurrent,
		})
	}
	poll := orchestrator.NewPoll(scopeRef, pdeps)

	// Spawn worker pool.
	worker := orchestrator.NewSpawnWorker(pdeps)
	pollCtx, stopPolling := context.WithCancel(ctx)
	defer stopPolling()
	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	var draining atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < s.GlobalMaxRunners; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for intent := range intentCh {
				// Once shutdown begins, discard queued-but-not-started intents.
				// An intent whose load won the race immediately before Store(true)
				// is already admitted work and participates in the drain deadline.
				if draining.Load() {
					pdeps.ReleaseReservation(intent.SpawnID)
					continue
				}
				outcome := "success"
				if err := worker.Execute(workerCtx, intent); err != nil {
					outcome = "failure"
				}
				serverDeps.recordSpawn(intent.Scope, intent.Repo, outcome)
			}
		}()
	}
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		poll.Run(pollCtx)
	}()

	// Wait for SIGTERM / SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	select {
	case <-ctx.Done():
	case sig := <-sigCh:
		fmt.Fprintln(os.Stderr, "orchestrator: caught", sig, "— draining…")
	case serverRunErr = <-serverDone:
		serverStopped = true
		if serverRunErr == nil && ctx.Err() == nil {
			return errors.New("orchestrator: management server stopped unexpectedly")
		}
		if serverRunErr != nil {
			return fmt.Errorf("orchestrator: management server: %w", serverRunErr)
		}
	}

	// Stop and join the sole channel producer before closing intentCh. The old
	// order closed the channel while Poll was still live, allowing a send on a
	// closed channel. Active runners drain until the deadline; only then is their
	// context cancelled so SpawnWorker can force-teardown with a fresh cleanup
	// context rather than the already-cancelled worker context.
	st.SetDraining(true)
	drainTimeout := time.Duration(envIntOr("RUNSECURE_DRAIN_SECONDS", 60)) * time.Second
	result := drainAndStop(drainTimeout, stopPolling, pollDone, intentCh,
		&draining, stopWorkers, workersDone)
	if result.Forced {
		fmt.Fprintln(os.Stderr, "orchestrator: drain deadline reached — forced runner cleanup requested")
	}
	if !result.WorkersStopped {
		return errors.New("orchestrator: workers did not stop within forced-cleanup grace")
	}
	return nil
}

// buildAuthProvider constructs the appropriate auth.Provider for the scope's
// configured auth type. It is a package-level function (not inlined in Run) so
// that the cmd tests can invoke it without instantiating the full Run graph.
func buildAuthProvider(s *config.Scope, apiBaseURL string) (auth.Provider, error) {
	switch s.Auth.Type {
	case "pat":
		if s.Backend == "kube" {
			return auth.NewKubernetesPATProvider(s.Auth.PATFile)
		}
		return auth.NewPATProvider(s.Auth.PATFile)
	case "github_app":
		if s.Backend == "kube" {
			return auth.NewKubernetesGitHubAppProvider(
				s.Auth.AppID,
				s.Auth.InstallationID,
				s.Auth.PrivateKeyFile,
				apiBaseURL,
			)
		}
		return auth.NewGitHubAppProvider(
			s.Auth.AppID,
			s.Auth.InstallationID,
			s.Auth.PrivateKeyFile,
			apiBaseURL,
		)
	default:
		// Validate() already rejects unknown types; this is a defensive guard.
		return nil, fmt.Errorf("orchestrator: unknown auth.type %q", s.Auth.Type)
	}
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func envIntOr(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return fallback
	}
	return n
}

// ------------- breaker map (one breaker per repo) ----------------------

type breakerMap struct {
	mu       sync.Mutex
	breakers map[string]*state.Breaker
}

func newBreakerMap() *breakerMap { return &breakerMap{breakers: map[string]*state.Breaker{}} }

func (b *breakerMap) get(repo string) *state.Breaker {
	b.mu.Lock()
	defer b.mu.Unlock()
	if br, ok := b.breakers[repo]; ok {
		return br
	}
	br := state.NewBreaker(5, 5*time.Minute, time.Now)
	b.breakers[repo] = br
	return br
}

func (b *breakerMap) IsOpen(repo string) bool        { return b.get(repo).IsOpen() }
func (b *breakerMap) MaybeHalfOpen(repo string) bool { return b.get(repo).MaybeHalfOpen() }
func (b *breakerMap) RecordSuccess(repo string) (closed bool) {
	return b.get(repo).RecordSuccess()
}
func (b *breakerMap) RecordFailure(repo string) (opened bool, count int) {
	return b.get(repo).RecordFailure()
}
func (b *breakerMap) snapshot() map[string]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]bool, len(b.breakers))
	for k, v := range b.breakers {
		out[k] = v.IsOpen()
	}
	return out
}

// ------------- server-deps shim ----------------------------------------

type serverDeps struct {
	st           *state.State
	clk          clock.Clock
	intervalS    int
	lastPoll     atomic.Pointer[time.Time]
	pollStarted  atomic.Bool
	api          sync.Map // server.APICallKey → *int64
	spawns       sync.Map
	breakerSnap  func() map[string]bool
	readyMu      sync.RWMutex
	backendReady func(context.Context) error
}

func newServerDeps(st *state.State, clk clock.Clock, intervalS int) *serverDeps {
	d := &serverDeps{st: st, clk: clk, intervalS: intervalS}
	t := time.Now()
	d.lastPoll.Store(&t)
	return d
}

func (d *serverDeps) LastPollAt() time.Time {
	p := d.lastPoll.Load()
	if p == nil {
		return time.Time{}
	}
	return *p
}
func (d *serverDeps) PollStarted() bool        { return d.pollStarted.Load() }
func (d *serverDeps) Now() time.Time           { return d.clk.Now() }
func (d *serverDeps) PollIntervalSeconds() int { return d.intervalS }
func (d *serverDeps) StateSnapshot() state.Snapshot {
	snap := d.st.Snapshot()
	if d.breakerSnap != nil {
		for repo, open := range d.breakerSnap() {
			r := snap.PerRepo[repo]
			r.BreakerOpen = open
			snap.PerRepo[repo] = r
		}
	}
	return snap
}

func (d *serverDeps) setBackendReady(fn func(context.Context) error) {
	d.readyMu.Lock()
	d.backendReady = fn
	d.readyMu.Unlock()
}

func (d *serverDeps) BackendReady(ctx context.Context) error {
	d.readyMu.RLock()
	fn := d.backendReady
	d.readyMu.RUnlock()
	if fn == nil {
		return errors.New("backend not initialized")
	}
	return fn(ctx)
}
func (d *serverDeps) APICalls() map[server.APICallKey]int64 {
	out := map[server.APICallKey]int64{}
	d.api.Range(func(k, v any) bool {
		out[k.(server.APICallKey)] = atomic.LoadInt64(v.(*int64))
		return true
	})
	return out
}
func (d *serverDeps) SpawnsTotal() map[server.SpawnKey]int64 {
	out := map[server.SpawnKey]int64{}
	d.spawns.Range(func(k, v any) bool {
		out[k.(server.SpawnKey)] = atomic.LoadInt64(v.(*int64))
		return true
	})
	return out
}

func (d *serverDeps) recordAPICall(method, path, status string) {
	key := server.APICallKey{Endpoint: githubAPIEndpoint(method, path), Status: status}
	counter, _ := d.api.LoadOrStore(key, new(int64))
	atomic.AddInt64(counter.(*int64), 1)
}

func (d *serverDeps) recordSpawn(scope, repo, outcome string) {
	key := server.SpawnKey{Scope: scope, Repo: repo, Outcome: outcome}
	counter, _ := d.spawns.LoadOrStore(key, new(int64))
	atomic.AddInt64(counter.(*int64), 1)
}

func githubAPIEndpoint(method, path string) string {
	cleanPath := path
	if query := strings.IndexByte(cleanPath, '?'); query >= 0 {
		cleanPath = cleanPath[:query]
	}
	switch {
	case strings.Contains(cleanPath, "/contents/.github/runner.yml"):
		return "runner_yml"
	case strings.Contains(cleanPath, "/generate-jitconfig"):
		return "generate_jit_config"
	case strings.Contains(cleanPath, "/actions/runs/") && strings.HasSuffix(cleanPath, "/jobs"):
		return "workflow_jobs"
	case strings.HasSuffix(cleanPath, "/actions/runs"):
		return "workflow_runs"
	case strings.Contains(cleanPath, "/actions/jobs/"):
		return "workflow_job"
	case strings.Contains(cleanPath, "/actions/runners/") && method == "DELETE":
		return "delete_runner"
	case strings.Contains(cleanPath, "/actions/runners/"):
		return "get_runner"
	case strings.HasSuffix(cleanPath, "/actions/runners"):
		return "list_runners"
	default:
		return "other"
	}
}
func (d *serverDeps) SpawnDurations() map[string][]float64 { return nil }
func (d *serverDeps) BreakerOpen() map[string]bool {
	if d.breakerSnap == nil {
		return nil
	}
	return d.breakerSnap()
}

// ------------- production deps for poll + spawn ------------------------

type productionDeps struct {
	gh          *github.Client
	dc          docker.Client
	be          backend.Backend
	em          *cornerstone.Emitter
	clk         clock.Clock
	st          *state.State
	eg          egress.Generator
	basePolicy  security.Policy
	allowKeys   []string
	bucket      *state.TokenBucket
	brks        *breakerMap
	intents     chan orchestrator.SpawnIntent
	scopeRef    *config.Scope
	serverDeps  *serverDeps
	runnerMu    sync.Mutex
	runnerCache map[string]*orchestrator.RunnerYMLSnapshot

	// rate-limit state
	rlMu     sync.Mutex
	rlPaused bool
	rlReset  time.Time
}

// PollDeps and SpawnDeps shared methods.

func (p *productionDeps) GitHub() *github.Client        { return p.gh }
func (p *productionDeps) Docker() docker.Client         { return p.dc }
func (p *productionDeps) Backend() backend.Backend      { return p.be }
func (p *productionDeps) Emit() *cornerstone.Emitter    { return p.em }
func (p *productionDeps) Clock() orchestrator.ClockLike { return p.clk }
func (p *productionDeps) Egress() orchestrator.EgressGenerator {
	return egressShim{g: p.eg, base: p.basePolicy, allowKeys: p.allowKeys}
}
func (p *productionDeps) State() orchestrator.StateLike { return p.st }

func (p *productionDeps) RunnerYML(repo string) (*orchestrator.RunnerYMLSnapshot, error) {
	return p.RunnerYMLContext(context.Background(), repo)
}

func (p *productionDeps) RunnerYMLContext(
	ctx context.Context,
	repo string,
) (*orchestrator.RunnerYMLSnapshot, error) {
	for _, r := range p.scopeRef.Repos {
		if r.Repo != repo {
			continue
		}
		if p.scopeRef.Backend == "kube" {
			snapshot, err := loadRunnerYMLFromAPI(ctx, p.gh, p.st, repo)
			if errors.Is(err, errRunnerYMLNotModified) {
				if cached, ok := p.cachedRunnerYML(repo); ok {
					return cached, nil
				}
			}
			if err != nil {
				return nil, err
			}
			p.storeRunnerYML(repo, snapshot)
			return snapshot, nil
		}
		yml, err := runneryml.Parse(filepath_join(r.ProjectDir, ".github", "runner.yml"))
		if err != nil {
			return nil, err
		}
		for _, w := range yml.DeprecationWarnings() {
			fmt.Fprintln(os.Stderr, "[RunSecure] WARNING:", w)
		}
		if err := yml.ValidateEgress(); err != nil {
			return nil, fmt.Errorf("runner.yml egress validation: %w", err)
		}
		snapshot := &orchestrator.RunnerYMLSnapshot{YML: yml}
		p.storeRunnerYML(repo, snapshot)
		return snapshot, nil
	}
	return nil, errors.New("unknown repo")
}

func (p *productionDeps) cachedRunnerYML(
	repo string,
) (*orchestrator.RunnerYMLSnapshot, bool) {
	p.runnerMu.Lock()
	defer p.runnerMu.Unlock()
	cached, ok := p.runnerCache[repo]
	return cached, ok
}

func (p *productionDeps) storeRunnerYML(
	repo string,
	snapshot *orchestrator.RunnerYMLSnapshot,
) {
	p.runnerMu.Lock()
	if p.runnerCache == nil {
		p.runnerCache = map[string]*orchestrator.RunnerYMLSnapshot{}
	}
	p.runnerCache[repo] = snapshot
	p.runnerMu.Unlock()
}

// loadRunnerYMLFromAPI fetches runner.yml via the GitHub Contents API using
// ETag-based conditional requests (304 → reuse cached snapshot). It is a
// package-level function (not a method) so tests can inject a stubbed github
// client without instantiating the full productionDeps graph.
//
// The st argument provides ETag storage per repo (state.RepoState.LastETag).
// On 304 the function returns errNotModified; callers should substitute their
// cached snapshot. On 200 the snapshot is returned and the ETag is persisted.
//
// TODO(k8s_context): once cornerstone defines a k8s_context schema field,
// thread Backend=="kube" into Cornerstone spawn events here and in spawn.go
// instead of container_context. Currently container_context is reused as-is
// for kube (no behavior change; pod names are set via Handle.Refs not ctx).
func loadRunnerYMLFromAPI(ctx context.Context, gh *github.Client, st etagger, repo string) (*orchestrator.RunnerYMLSnapshot, error) {
	etag := st.LastETag(repo)
	body, newETag, notModified, err := gh.GetRunnerYML(ctx, repo, etag)
	if err != nil {
		return nil, fmt.Errorf("runner.yml API fetch for %s: %w", repo, err)
	}
	if notModified {
		// Caller must supply a cached snapshot; surface a sentinel so the
		// caller can distinguish 304 from a real error.
		return nil, errRunnerYMLNotModified
	}
	yml, err := runneryml.ParseBytes(body, "api:"+repo)
	if err != nil {
		return nil, err
	}
	for _, w := range yml.DeprecationWarnings() {
		fmt.Fprintln(os.Stderr, "[RunSecure] WARNING:", w)
	}
	if err := yml.ValidateEgress(); err != nil {
		return nil, fmt.Errorf("runner.yml egress validation: %w", err)
	}
	if newETag != "" {
		st.SetLastETag(repo, newETag)
	}
	return &orchestrator.RunnerYMLSnapshot{YML: yml}, nil
}

// errRunnerYMLNotModified is returned by loadRunnerYMLFromAPI when the server
// responds 304 Not Modified. The caller must substitute the cached snapshot.
var errRunnerYMLNotModified = errors.New("runner.yml: not modified (304)")

// etagger is the subset of *state.State used by loadRunnerYMLFromAPI so that
// tests can inject a lightweight stub without the full state.State.
type etagger interface {
	LastETag(repo string) string
	SetLastETag(repo, etag string)
}

// PollDeps-only ------------------------------------------------------------

func (p *productionDeps) InFlight(repo string) int       { return p.st.InFlight(repo) }
func (p *productionDeps) GlobalInFlight() int            { return p.st.GlobalInFlight() }
func (p *productionDeps) SchedulingBlocked() bool        { return p.st.SchedulingBlocked() }
func (p *productionDeps) BreakerIsOpen(repo string) bool { return p.brks.IsOpen(repo) }
func (p *productionDeps) BreakerMaybeHalfOpen(repo string) bool {
	return p.brks.MaybeHalfOpen(repo)
}
func (p *productionDeps) IntentChannel() chan<- orchestrator.SpawnIntent { return p.intents }
func (p *productionDeps) RateLimitContextFor(_ string) (int, int, string) {
	rem, lim, reset := p.st.RateLimit()
	if reset.IsZero() {
		return rem, lim, ""
	}
	return rem, lim, reset.Format(time.RFC3339)
}
func (p *productionDeps) RecordRateLimit(_ string, lim github.RateLimit) {
	reset := time.Time{}
	if lim.ResetUnix > 0 {
		reset = time.Unix(lim.ResetUnix, 0)
	}
	p.st.SetRateLimit(lim.Remaining, lim.Limit, reset)
}
func (p *productionDeps) MarkRateLimited(_ string) bool {
	p.rlMu.Lock()
	newlyPaused := !p.rlPaused
	p.rlPaused = true
	_, _, r := p.st.RateLimit()
	if r.IsZero() {
		r = time.Now().Add(time.Minute)
	}
	p.rlReset = r
	p.st.SetRateLimited(true)
	p.rlMu.Unlock()
	return newlyPaused
}
func (p *productionDeps) IsRateLimited(_ string) bool {
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	return p.rlPaused
}
func (p *productionDeps) MaybeClearRateLimit(_ string) bool {
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	if p.rlPaused && time.Now().After(p.rlReset) {
		p.rlPaused = false
		p.st.SetRateLimited(false)
		return true
	}
	return false
}
func (p *productionDeps) NewSpawnID() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), nextSeq())
}

func (p *productionDeps) LabelsForRepo(
	ctx context.Context,
	repo string,
) ([]string, error) {
	snapshot, err := p.RunnerYMLContext(ctx, repo)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), snapshot.YML.Labels...), nil
}

func (p *productionDeps) TryReserve(spawnID, repo string, repoCap, globalCap int) bool {
	return p.st.TryReserve(spawnID, repo, repoCap, globalCap, p.clk.Now())
}

func (p *productionDeps) ReconcileDemand(repo string, queuedJobIDs []int64) int {
	return p.st.ReconcileDemand(repo, queuedJobIDs)
}

func (p *productionDeps) ReleaseReservation(spawnID string) {
	p.st.ReleaseReservation(spawnID)
}

func (p *productionDeps) RecordPollAttempt(repo string) {
	p.st.RecordPollAttempt(repo, p.clk.Now())
}

func (p *productionDeps) RecordPollSuccess(repo string, queued int) bool {
	p.st.RecordPollSuccess(repo, queued, p.clk.Now())
	return p.brks.RecordSuccess(repo)
}

func (p *productionDeps) RecordPollFailure(repo, class, detail string) (bool, int) {
	p.st.RecordPollFailure(repo, class, detail)
	// A scoped rate-limit pause already suppresses every repository poll until
	// its reset window. It must not also consume the per-repository demand
	// breaker budget or turn one GitHub quota event into a five-minute outage.
	if class == "github_rate_limited" {
		return false, 0
	}
	return p.brks.RecordFailure(repo)
}

// RecordPollTick (bug #2 fix) updates the serverDeps freshness signal that
// /healthz reads. Without this, lastPoll is set once at boot and /healthz
// goes red after 3*poll_interval and stays there.
func (p *productionDeps) RecordPollTick() {
	t := time.Now()
	p.serverDeps.lastPoll.Store(&t)
	p.serverDeps.pollStarted.Store(true)
}

// SpawnDeps-only --------------------------------------------------------

func (p *productionDeps) GlobalMaxRunners() int { return p.scopeRef.GlobalMaxRunners }
func (p *productionDeps) RepoMaxConcurrent(repo string) int {
	for _, r := range p.scopeRef.Repos {
		if r.Repo == repo {
			return r.MaxConcurrent
		}
	}
	return 1
}
func (p *productionDeps) ScopeName() string        { return p.scopeRef.Name }
func (p *productionDeps) ProxyImageDigest() string { return os.Getenv("RUNSECURE_PROXY_IMAGE") }
func (p *productionDeps) RunnerImageDigestFor(runtime string) string {
	// Convention: env var RUNSECURE_RUNNER_IMAGE_<RUNTIME_UPPERCASE> →
	// "ghcr.io/.../runner-<lang>:<ver>@sha256:..." Caller has bounded
	// this via socket-proxy's allowed-images.txt.
	upper := upperRuntime(runtime)
	if v := os.Getenv("RUNSECURE_RUNNER_IMAGE_" + upper); v != "" {
		return v
	}
	return os.Getenv("RUNSECURE_RUNNER_IMAGE_DEFAULT")
}
func (p *productionDeps) SeccompProfileHostPath(name string) string {
	// Empty name → no seccomp profile applied (defense in depth on top of
	// cap_drop:ALL + no-new-privileges, not load-bearing).
	//
	// When set, the path must be a JSON-encoded profile that dockerd can
	// read at container-start time. Note: Docker's SecurityOpt API expects
	// the JSON CONTENTS, not a file path — passing a path triggers
	// "Decoding seccomp profile failed". A path-based wiring requires the
	// orchestrator to read the file and inject the JSON inline, which
	// requires bind-mounting the seccomp dir into the orchestrator. That
	// integration is deferred; for now an explicit profile name is treated
	// as a no-op until the bind-mount is wired (next: read the file in
	// productionDeps and pass JSON inline).
	if name == "" {
		return ""
	}
	return "/host/seccomp/" + name
}
func (p *productionDeps) RateLimiter() orchestrator.TokenBucket {
	return tokenBucketAdapter{b: p.bucket}
}
func (p *productionDeps) LifecycleTiming() orchestrator.LifecycleTiming {
	return orchestrator.DefaultLifecycleTiming()
}
func (p *productionDeps) Version() string  { return version }
func (p *productionDeps) BuildSHA() string { return buildSHA }

// ------------- small adapters --------------------------------------------

// egressShim adapts egress.Generator (which needs a resolved security.Policy)
// to the orchestrator.EgressGenerator interface (which only has spawnID + Runner).
//
// Policy resolution happens per-spawn in Render:
//  1. Start from the operator-level base policy (scope Defaults + scope overrides).
//  2. Apply the project's runner.yml security_overrides, gated to the keys the
//     scope permits via AllowProjectOverrides. Disallowed keys are ignored.
//  3. Fail the spawn on any type-mismatch in the project's override values.
type egressShim struct {
	g         egress.Generator
	base      security.Policy
	allowKeys []string
}

func (e egressShim) Render(spawnID string, r *runneryml.Runner) (string, []string, error) {
	policy, err := security.ApplyProjectOverrides(e.base, e.allowKeys, r.Orchestrator.SecurityOverrides)
	if err != nil {
		return "", nil, fmt.Errorf("security: project override invalid: %w", err)
	}
	dir, err := e.g.Render(spawnID, r, policy)
	if err != nil {
		return "", nil, err
	}
	// Stringify the resolved *net.IPNet CIDRs for transport to the kube backend.
	var cidrs []string
	for _, ipnet := range policy.AllowedPrivateCIDRs {
		cidrs = append(cidrs, ipnet.String())
	}
	return dir, cidrs, nil
}

// buildBasePolicy constructs the operator-level base policy:
//  1. Defaults(profile) — preset floor.
//  2. Apply scope-level security_overrides (unrestricted — operator controls the scope).
//
// allKeys is the full set of keys ApplyProjectOverrides handles; passing it
// here gives the operator unrestricted access to all override knobs.
func buildBasePolicy(profile string, scopeOverrides map[string]any, allKeys []string) (security.Policy, error) {
	return security.ApplyProjectOverrides(security.Defaults(profile), allKeys, scopeOverrides)
}

// allOverrideKeys returns the full set of keys that ApplyProjectOverrides
// handles. Used when applying operator-level (unrestricted) scope overrides.
func allOverrideKeys() []string {
	return []string{
		"allow_wildcards",
		"allow_doh",
		"allow_imds",
		"allow_kube_api",
		"allow_private_cidrs",
	}
}

type tokenBucketAdapter struct{ b *state.TokenBucket }

func (t tokenBucketAdapter) TryTake() bool { return t.b.TryTake() }

// filepath_join — local stub to avoid importing path/filepath at the top.
// Kept named in snake_case to avoid colliding with the stdlib import elsewhere.
func filepath_join(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

func upperRuntime(rt string) string {
	out := []byte{}
	for i := 0; i < len(rt); i++ {
		c := rt[i]
		if c == ':' || c == '/' {
			break
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, c)
	}
	return string(out)
}

var seq atomic.Int64

func nextSeq() int64 { return seq.Add(1) }

// productionKubeCtor is the kubeCtor used in the binary. It calls
// kube.NewInCluster() (requires in-cluster service-account credentials) and
// wraps the resulting client in the kube backend.
func productionKubeCtor() (backend.Backend, error) {
	c, err := kube.NewInCluster()
	if err != nil {
		return nil, fmt.Errorf("kube: in-cluster init: %w", err)
	}
	return backendkube.New(c), nil
}

// selectBackend constructs the spawn backend indicated by scope.Backend.
// The kubeCtor parameter is injectable so unit tests can verify the selection
// logic without a real Kubernetes cluster.
//
// Selection rules:
//   - "kube"    → kubeCtor() (error propagated to caller)
//   - "compose" → compose.New(dc)
//   - ""        → normalised to "compose" by config.Validate before this is
//     called, so the empty-string arm is defensive only.
func selectBackend(s *config.Scope, dc docker.Client, kubeCtor func() (backend.Backend, error)) (backend.Backend, error) {
	if s.Backend == "kube" {
		return kubeCtor()
	}
	if dc == nil {
		return nil, errors.New("compose backend requires a Docker client")
	}
	return compose.New(dc), nil
}
