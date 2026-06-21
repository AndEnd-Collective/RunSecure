package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/clock"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/egress"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/server"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
)

//coverage:ignore Run is the production wiring; covered by integration tests
func Run(ctx context.Context, scopePath string) error {
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
	gh, err := github.NewClient(baseURL, s.Auth.PATFile)
	if err != nil {
		return err
	}
	dc, err := docker.NewClient(envOr("DOCKER_HOST", "tcp://socket-proxy:2375"))
	if err != nil {
		return err
	}
	st := state.New()

	// Server (healthz + metrics + snapshot) starts first so /healthz can
	// surface "we're booting" status to docker HEALTHCHECK / k8s probes.
	serverDeps := newServerDeps(st, clk, s.PollIntervalSeconds)
	srv := server.New(":8080", ":8081", serverDeps, em)
	go func() { _ = srv.Run(ctx) }()

	// Cold-start state recovery from docker.
	if listed, err := dc.ListContainersForScope(ctx, s.Name); err == nil {
		orphans := state.RebuildFromDocker(st, listed)
		for _, o := range orphans {
			_ = dc.DeleteContainer(ctx, o.ContainerID, true)
		}
	}

	// Build everything the poll + spawn deps need.
	intentCh := make(chan orchestrator.SpawnIntent, 32)
	// B1 rate limiter — token bucket protecting against unbounded burst.
	// Defaults: 5 tokens/sec sustained, burst 10. The burst allows initial
	// fan-out when the orchestrator first sees a queued backlog; sustained
	// rate prevents a runaway poll loop from spawning thousands.
	rl := state.NewTokenBucket(5, 10, time.Now)
	brks := newBreakerMap()
	eg := egress.NewFSGenerator(envOr("RUNSECURE_EGRESS_BASE_DIR", "/tmp/runsecure/egress"))
	basePolicy, err := buildBasePolicy(s.SecurityProfile, s.SecurityOverrides, allOverrideKeys())
	if err != nil {
		return fmt.Errorf("orchestrator: scope security_overrides invalid: %w", err)
	}
	pdeps := &productionDeps{
		gh:         gh,
		dc:         dc,
		em:         em,
		clk:        clk,
		st:         st,
		eg:         eg,
		basePolicy: basePolicy,
		allowKeys:  s.AllowProjectOverrides,
		bucket:     rl,
		brks:       brks,
		intents:    intentCh,
		scopeRef:   s,
		serverDeps: serverDeps,
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
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for intent := range intentCh {
				_ = worker.Execute(ctx, intent)
			}
		}()
	}

	go poll.Run(ctx)

	// Wait for SIGTERM / SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-ctx.Done():
	case sig := <-sigCh:
		fmt.Fprintln(os.Stderr, "orchestrator: caught", sig, "— draining…")
	}

	// A3 drain: stop polling, wait for in-flight to settle, then force cleanup.
	close(intentCh)
	drainTimeout := envIntOr("RUNSECURE_DRAIN_SECONDS", 60)
	drainDeadline := time.Now().Add(time.Duration(drainTimeout) * time.Second)
	for time.Now().Before(drainDeadline) {
		if st.GlobalInFlight() == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	wg.Wait()
	return nil
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
	st          *state.State
	clk         clock.Clock
	intervalS   int
	lastPoll    atomic.Pointer[time.Time]
	api         sync.Map // server.APICallKey → *int64
	spawns      sync.Map
	breakerSnap func() map[string]bool
}

func newServerDeps(st *state.State, clk clock.Clock, intervalS int) *serverDeps {
	d := &serverDeps{st: st, clk: clk, intervalS: intervalS}
	t := time.Now()
	d.lastPoll.Store(&t)
	return d
}

func (d *serverDeps) LastPollAt() time.Time         { p := d.lastPoll.Load(); if p == nil { return time.Time{} }; return *p }
func (d *serverDeps) Now() time.Time                { return d.clk.Now() }
func (d *serverDeps) PollIntervalSeconds() int      { return d.intervalS }
func (d *serverDeps) StateSnapshot() state.Snapshot { return d.st.Snapshot() }
func (d *serverDeps) APICalls() map[server.APICallKey]int64 {
	out := map[server.APICallKey]int64{}
	d.api.Range(func(k, v any) bool {
		out[k.(server.APICallKey)] = *(v.(*int64))
		return true
	})
	return out
}
func (d *serverDeps) SpawnsTotal() map[server.SpawnKey]int64 {
	out := map[server.SpawnKey]int64{}
	d.spawns.Range(func(k, v any) bool {
		out[k.(server.SpawnKey)] = *(v.(*int64))
		return true
	})
	return out
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
	gh         *github.Client
	dc         docker.Client
	em         *cornerstone.Emitter
	clk        clock.Clock
	st         *state.State
	eg         egress.Generator
	basePolicy security.Policy
	allowKeys  []string
	bucket     *state.TokenBucket
	brks       *breakerMap
	intents    chan orchestrator.SpawnIntent
	scopeRef   *config.Scope
	serverDeps *serverDeps

	// rate-limit state
	rlMu      sync.Mutex
	rlPaused  bool
	rlReset   time.Time
}

// PollDeps and SpawnDeps shared methods.

func (p *productionDeps) GitHub() *github.Client          { return p.gh }
func (p *productionDeps) Docker() docker.Client           { return p.dc }
func (p *productionDeps) Emit() *cornerstone.Emitter      { return p.em }
func (p *productionDeps) Clock() orchestrator.ClockLike   { return p.clk }
func (p *productionDeps) Egress() orchestrator.EgressGenerator {
	return egressShim{g: p.eg, base: p.basePolicy, allowKeys: p.allowKeys}
}
func (p *productionDeps) State() orchestrator.StateLike    { return p.st }

func (p *productionDeps) RunnerYML(repo string) (*orchestrator.RunnerYMLSnapshot, error) {
	for _, r := range p.scopeRef.Repos {
		if r.Repo != repo {
			continue
		}
		yml, err := runneryml.Parse(filepath_join(r.ProjectDir, ".github", "runner.yml"))
		if err != nil {
			return nil, err
		}
		for _, w := range yml.DeprecationWarnings() {
			fmt.Fprintln(os.Stderr, "[RunSecure] WARNING:", w)
		}
		return &orchestrator.RunnerYMLSnapshot{YML: yml}, nil
	}
	return nil, errors.New("unknown repo")
}

// PollDeps-only ------------------------------------------------------------

func (p *productionDeps) InFlight(repo string) int         { return p.st.InFlight(repo) }
func (p *productionDeps) GlobalInFlight() int              { return p.st.GlobalInFlight() }
func (p *productionDeps) BreakerIsOpen(repo string) bool   { return p.brks.IsOpen(repo) }
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
	p.st.SetRateLimit(lim.Remaining, lim.Limit, time.Unix(lim.ResetUnix, 0))
}
func (p *productionDeps) MarkRateLimited(_ string) {
	p.rlMu.Lock()
	p.rlPaused = true
	_, _, r := p.st.RateLimit()
	if r.IsZero() {
		r = time.Now().Add(time.Minute)
	}
	p.rlReset = r
	p.rlMu.Unlock()
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
		return true
	}
	return false
}
func (p *productionDeps) NewSpawnID() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), nextSeq())
}

// RecordPollTick (bug #2 fix) updates the serverDeps freshness signal that
// /healthz reads. Without this, lastPoll is set once at boot and /healthz
// goes red after 3*poll_interval and stays there.
func (p *productionDeps) RecordPollTick() {
	t := time.Now()
	p.serverDeps.lastPoll.Store(&t)
}

// SpawnDeps-only --------------------------------------------------------

func (p *productionDeps) GlobalMaxRunners() int        { return p.scopeRef.GlobalMaxRunners }
func (p *productionDeps) RepoMaxConcurrent(repo string) int {
	for _, r := range p.scopeRef.Repos {
		if r.Repo == repo {
			return r.MaxConcurrent
		}
	}
	return 1
}
func (p *productionDeps) ScopeName() string                       { return p.scopeRef.Name }
func (p *productionDeps) ProxyImageDigest() string                { return os.Getenv("RUNSECURE_PROXY_IMAGE") }
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
func (p *productionDeps) RateLimiter() orchestrator.TokenBucket { return tokenBucketAdapter{b: p.bucket} }
func (p *productionDeps) Breakers() orchestrator.BreakerMap     { return p.brks }

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

func (e egressShim) Render(spawnID string, r *runneryml.Runner) (string, error) {
	policy, err := security.ApplyProjectOverrides(e.base, e.allowKeys, r.Orchestrator.SecurityOverrides)
	if err != nil {
		return "", fmt.Errorf("security: project override invalid: %w", err)
	}
	return e.g.Render(spawnID, r, policy)
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
