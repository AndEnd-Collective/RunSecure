package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
)

// egressNetworkFallback is the fallback egress network name used when
// RUNSECURE_EGRESS_NETWORK is not set in the environment. The compose stack
// sets RUNSECURE_EGRESS_NETWORK to "${RUNSECURE_SCOPE}-spawn-egress"; this
// constant covers bare docker / integration-test environments that do not run
// through compose.
const egressNetworkFallback = "runsecure-egress"

// egressNetworkName returns the Docker network name the proxy container is
// attached to for outbound internet access. It reads RUNSECURE_EGRESS_NETWORK
// from the environment (set by compose.scope.yml) and falls back to the
// well-known constant for non-compose deployments.
//
// The runner is never attached to this network — it reaches the internet only
// through the proxy on the internal network.
func egressNetworkName() string {
	if v := os.Getenv("RUNSECURE_EGRESS_NETWORK"); v != "" {
		return v
	}
	return egressNetworkFallback
}

// EgressMountPath is the path the shared egress-configs volume is mounted at
// inside the proxy container. Re-exported from internal/backend for callers
// (run.go, integration tests) that import the orchestrator package rather than
// backend directly. The canonical definition lives in backend.EgressMountPath
// to avoid duplicating the string literal across packages.
const EgressMountPath = backend.EgressMountPath

// egressVolumeName returns the name of the shared named Docker volume that
// carries per-spawn egress configs. It reads RUNSECURE_EGRESS_VOLUME from the
// environment (set by compose.scope.yml). Unlike egressNetworkName there is no
// hardcoded fallback: an empty value means the socket-proxy's volume gate is
// fail-closed and no proxy volume mount will be permitted, surfacing a
// misconfiguration loudly rather than silently mounting the wrong volume.
func egressVolumeName() string {
	return os.Getenv("RUNSECURE_EGRESS_VOLUME")
}

// SpawnWorker is the per-intent worker. One instance is shared by all
// goroutines in the spawn-worker pool.
type SpawnWorker struct {
	deps SpawnDeps
}

// NewSpawnWorker constructs a worker.
func NewSpawnWorker(deps SpawnDeps) *SpawnWorker {
	return &SpawnWorker{deps: deps}
}

// Execute runs spec §5.2 steps 0-7 for one spawn intent. Returns nil on
// success or a wrapped error on failure (in either case, the result is
// also reported via Cornerstone events).
func (w *SpawnWorker) Execute(ctx context.Context, intent SpawnIntent) error {
	// Pre-step: B1 rate limit. Defensive — the poll loop already shaped the
	// stream, but a misconfigured pool could still try to spawn faster than
	// the bucket allows. Emit spawn.failed on deny so a rate-limited backlog
	// is visible to operators and the test suite rather than silently dropped.
	if !w.deps.RateLimiter().TryTake() {
		_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			FailureReason: "spawn_rate_limited",
			Detail:        "B1 token bucket denied — backlog larger than burst",
		})
		return ErrRateLimitBackoff
	}

	// Step 0: acquire semaphores. Defensive — poll loop already filtered, but
	// a race between two workers picking up adjacent intents could collide.
	if !w.deps.State().AcquireSemaphores(intent.Repo,
		w.deps.RepoMaxConcurrent(intent.Repo),
		w.deps.GlobalMaxRunners()) {
		return ErrSemaphoreUnavailable
	}
	defer w.deps.State().ReleaseSemaphores(intent.Repo)

	containerName := fmt.Sprintf("rs-%s-runner", intent.SpawnID)

	// Load runner.yml (cached per-repo by deps).
	snapshot, err := w.deps.RunnerYML(intent.Repo)
	if err != nil {
		return w.fail(intent, containerName, "runner_yml_parse", err)
	}
	if err := snapshot.YML.ValidateEgress(); err != nil {
		return w.fail(intent, containerName, "runner_yml_parse", err)
	}
	imageDigest := snapshot.ImageDigest
	if imageDigest == "" {
		// Fall back to the deps lookup keyed on runtime string.
		imageDigest = w.deps.RunnerImageDigestFor(snapshot.YML.Runtime)
	}

	_ = w.deps.Emit().EmitSpawnStarted(cornerstone.SpawnStartedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName, ImageDigest: imageDigest,
	})

	// Step 1: generate JIT.
	jit, err := w.deps.GitHub().GenerateJITConfig(ctx, intent.Repo, github.JITConfigRequest{
		Name:   containerName,
		Labels: snapshot.YML.Labels,
	})
	if err != nil {
		reason := classifyJITError(err)
		w.recordFailureAndMaybeEmit(intent.Scope, intent.Repo)
		return w.fail(intent, containerName, reason, err)
	}
	_ = w.deps.Emit().EmitSpawnJITAcquired(cornerstone.SpawnJITAcquiredFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName, GitHubRunnerID: jit.RunnerID,
	})

	// Step 2: generate per-spawn egress configs.
	// Render also returns the resolved operator-approved private CIDRs so they
	// can be threaded into SpawnInput for kube backend L3 enforcement.
	egressDir, allowedPrivateCIDRs, err := w.deps.Egress().Render(intent.SpawnID, snapshot.YML)
	if err != nil {
		w.recordFailureAndMaybeEmit(intent.Scope, intent.Repo)
		return w.failAndLeak(ctx, intent, containerName, "egress_render", err, jit.RunnerID)
	}

	// Steps 3-5: delegate network creation + container spawn to the backend.
	// The backend owns network creation, container creation/start, and rollback
	// on partial failure. This replaces the CreateNetwork→docker.Spawn block
	// that previously lived here; the compose backend replicates that exact
	// behavior. The netName used for the runner_created event is derived the
	// same way as before so the event payload is byte-for-byte identical.
	memBytes, nanoCPUs := parseResources(snapshot.YML.Resources.Memory, snapshot.YML.Resources.CPUs)
	r := snapshot.YML
	// EnableDNSMasq when dns.host is explicitly set to false, meaning the
	// project wants the proxy to resolve DNS rather than using the host resolver.
	enableDNSMasq := r.DNS.Host != nil && !*r.DNS.Host

	// Parse port numbers from TCPEgress entries (format "host:port").
	tcpEgressPorts := make([]int, 0, len(r.TCPEgress))
	for _, entry := range r.TCPEgress {
		colon := strings.LastIndex(entry, ":")
		if colon < 0 {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(entry[colon+1:], "%d", &port); err == nil && port > 0 {
			tcpEgressPorts = append(tcpEgressPorts, port)
		}
	}

	spawnIn := backend.SpawnInput{
		Scope:               intent.Scope,
		Repo:                intent.Repo,
		SpawnID:             intent.SpawnID,
		RunnerImage:         imageDigest,
		ProxyImage:          w.deps.ProxyImageDigest(),
		SeccompProfilePath:  w.deps.SeccompProfileHostPath(r.Orchestrator.SeccompProfile),
		ResourcesMemory:     memBytes,
		ResourcesNanoCPUs:   nanoCPUs,
		ResourcesPIDs:       int64(r.Resources.PIDs),
		JITConfigB64:        jit.EncodedJITConfig,
		EgressConfigDir:     egressDir,
		EgressNetwork:       egressNetworkName(),
		EgressVolume:        egressVolumeName(),
		EnableDNSMasq:       enableDNSMasq,
		TCPEgressPorts:      tcpEgressPorts,
		AllowedPrivateCIDRs: allowedPrivateCIDRs,
	}
	h, err := w.deps.Backend().Spawn(ctx, spawnIn)
	if err != nil {
		w.recordFailureAndMaybeEmit(intent.Scope, intent.Repo)
		return w.failAndLeak(ctx, intent, containerName, classifyDockerError(err), err, jit.RunnerID)
	}

	// State counter is bumped here (Acquire already incremented; this just
	// transitions ownership conceptually — the counter stays at +1 until
	// teardown decrements it via ReleaseSemaphores in the defer).
	_ = w.deps.Emit().EmitSpawnRunnerCreated(cornerstone.SpawnRunnerCreatedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName, ImageDigest: imageDigest,
		// NetworkName must be the human-readable network name (as before the
		// backend refactor), not the opaque network ID. The compose backend
		// surfaces it in Refs["network_name"] = "rs-net-<repo>-<spawnID>".
		NetworkName: h.Refs["network_name"],
	})

	// Step 6: wait for exit OR wall-clock timeout (A2).
	start := w.deps.Clock().Now()
	timeoutSecs := defaultTimeoutSeconds(snapshot.YML.Orchestrator.TimeoutSeconds)
	timeout := secondsToDuration(timeoutSecs)
	exitCode, timedOut := w.deps.Backend().WaitForExit(ctx, h, timeout)

	// Step 7: teardown.
	_ = w.deps.Backend().Teardown(ctx, h, timedOut)

	if timedOut {
		elapsed := int(w.deps.Clock().Now().Sub(start).Seconds())
		_ = w.deps.Emit().EmitSpawnTimeoutForcedTeardown(cornerstone.SpawnTimeoutForcedTeardownFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerName:         containerName,
			ConfiguredTimeoutSecs: timeoutSecs,
			ElapsedSeconds:        elapsed,
		})
		w.recordFailureAndMaybeEmit(intent.Scope, intent.Repo)
		return errors.New("spawn timed out")
	}

	durationMs := w.deps.Clock().Now().Sub(start).Milliseconds()
	runnerContainerID := h.Refs["runner"]
	if exitCode == 0 {
		w.recordSuccessAndMaybeEmit(intent.Scope, intent.Repo)
		_ = w.deps.Emit().EmitSpawnCompleted(cornerstone.SpawnCompletedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerID: runnerContainerID, ContainerName: containerName,
			ImageDigest: imageDigest, ExitCode: exitCode, DurationMillis: durationMs,
		})
		return nil
	}
	w.recordFailureAndMaybeEmit(intent.Scope, intent.Repo)
	_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName,
		FailureReason: "runner_nonzero_exit",
		Detail:        fmt.Sprintf("exit_code=%d", exitCode),
	})
	return fmt.Errorf("runner exited %d", exitCode)
}

// fail emits spawn.failed and returns the error. Used for failures BEFORE
// JIT generation (no leak cleanup needed).
func (w *SpawnWorker) fail(intent SpawnIntent, containerName, reason string, err error) error {
	_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName,
		FailureReason: reason,
		Detail:        err.Error(),
	})
	return err
}

// failAndLeak — used AFTER JIT is acquired but before runner starts claiming
// a job. Implements A1: delete the orphan runner registration.
func (w *SpawnWorker) failAndLeak(ctx context.Context, intent SpawnIntent, containerName, reason string, err error, runnerID int64) error {
	if runnerID > 0 {
		if delErr := w.deps.GitHub().DeleteRunner(ctx, intent.Repo, runnerID); delErr == nil {
			_ = w.deps.Emit().EmitRunnerLeakCleaned(cornerstone.RunnerLeakCleanedFields{
				Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
				GitHubRunnerID: runnerID,
			})
		}
	}
	return w.fail(intent, containerName, reason, err)
}

// recordFailureAndMaybeEmit calls the breaker's RecordFailure and emits
// breaker.opened on the open transition (FIX for bug #1: the events were
// previously never emitted because the return values were dropped).
func (w *SpawnWorker) recordFailureAndMaybeEmit(scope, repo string) {
	opened, consecutive := w.deps.Breakers().RecordFailure(repo)
	if opened {
		_ = w.deps.Emit().EmitBreakerOpened(cornerstone.BreakerFields{
			Scope: scope, Repo: repo, ConsecutiveFailures: consecutive,
		})
	}
}

// recordSuccessAndMaybeEmit calls RecordSuccess and emits breaker.closed
// only when the breaker just transitioned from a non-Closed state.
func (w *SpawnWorker) recordSuccessAndMaybeEmit(scope, repo string) {
	if closed := w.deps.Breakers().RecordSuccess(repo); closed {
		_ = w.deps.Emit().EmitBreakerClosed(cornerstone.BreakerFields{
			Scope: scope, Repo: repo,
		})
	}
}

func classifyJITError(err error) string {
	switch {
	case errors.Is(err, github.ErrJITLabelMismatch):
		return "jit_label_mismatch"
	case errors.Is(err, github.ErrAuthFailed):
		return "github_auth_failed"
	case errors.Is(err, github.ErrRateLimited):
		return "github_rate_limited"
	default:
		return "github_jit_failed"
	}
}

func classifyDockerError(err error) string {
	if errors.Is(err, docker.ErrPolicyDenied) {
		return "socket_proxy_denied"
	}
	return "docker_error"
}

// parseResources converts runner.yml's memory string ("8g", "512m") and
// CPU count (int) into docker's bytes + nanocpus form.
//
// The switch's default case handles unknown units, which removes the
// `if mul > 0` paranoia branch (and its equivalent boundary mutant).
func parseResources(mem string, cpus int) (int64, int64) {
	nanoCPUs := int64(cpus) * 1_000_000_000
	if len(mem) < 2 {
		return 0, nanoCPUs
	}
	var mul int64
	switch mem[len(mem)-1] {
	case 'g', 'G':
		mul = 1 << 30
	case 'm', 'M':
		mul = 1 << 20
	case 'k', 'K':
		mul = 1 << 10
	default:
		return 0, nanoCPUs
	}
	var n int64
	fmt.Sscanf(mem[:len(mem)-1], "%d", &n)
	return n * mul, nanoCPUs
}

// secondsToDuration converts a non-negative whole-second count into a
// time.Duration. Extracted so mutation testing can directly assert the
// multiplication operator with an exact-value test, and so the runner
// timeout arithmetic is observable from unit tests.
func secondsToDuration(s int) time.Duration {
	return time.Duration(s) * time.Second
}

// waitForExitPollInterval is the cadence at which waitForExit re-inspects
// the runner container while waiting for it to transition to "exited".
// Extracted so mutation testing observes the multiplication operator.
func waitForExitPollInterval() time.Duration {
	return 1 * time.Second
}

// defaultTimeoutSeconds returns the runner timeout in seconds, applying
// the 6-hour fallback when the configured value is non-positive.
// Extracted so mutation testing can directly observe the `<= 0` boundary.
func defaultTimeoutSeconds(s int) int {
	if s <= 0 {
		return 21600 // 6h
	}
	return s
}
