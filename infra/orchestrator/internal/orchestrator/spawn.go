package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

const (
	runnerOperationGenerateJIT   = "generate_jit_config"
	runnerOperationGetRunner     = "get_runner"
	runnerOperationGetJob        = "get_workflow_job"
	runnerOperationFindRecentJob = "find_recent_workflow_job"
	runnerOperationDelete        = "delete_runner"
	// JITOwnerLabel and JITScopeLabelPrefix make a registration discoverable
	// after both the worker process and its backend resources are gone.
	JITOwnerLabel                 = "runsecure-jit"
	JITScopeLabelPrefix           = "runsecure-scope-"
	cleanupAuthRetryInterval      = 30 * time.Second
	cleanupRateLimitRetryInterval = time.Minute
)

func jitRunnerLabels(scope string, configured []string) []string {
	labels := make([]string, 0, len(configured)+2)
	seen := make(map[string]bool, len(configured)+2)
	for _, label := range append(append([]string(nil), configured...),
		JITOwnerLabel, JITScopeLabelPrefix+scope) {
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		labels = append(labels, label)
	}
	return labels
}

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
	// Poll normally creates the reservation before enqueueing. The defensive
	// TryReserve keeps direct callers fail-closed without double-counting an
	// existing reservation.
	if !w.deps.State().HasReservation(intent.SpawnID, intent.Repo) &&
		!w.deps.State().TryReserve(intent.SpawnID, intent.Repo,
			w.deps.RepoMaxConcurrent(intent.Repo), w.deps.GlobalMaxRunners(), w.deps.Clock().Now()) {
		return ErrSemaphoreUnavailable
	}
	defer w.deps.State().ReleaseReservation(intent.SpawnID)
	if w.deps.State().SchedulingBlocked() {
		return ErrSchedulingBlocked
	}

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

	containerName := fmt.Sprintf("rs-%s-runner", intent.SpawnID)

	// Load runner.yml (cached per-repo by deps).
	snapshot, err := w.deps.RunnerYMLContext(ctx, intent.Repo)
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
		Labels: jitRunnerLabels(intent.Scope, snapshot.YML.Labels),
	})
	w.recordRunnerOperation(intent.Repo, runnerOperationGenerateJIT, err)
	if err != nil {
		reason := classifyJITError(err)
		w.pauseForRateLimit(intent.Scope, err)
		if jit.RunnerID > 0 {
			// GitHub creates the runner before the response can fail local
			// validation. Preserve its identity and clean it exactly like every
			// other post-JIT failure.
			w.deps.State().RecordJIT(intent.SpawnID, jit.RunnerID, containerName)
			return w.failAndLeak(ctx, intent, containerName, reason, err, jit.RunnerID)
		}
		return w.fail(intent, containerName, reason, err)
	}
	_ = w.deps.Emit().EmitSpawnJITAcquired(cornerstone.SpawnJITAcquiredFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName, GitHubRunnerID: jit.RunnerID,
	})
	w.deps.State().RecordJIT(intent.SpawnID, jit.RunnerID, containerName)

	// Step 2: generate per-spawn egress configs.
	// Render also returns the resolved operator-approved private CIDRs so they
	// can be threaded into SpawnInput for kube backend L3 enforcement.
	egressDir, allowedPrivateCIDRs, err := w.deps.Egress().Render(intent.SpawnID, snapshot.YML)
	if err != nil {
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
		var port int
		if _, err := fmt.Sscanf(entry[colon+1:], "%d", &port); err == nil && port > 0 {
			tcpEgressPorts = append(tcpEgressPorts, port)
		}
	}

	spawnIn := backend.SpawnInput{
		Scope:                intent.Scope,
		Repo:                 intent.Repo,
		SpawnID:              intent.SpawnID,
		Version:              w.deps.Version(),
		BuildSHA:             w.deps.BuildSHA(),
		RunnerImage:          imageDigest,
		ProxyImage:           w.deps.ProxyImageDigest(),
		SeccompProfilePath:   w.deps.SeccompProfileHostPath(r.Orchestrator.SeccompProfile),
		ResourcesMemory:      memBytes,
		ResourcesNanoCPUs:    nanoCPUs,
		ResourcesPIDs:        int64(r.Resources.PIDs),
		JITConfigB64:         jit.EncodedJITConfig,
		EgressConfigDir:      egressDir,
		EgressNetwork:        egressNetworkName(),
		EgressVolume:         egressVolumeName(),
		EnableDNSMasq:        enableDNSMasq,
		TCPEgressPorts:       tcpEgressPorts,
		KubeDNSServiceCIDRs:  strings.Split(os.Getenv("RUNSECURE_KUBE_DNS_SERVICE_CIDRS"), ","),
		KubeDNSNamespace:     os.Getenv("RUNSECURE_KUBE_DNS_NAMESPACE"),
		KubeDNSPodLabelKey:   os.Getenv("RUNSECURE_KUBE_DNS_POD_LABEL_KEY"),
		KubeDNSPodLabelValue: os.Getenv("RUNSECURE_KUBE_DNS_POD_LABEL_VALUE"),
		AllowedPrivateCIDRs:  allowedPrivateCIDRs,
	}
	h, err := w.deps.Backend().Spawn(ctx, spawnIn)
	if err != nil {
		if h.Backend != "" {
			// A non-empty handle on failure means backend rollback was not
			// proven complete. Retry that exact handle and the JIT registration
			// under one retained reservation.
			cleanupResult := w.settlePartialSpawn(
				ctx, intent, containerName, h, err, jit.RunnerID,
			)
			if !w.deps.State().HasReservation(intent.SpawnID, intent.Repo) {
				_ = w.deps.Emit().EmitRunnerLeakCleaned(cornerstone.RunnerLeakCleanedFields{
					Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
					GitHubRunnerID: jit.RunnerID,
				})
			}
			return w.fail(intent, containerName, classifyDockerError(err), cleanupResult)
		}
		return w.failAndLeak(ctx, intent, containerName, classifyDockerError(err), err, jit.RunnerID)
	}

	// The pending reservation now represents a live runner. It remains counted
	// against repository and global capacity until the deferred release runs.
	_ = w.deps.Emit().EmitSpawnRunnerCreated(cornerstone.SpawnRunnerCreatedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName, ImageDigest: imageDigest,
		// NetworkName must be the human-readable network name (as before the
		// backend refactor), not the opaque network ID. The compose backend
		// surfaces it in Refs["network_name"] = "rs-net-<repo>-<spawnID>".
		NetworkName: h.Refs["network_name"],
	})

	// Step 6: observe GitHub delivery while waiting for process exit. A runner
	// that exits zero without ever being assigned is a runtime failure.
	start := w.deps.Clock().Now()
	timeoutSecs := defaultTimeoutSeconds(snapshot.YML.Orchestrator.TimeoutSeconds)
	timeout := secondsToDuration(timeoutSecs)
	lifecycle := w.waitForLifecycle(ctx, intent, containerName, jit.RunnerID, h, timeout)
	exitCode, timedOut := lifecycle.exitCode, lifecycle.timedOut
	durationMs := w.deps.Clock().Now().Sub(start).Milliseconds()
	runnerContainerID := h.Refs["runner"]
	if lifecycle.err == nil && !timedOut {
		// Runner delivery completed when the assigned runner process exited.
		// Record that fact before backend/GitHub cleanup so teardown latency or
		// failure cannot rewrite the job-delivery outcome or its duration.
		w.deps.State().RecordCompleted()
		_ = w.deps.Emit().EmitRunnerCompleted(cornerstone.RunnerCompletedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerName: containerName, GitHubRunnerID: jit.RunnerID,
			ExitCode: exitCode, DurationMillis: durationMs,
		})
	}

	// Step 7: teardown. Lifecycle failures are force conditions, and cleanup
	// always receives a fresh bounded context so cancellation cannot leak the
	// runner/proxy resources.
	teardownErr := teardownSpawn(ctx, w.deps.Backend(), h, timedOut || lifecycle.err != nil)
	deregisterErr := w.deregister(ctx, intent.Repo, jit.RunnerID)

	if lifecycle.err != nil {
		w.pauseForRateLimit(intent.Scope, lifecycle.err)
		if lifecycle.unassigned {
			w.deps.State().RecordUnassignedExit()
		}
		cleanupResult := w.settleCleanup(
			ctx, intent, containerName, h, teardownErr, deregisterErr,
			lifecycle.err, lifecycle.failureReason, jit.RunnerID,
		)
		return w.fail(intent, containerName, lifecycle.failureReason, cleanupResult)
	}

	if timedOut {
		timeoutErr := errors.New("spawn timed out")
		cleanupResult := w.settleCleanup(
			ctx, intent, containerName, h, teardownErr, deregisterErr,
			timeoutErr, "wall_clock_timeout", jit.RunnerID,
		)
		elapsed := int(w.deps.Clock().Now().Sub(start).Seconds())
		_ = w.deps.Emit().EmitSpawnTimeoutForcedTeardown(cornerstone.SpawnTimeoutForcedTeardownFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerName:         containerName,
			ConfiguredTimeoutSecs: timeoutSecs,
			ElapsedSeconds:        elapsed,
		})
		return cleanupResult
	}
	if teardownErr != nil {
		return w.settleCleanup(
			ctx, intent, containerName, h, teardownErr, deregisterErr,
			nil, "", jit.RunnerID,
		)
	}
	if deregisterErr != nil {
		cleanupResult := w.settleCleanup(
			ctx, intent, containerName, h, nil, deregisterErr,
			nil, "", jit.RunnerID,
		)
		return w.fail(intent, containerName, "runner_deregistration_failed", cleanupResult)
	}

	if exitCode == 0 {
		_ = w.deps.Emit().EmitSpawnCompleted(cornerstone.SpawnCompletedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerID: runnerContainerID, ContainerName: containerName,
			ImageDigest: imageDigest, ExitCode: exitCode, DurationMillis: durationMs,
		})
		return nil
	}
	_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName,
		FailureReason: "runner_nonzero_exit",
		Detail:        fmt.Sprintf("exit_code=%d", exitCode),
	})
	return fmt.Errorf("runner exited %d", exitCode)
}

func (w *SpawnWorker) settlePartialSpawn(
	ctx context.Context,
	intent SpawnIntent,
	containerName string,
	h backend.Handle,
	spawnErr error,
	runnerID int64,
) error {
	// The backend has already reported an incomplete rollback. Convert the
	// reservation to global admission debt before the first exact retry so a
	// concurrent poll cannot race cleanup.
	w.blockTeardown(intent, containerName, spawnErr, classifyDockerError(spawnErr))
	backendErr := teardownSpawn(ctx, w.deps.Backend(), h, true)
	runnerErr := w.deregister(ctx, intent.Repo, runnerID)
	result := spawnErr
	if backendErr != nil {
		result = errors.Join(result, fmt.Errorf("backend teardown failed: %w", backendErr))
	}
	if runnerErr != nil {
		result = errors.Join(result, fmt.Errorf("runner deregistration failed: %w", runnerErr))
		w.blockRunnerCleanup(intent, containerName, result)
	}
	if backendErr != nil {
		if retryErr := w.retryBackendTeardown(ctx, intent, h); retryErr != nil {
			return errors.Join(result, retryErr)
		}
	}
	if runnerErr != nil {
		if retryErr := w.retryRunnerDeletion(ctx, intent, runnerID, runnerErr); retryErr != nil {
			return errors.Join(result, retryErr)
		}
	}
	w.deps.State().ResolveTeardown(intent.SpawnID)
	return result
}

// teardownSpawn never reuses a cancelled run context for cleanup. Docker and
// Kubernetes clients reject requests immediately when handed that context,
// which previously left runner/proxy resources behind during forced shutdown.
// Context cancellation is itself a force condition because WaitForExit returns
// without observing a normal runner exit.
func teardownSpawn(runCtx context.Context, be backend.Backend, h backend.Handle, timedOut bool) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), teardownGracePeriod())
	defer cancel()
	return be.Teardown(cleanupCtx, h, timedOut || runCtx.Err() != nil)
}

func teardownGracePeriod() time.Duration { return 15 * time.Second }

func (w *SpawnWorker) blockTeardown(
	intent SpawnIntent,
	containerName string,
	err error,
	priorFailureReason string,
) {
	if !w.deps.State().MarkTeardownBlocked(
		intent.SpawnID, intent.Repo, err.Error(), w.deps.Clock().Now(),
	) {
		return
	}
	extra := map[string]any{
		"backend":            w.deps.Backend().Name(),
		"capacity_retained":  true,
		"scheduling_blocked": true,
		"recovery":           "exact_teardown_retry",
	}
	if priorFailureReason != "" {
		extra["prior_failure_reason"] = priorFailureReason
	}
	_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName:  containerName,
		FailureReason:  "backend_teardown_failed",
		Detail:         err.Error(),
		ExtraErrorData: extra,
	})
}

func (w *SpawnWorker) blockRunnerCleanup(
	intent SpawnIntent,
	containerName string,
	err error,
) {
	w.deps.State().MarkTeardownBlocked(
		intent.SpawnID, intent.Repo, err.Error(), w.deps.Clock().Now(),
	)
	_ = w.deps.Emit().EmitSpawnFailed(cornerstone.SpawnFailedFields{
		Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
		ContainerName: containerName,
		FailureReason: "runner_deregistration_failed",
		Detail:        err.Error(),
		ExtraErrorData: map[string]any{
			"cleanup_target":     "github_runner_registration",
			"capacity_retained":  true,
			"scheduling_blocked": true,
			"recovery":           "exact_runner_deregistration_retry",
		},
	})
}

// settleCleanup turns every failed backend or GitHub cleanup into capacity
// debt before retrying the exact resources. The reservation is resolved only
// after every outstanding cleanup succeeds.
func (w *SpawnWorker) settleCleanup(
	ctx context.Context,
	intent SpawnIntent,
	containerName string,
	h backend.Handle,
	backendErr error,
	runnerErr error,
	originalErr error,
	priorFailureReason string,
	runnerID int64,
) error {
	result := originalErr
	if backendErr != nil {
		result = errors.Join(result, fmt.Errorf("backend teardown failed: %w", backendErr))
	}
	if runnerErr != nil {
		result = errors.Join(result, fmt.Errorf("runner deregistration failed: %w", runnerErr))
	}
	if backendErr == nil && runnerErr == nil {
		return result
	}
	if backendErr != nil {
		w.blockTeardown(intent, containerName, result, priorFailureReason)
	}
	if runnerErr != nil {
		w.blockRunnerCleanup(intent, containerName, result)
	}
	if backendErr != nil {
		if err := w.retryBackendTeardown(ctx, intent, h); err != nil {
			return errors.Join(result, err)
		}
	}
	if runnerErr != nil {
		if err := w.retryRunnerDeletion(ctx, intent, runnerID, runnerErr); err != nil {
			return errors.Join(result, err)
		}
	}
	w.deps.State().ResolveTeardown(intent.SpawnID)
	return result
}

func (w *SpawnWorker) retryBackendTeardown(
	ctx context.Context,
	intent SpawnIntent,
	h backend.Handle,
) error {
	retryInterval := normalizedLifecycleTiming(w.deps.LifecycleTiming()).CleanupRetryInterval
	for {
		retryErr := teardownSpawn(ctx, w.deps.Backend(), h, true)
		if retryErr == nil {
			return nil
		}
		w.deps.State().UpdateTeardownFailure(intent.SpawnID, retryErr.Error())
		select {
		case <-ctx.Done():
			return fmt.Errorf("teardown reconciliation interrupted: %w", ctx.Err())
		case <-w.deps.Clock().After(retryInterval):
		}
	}
}

func (w *SpawnWorker) retryRunnerDeletion(
	ctx context.Context,
	intent SpawnIntent,
	runnerID int64,
	initialErr error,
) error {
	retryInterval := normalizedLifecycleTiming(w.deps.LifecycleTiming()).CleanupRetryInterval
	err := initialErr
	first := true
	for {
		w.deps.State().UpdateTeardownFailure(intent.SpawnID, err.Error())
		w.pauseForRateLimit(intent.Scope, err)
		if !first || errors.Is(err, github.ErrAuthFailed) || errors.Is(err, github.ErrRateLimited) {
			delay := w.runnerDeletionRetryDelay(intent.Scope, err, retryInterval)
			select {
			case <-ctx.Done():
				return fmt.Errorf("runner deregistration reconciliation interrupted: %w", ctx.Err())
			case <-w.deps.Clock().After(delay):
			}
		}
		first = false
		err = w.deregister(ctx, intent.Repo, runnerID)
		if err == nil {
			return nil
		}
	}
}

func (w *SpawnWorker) runnerDeletionRetryDelay(
	scope string,
	err error,
	base time.Duration,
) time.Duration {
	if errors.Is(err, github.ErrAuthFailed) && base < cleanupAuthRetryInterval {
		return cleanupAuthRetryInterval
	}
	if !errors.Is(err, github.ErrRateLimited) {
		return base
	}
	_, _, reset := w.deps.RateLimitContextFor(scope)
	resetAt, parseErr := time.Parse(time.RFC3339, reset)
	if parseErr != nil {
		return max(base, cleanupRateLimitRetryInterval)
	}
	delay := resetAt.Sub(w.deps.Clock().Now())
	if delay < base {
		return base
	}
	return delay
}

func (w *SpawnWorker) deregister(ctx context.Context, repo string, runnerID int64) error {
	if runnerID <= 0 {
		return nil
	}
	cleanupCtx, cancel := runnerCleanupContext(ctx)
	defer cancel()
	err := w.deps.GitHub().DeleteRunner(cleanupCtx, repo, runnerID)
	w.recordRunnerOperation(repo, runnerOperationDelete, err)
	if err != nil {
		return err
	}
	w.deps.State().RecordDeregistered()
	return nil
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
	if runnerID <= 0 {
		return w.fail(intent, containerName, reason, err)
	}
	deregisterErr := w.deregister(ctx, intent.Repo, runnerID)
	if deregisterErr != nil {
		err = w.settleCleanup(
			ctx, intent, containerName, backend.Handle{}, nil, deregisterErr,
			err, reason, runnerID,
		)
	}
	if deregisterErr == nil || !w.deps.State().HasReservation(intent.SpawnID, intent.Repo) {
		_ = w.deps.Emit().EmitRunnerLeakCleaned(cornerstone.RunnerLeakCleanedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			GitHubRunnerID: runnerID,
		})
	}
	return w.fail(intent, containerName, reason, err)
}

func (w *SpawnWorker) recordRunnerOperation(repo, operation string, err error) {
	switch {
	case err == nil:
		w.deps.State().RecordRunnerOperationSuccess(repo, operation)
	case operation == runnerOperationGetRunner && errors.Is(err, github.ErrRunnerNotFound):
		w.deps.State().RecordRunnerOperationSuccess(repo, operation)
	case operation == runnerOperationGetJob && github.ErrorStatus(err) == 404:
		w.deps.State().RecordRunnerOperationSuccess(repo, operation)
	default:
		w.deps.State().RecordRunnerOperationFailure(
			repo, operation, classifyRunnerOperationError(err), err.Error(),
		)
	}
}

func classifyRunnerOperationError(err error) string {
	switch {
	case errors.Is(err, github.ErrJITLabelMismatch):
		return "github_jit_label_mismatch"
	case errors.Is(err, github.ErrAuthFailed):
		return "github_auth_failed"
	case errors.Is(err, github.ErrRateLimited):
		return "github_rate_limited"
	case github.ErrorStatus(err) == http.StatusUnprocessableEntity:
		return "github_jit_unavailable"
	default:
		return "github_runner_operation_failed"
	}
}

// runnerCleanupContext bounds GitHub cleanup independently from the worker
// context. Shutdown cancels workers only after the drain deadline; reusing that
// cancelled context would make DeleteRunner fail immediately and leave an
// orphaned JIT registration.
func runnerCleanupContext(context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), teardownGracePeriod())
}

func (w *SpawnWorker) pauseForRateLimit(scope string, err error) {
	if !errors.Is(err, github.ErrRateLimited) {
		return
	}
	w.deps.RecordRateLimit(scope, github.ErrorRateLimit(err))
	if !w.deps.MarkRateLimited(scope) {
		return
	}
	remaining, limit, reset := w.deps.RateLimitContextFor(scope)
	_ = w.deps.Emit().EmitRatelimitPaused(cornerstone.RateLimitFields{
		Scope: scope, Remaining: remaining, Limit: limit, ResetISO: reset,
	})
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
