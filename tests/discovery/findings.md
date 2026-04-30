# Log-Upload Marker Discovery Findings

**Date:** 2026-04-29
**Method:** Source-based research (actions-runner GitHub repository)
**Status:** PROVISIONAL — empirical verification pending; see "Future empirical verification" below.

## Why source-based?

The original plan called for empirical discovery: build an instrumented entrypoint, trigger workflows against a real GitHub repository, observe `_diag/Worker_*.log` tails. This requires a scratch GitHub repo + `gh` CLI access + actually running workflows. We did not have that infrastructure available for this PR.

The alternative used here: the GitHub actions-runner is open source. Read its source code, identify the log line consistently emitted *after* upload completion, use that as the marker. The risk is that source-derived markers might miss subtle runtime details (timing, exact format). Mitigations: PR3's `entrypoint.sh` has a 30-second timeout (configurable via `RUNSECURE_LOG_UPLOAD_TIMEOUT`) and a host-mounted `_diag/` volume — if the marker is wrong, the wait times out and logs are still recoverable from the host.

## Identified marker

- **Marker string:** `All queue process tasks have been stopped, and all queues are drained.`
- **Source file:** `src/Runner.Common/JobServerQueue.cs` (line ~461)
- **Source URL:** `https://github.com/actions/runner/blob/main/src/Runner.Common/JobServerQueue.cs#L461`
- **Why this string:** It is emitted by `Trace.Info(...)` inside `ShutdownAsync()` only after
  `ProcessFilesUploadQueueAsync`, `ProcessResultsUploadQueueAsync`, and
  `ProcessTimelinesUpdateQueueAsync` have all been awaited to completion, and after both the
  job server and results server have been disposed — making it the last observable evidence
  that every upload queue has been fully drained.

## Upload sequence leading to the marker

Inside `JobServerQueue.ShutdownAsync()`, the sequence is:

1. `"Fire signal to shutdown all queues."` — triggers in-flight work to wrap up
2. `"All queue process task stopped."` — background dequeue tasks have exited
3. `"Web console line queue drained."` — live console lines flushed (best-effort)
4. `"File upload queue drained."` — step log file uploads complete (best-effort)
5. `"Results upload queue drained."` — results service uploads complete
6. `"Timeline update queue drained."` — timeline records (which carry output variables) flushed
7. `"Disposing job server ..."` / `"Disposing results server ..."` — HTTP clients torn down
8. **`"All queue process tasks have been stopped, and all queues are drained."`** <- MARKER

The marker appears at step 8, unconditionally, in every code path through `ShutdownAsync()`.
It is emitted regardless of whether the job succeeded, failed, or was cancelled.

## Log line format in `_diag/Worker_*.log`

Per `src/Runner.Common/HostTraceListener.cs`, each `Trace.Info(...)` call is written as:

```
[<UTC timestamp> INFO <source>] <message>
```

Example of how the marker appears on disk:

```
[2024-05-15 13:42:07Z INFO JobServerQueue] All queue process tasks have been stopped, and all queues are drained.
```

The short distinctive substring to grep for in PR3's `entrypoint.sh`:

```
All queue process tasks have been stopped, and all queues are drained.
```

This substring is 67 characters, highly specific, and unlikely to appear in any workflow stdout.

## Recommendation for PR3

Use the marker string:

```
All queue process tasks have been stopped, and all queues are drained.
```

as the default `RUNSECURE_LOG_UPLOAD_MARKER` in `entrypoint.sh`. The wait loop should:

1. Monitor the most-recent `_diag/Worker_*.log` for the marker via `grep -qF`.
2. Exit the wait when the marker is found OR when `RUNSECURE_LOG_UPLOAD_TIMEOUT` (default 30s) elapses.
3. Proceed with container exit either way.

If the marker is absent within the timeout, proceed with exit; the persistent `_diag/`
host volume preserves logs for operator-side recovery.

Operators who observe BlobNotFound issues with this default can override via the env var
while we collect empirical data.

## Future empirical verification

To confirm the marker empirically, an operator with a scratch GitHub repository should:

1. Build the runner image with the instrumented entrypoint (`infra/scripts/entrypoint.discovery.sh`):

   ```bash
   docker build -f images/base.Dockerfile -t runner-base:latest .
   docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .
   # Build a one-off discovery image:
   docker build -f - -t runner-discovery:24 . <<'EOF'
   FROM runner-node:24
   COPY infra/scripts/entrypoint.discovery.sh /home/runner/entrypoint.sh
   USER 1001
   ENTRYPOINT ["/home/runner/entrypoint.sh"]
   EOF
   ```

2. Push the three workflow files in `tests/discovery/` to a scratch GitHub repo under `.github/workflows/`. Commit and push.

3. Run each workflow and the orchestrator:

   ```bash
   gh workflow run discovery-success.yml -R <owner>/<repo>
   RUNNER_IMAGE=runner-discovery:24 ./infra/scripts/run.sh --project /tmp/discovery-project --repo <owner>/<repo> --no-proxy 2>&1 | tee tests/discovery/run-success.log
   # Repeat for workflow-failure.yml and workflow-multistep.yml
   ```

4. Inspect the captured `_diag/Worker_*.log` tail (the instrumented entrypoint prints 200 lines).
   Confirm the marker `All queue process tasks have been stopped, and all queues are drained.`
   is present in all three runs, and note its position relative to the end of the file.

5. Time `gh api .../jobs/<id>/logs` until 200 to verify the marker truly indicates upload completion:

   ```bash
   JOB_ID=$(gh run list -R <owner>/<repo> --workflow=discovery-failure.yml --limit 1 --json databaseId --jq '.[0].databaseId')
   for i in 1 2 3 5 10 20 30; do
     sleep 1
     STATUS=$(gh api "repos/<owner>/<repo>/actions/runs/$JOB_ID/logs" 2>&1 | head -1)
     echo "T+${i}s: $STATUS"
   done
   ```

   If `gh api` returns 200 at or before the marker appears, the marker is conservative (safe).
   If `gh api` returns 200 only after the marker, the marker is the binding signal.
   If `gh api` never returns 200, there is a deeper infrastructure issue.

6. Update this file with empirical results and remove the "PROVISIONAL" tag from the Status line.
