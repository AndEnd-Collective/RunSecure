# Log-Upload Marker Discovery Findings

**Date:** 2026-04-29
**Method:** Source-based research (actions-runner GitHub repository)
**Status:** EMPIRICALLY CORRECTED — the marker proves local queue drain only;
it does not prove remote log persistence.

## Why source-based?

The original plan called for empirical discovery: build an instrumented entrypoint, trigger workflows against a real GitHub repository, observe `_diag/Worker_*.log` tails. This requires a scratch GitHub repo + `gh` CLI access + actually running workflows. We did not have that infrastructure available for this PR.

The alternative used here: the GitHub actions-runner is open source. Its source identified a
line consistently emitted after local upload-queue processing stops. The original analysis
mistook that local lifecycle boundary for remote-delivery confirmation. The v2.1.8 empirical
result below corrected that interpretation. The bounded wait and host-mounted `_diag/` volume
still reduce premature teardown and preserve the local trace, but neither proves remote
persistence.

## Identified marker

- **Marker string:** `All queue process tasks have been stopped, and all queues are drained.`
- **Source file:** `src/Runner.Common/JobServerQueue.cs` (line ~461)
- **Source URL:** `https://github.com/actions/runner/blob/main/src/Runner.Common/JobServerQueue.cs#L461`
- **Why this string:** It is emitted by `Trace.Info(...)` inside `ShutdownAsync()` only after
  `ProcessFilesUploadQueueAsync`, `ProcessResultsUploadQueueAsync`, and
  `ProcessTimelinesUpdateQueueAsync` have all been awaited to completion, and after both the
  job server and results server have been disposed. It is the last observable evidence that
  every local queue processor stopped. Because the marker is unconditional, it says nothing
  about whether an attempted upload was accepted or persisted by GitHub.

## Upload sequence leading to the marker

Inside `JobServerQueue.ShutdownAsync()`, the sequence is:

1. `"Fire signal to shutdown all queues."` — triggers in-flight work to wrap up
2. `"All queue process task stopped."` — background dequeue tasks have exited
3. `"Web console line queue drained."` — live console lines flushed (best-effort)
4. `"File upload queue drained."` — local step-log upload queue drained (best-effort)
5. `"Results upload queue drained."` — results service uploads complete
6. `"Timeline update queue drained."` — timeline records (which carry output variables) flushed
7. `"Disposing job server ..."` / `"Disposing results server ..."` — HTTP clients torn down
8. **`"All queue process tasks have been stopped, and all queues are drained."`**
   <- LOCAL-DRAIN MARKER

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
3. Report only that local queues drained; never call the marker remote delivery confirmation.
4. Proceed with container exit either way.

If the marker is absent within the timeout, proceed with exit; the persistent `_diag/`
host volume preserves logs for operator-side recovery.

Remote persistence must be verified separately through GitHub's job-log API.

## Empirical verification result (2026-07-21)

RunSecure v2.1.8 release validation observed the marker in each exercised runner while the
GitHub job-log API returned HTTP 404 for all seven self-hosted jobs. The corresponding Squid
evidence recorded `TCP_DENIED/403` for
`productionresultssa15.blob.core.windows.net`, the dynamically named Azure Blob host selected
by GitHub Actions. Therefore:

- the marker correctly identifies local queue shutdown;
- it cannot establish remote persistence or availability; and
- live release acceptance must independently require a successful job-log API response.

The egress baseline must include `.blob.core.windows.net`, which covers GitHub's dynamically
selected Blob hostnames for logs, artifacts, and caches.

## Future release acceptance

For every release, an operator with a scratch GitHub repository should:

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

5. Time `gh api .../jobs/<id>/logs` until 200 to verify remote delivery independently:

   ```bash
   JOB_ID=$(gh run list -R <owner>/<repo> --workflow=discovery-failure.yml --limit 1 --json databaseId --jq '.[0].databaseId')
   for i in 1 2 3 5 10 20 30; do
     sleep 1
     STATUS=$(gh api "repos/<owner>/<repo>/actions/runs/$JOB_ID/logs" 2>&1 | head -1)
     echo "T+${i}s: $STATUS"
   done
   ```

   The release passes only when the API returns 200. Marker presence alone is insufficient.

6. Record the API result and proxy evidence in the release acceptance receipt.
