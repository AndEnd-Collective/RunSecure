# TCP Egress, Log Loss, and DNS Design

**Date:** 2026-04-28
**Status:** DRAFT

## Overview

This spec covers two independent RunSecure improvements:

1. **TCP-level egress control** — upgrade from HTTP-proxy-only egress enforcement to TCP-level
   enforcement so that non-HTTP traffic (git over SSH, raw TLS, DNS-over-HTTPS) cannot bypass
   the Squid proxy.

2. **Log-loss fix** — the runner container exits before the actions-runner finishes uploading
   per-step logs to GitHub, causing `gh api .../jobs/<id>/logs` to return `BlobNotFound` for
   failed runs. The fix is to wait for a log-upload-complete marker before exiting.

---

## §9 Appendix

### §9.1 Empirical log-upload marker

**PROVISIONAL — empirical verification pending** (source-based research; see
`tests/discovery/findings.md` for full methodology and empirical verification recipe).

**Marker string:**

```
All queue process tasks have been stopped, and all queues are drained.
```

**Source derivation:**

The marker is emitted by `Trace.Info(...)` at the end of `JobServerQueue.ShutdownAsync()` in
the open-source actions-runner, in `src/Runner.Common/JobServerQueue.cs` (line ~461):

```
https://github.com/actions/runner/blob/main/src/Runner.Common/JobServerQueue.cs#L461
```

It is the last log line emitted after all upload queues are drained:
- `ProcessFilesUploadQueueAsync` (step log file uploads)
- `ProcessResultsUploadQueueAsync` (results service uploads)
- `ProcessTimelinesUpdateQueueAsync` (timeline / output variable records)

The marker is emitted unconditionally — regardless of job success, failure, or cancellation —
making it safe to use as a universal wait target.

**PR3 usage:**

`entrypoint.sh` (PR3) will tail `_diag/Worker_*.log` and block until this string is found
or until `RUNSECURE_LOG_UPLOAD_TIMEOUT` (default 30s) elapses, whichever comes first. The
fallback (timeout) ensures graceful degradation even if the marker is slightly off; the
host-mounted `_diag/` volume preserves logs for operator recovery in that case.

**Verification status:**

- [x] Source-derived (open-source actions-runner code read 2026-04-29)
- [ ] Empirically confirmed (requires scratch GitHub repo + workflow runs; see
  `tests/discovery/findings.md` for the verification recipe)
