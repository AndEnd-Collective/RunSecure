# Task 11 Report: Docs + deprecation log for `egress.allow_domains`

## Status: COMPLETE

## Changes

### 1. Go: `infra/orchestrator/internal/runneryml/runneryml.go`
Added `DeprecationWarnings() []string` method to `Runner`. Returns a one-element
slice with a human-readable warning when `Egress.AllowDomains` is non-empty AND
`HTTPEgress` is empty (deprecated alias in use). Returns nil otherwise. Callers
log each entry at WARNING level — the method does not import `log` itself, keeping
the package testable without I/O side effects.

### 2. Go: `infra/orchestrator/internal/runneryml/runneryml_test.go`
Added `TestDeprecationWarnings` with four sub-tests:
- warns when only `egress.allow_domains` is set
- no warning when `http_egress` is set (even alongside `allow_domains`)
- no warning when neither field is set
- no warning when only `http_egress` is set
Coverage: 100.0% (unchanged from pre-task baseline).

### 3. `skeleton/runner.yml`
- Added inline deprecation block under the `http_egress` section noting the
  `egress.allow_domains` rename and the one-release alias window.
- Added `dns.host: false` orchestrator limitation note (dnsmasq needs
  `CAP_NET_BIND_SERVICE`; cap_drop:ALL on the orchestrator path means it's a no-op).
- Added "Enforced by:" notes on `http_egress` and `tcp_egress` for clarity.

### 4. `SECURITY.md`
- Fixed item 9 (was wrong: said `egress:` is rejected; it's actually aliased). Now
  accurately describes the 2.x alias with deprecation warning and 3.0 removal.
- Added item 16: orchestrator egress allow-path (per-spawn proxy, dual-homed,
  ICC-disabled, private-IP rejection, `security_overrides.allow_private_cidrs`).
- Added item 17: orchestrator dnsmasq limitation (cap_drop:ALL blocks port-53
  bind; dns.host:false is a no-op on the orchestrator path; run.sh still works).
- Added item 18: egress-gate network-name matching residual risk.

### 5. `README.md`
- Updated `runner.yml` schema block: added inline deprecation comment for
  `egress.allow_domains` with migration instructions.
- Updated "How the egress proxy works" section: added paragraph stating both the
  orchestrator and `run.sh` enforce the allow-path (not just deny-all), with
  per-spawn proxy architecture summary.

## Test results
- `go test ./internal/runneryml/ -cover`: PASS, 100.0% coverage
- `go test ./internal/... (orchestrator)`: all 11 packages PASS
- `go test ./internal/... (socket-proxy)`: all 3 packages PASS

## Known accuracy items
- dnsmasq limitation is documented as-is (no false claims about it working on
  the orchestrator path).
- Egress-gate network-name matching documented as residual risk, not a blocker.
- `DeprecationWarnings()` returns []string (not io.Writer) to stay testable
  without process-level I/O. Caller in `run.go`/`egressShim` is responsible for
  logging; connecting that wiring was deferred as out of scope for this task
  (the method exists and is tested; a future task can wire `fmt.Fprintln(os.Stderr)`
  in `Run()` after `runneryml.Parse()`).

---

## Task 11 Review Blockers — Fix pass (2026-06-20, commit 27f902a)

### Fix 1 (Critical) — deprecation warning wired in orchestrator
`productionDeps.RunnerYML()` in `infra/orchestrator/cmd/orchestrator/run.go`
now calls `yml.DeprecationWarnings()` after every successful parse and emits
each message to stderr via `fmt.Fprintln(os.Stderr, "[RunSecure] WARNING:", w)`.

New tests in `egressshim_test.go`:
- `TestRunnerYML_DeprecationWarning_EmittedToStderr`: writes a runner.yml with
  `egress.allow_domains`, captures stderr via os.Pipe, asserts `[RunSecure] WARNING:`
  and `egress.allow_domains is deprecated` are present. PASS.
- `TestRunnerYML_NoWarning_WhenHTTPEgressUsed`: same setup with `http_egress`,
  asserts no WARNING. PASS.

```
go test ./cmd/orchestrator/ -v -run TestRunnerYML
=== RUN   TestRunnerYML_DeprecationWarning_EmittedToStderr --- PASS
=== RUN   TestRunnerYML_NoWarning_WhenHTTPEgressUsed       --- PASS
PASS
```

### Fix 2 (High) — run.sh path aliases egress.allow_domains
Two script changes close the silent-drop regression:

1. `infra/scripts/lib/validate-schema.sh`: `egress` is now an accepted top-level
   key (deprecated) that emits a `_warn` instead of `_err`. Previously it hard-errored.
2. `infra/scripts/generate-egress-conf.sh` (`_generate_squid_conf`): after reading
   `.http_egress`, if empty, reads `.egress.allow_domains` as fallback and emits a
   WARNING to stderr.

Verification:
```
$ generate-egress-conf.sh /project-with-allow-domains/
[validate-schema] WARNING: egress.allow_domains is deprecated; rename to http_egress...
[validate-schema] OK: ...
[generate-egress-conf] WARNING: egress.allow_domains is deprecated; rename to http_egress...
[generate-egress-conf] Adding project HTTP egress domains:
[generate-egress-conf]   + api.example.com
# runtime.conf contains: acl project_egress dstdomain api.example.com  ✓
```

Existing unit tests (`tests/unit/test-runner-yml-schema.sh`): 13/13 PASS.

### Fix 3 (Medium) — README dns.host caveat
`README.md` schema block now notes that `dns.host: false` is a no-op on the
orchestrator path (dnsmasq needs `CAP_NET_BIND_SERVICE`; unavailable under
`cap_drop: ALL`). Matches SECURITY.md §17 and skeleton/runner.yml.

### Fix 4 (Low) — runneryml.go doc comment
`DeprecationWarnings()` doc comment updated: "Callers should log" replaced with
"The orchestrator emits each entry to stderr via fmt.Fprintln after every Parse call."

### SECURITY.md §9 verification
After Fixes 1+2: both paths (orchestrator + run.sh) warn and alias. §9 claim
"the Go orchestrator and `run.sh` both accept it and emit a `WARNING` to stderr"
is now TRUE. No wording changes needed.

### Full test run
```
go test ./... (infra/orchestrator): 12/12 packages PASS
tests/unit/test-runner-yml-schema.sh: 13/13 PASS
```
