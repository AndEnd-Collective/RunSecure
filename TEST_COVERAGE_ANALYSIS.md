# RunSecure Test Coverage Analysis

## Current State

RunSecure has **~150+ assertions** across three testing layers:

| Layer | Files | Approx. Assertions |
|-------|-------|--------------------|
| **Unit tests** (sample projects) | 3 files | ~23 |
| **Integration tests** | 4 scripts | ~80+ |
| **Validation tests** | 2 scripts | ~30+ |

### What's Well-Covered

- **Egress proxy filtering** — allowed/blocked domains, CONNECT tunneling, exfiltration techniques, bypass attempts (`test-egress-proxy.sh`)
- **Attack simulation** — 10 attack categories including container escape, privilege escalation, reverse shells, credential harvesting (`test-attack-simulation.sh`)
- **Security hardening validation** — setuid stripping, package manager removal, root lockout, filesystem permissions (`validate-runner.sh`)
- **Node.js and Python CI workflows** — end-to-end pipeline through proxy (`test-ci-workflow-node.sh`, `test-ci-workflow-python.sh`)

---

## Gaps and Recommended Improvements

### 1. Missing Rust CI Workflow Integration Test (High Priority)

There are integration tests for Node.js (`test-ci-workflow-node.sh`) and Python (`test-ci-workflow-python.sh`), but **none for Rust** despite having a `rust.Dockerfile` and `tests/rust-project/`. A Rust CI workflow should validate:

- `cargo build` through the proxy (crates.io egress)
- `cargo test` execution
- Dependency resolution via the proxy

**File to create:** `tests/integration/test-ci-workflow-rust.sh`

### 2. No Tests for `generate-squid-conf.sh` (High Priority)

This script merges base Squid config with project-specific egress domains from `runner.yml`. It has non-trivial logic (YAML parsing, sed template injection) but zero dedicated tests. Bugs here silently break egress filtering. Test cases should cover:

- No `runner.yml` present — falls back to base config
- Empty egress list — falls back to base config
- Single egress domain — correctly injected into ACL blocks
- Multiple egress domains — all injected, correct ordering
- Domains with subdomains (`.example.com` vs `example.com`)
- Malformed `runner.yml` — graceful error handling

**File to create:** `tests/integration/test-generate-squid-conf.sh`

### 3. No Tests for `compose-image.sh` (High Priority)

The image composer is the most complex script in the codebase (210 lines). It handles YAML parsing, image layering, caching, registry pull with fallback, and dynamic Dockerfile generation. No dedicated tests exist. Critical paths to test:

- No tools / no apt packages — returns base language image directly
- With tools — generates correct Dockerfile with COPY + RUN for each recipe
- Unknown tool recipe — warns and skips
- Missing language Dockerfile — errors clearly
- Cache hit (image already exists) — skips rebuild
- `--force` flag — rebuilds despite cache
- Config hash determinism — same config produces same tag

**File to create:** `tests/integration/test-compose-image.sh`

### 4. No Tests for `entrypoint.sh` (Medium Priority)

The container entrypoint handles JIT config validation, proxy setup, and credential sanitization. Test cases:

- Missing `RUNNER_JIT_CONFIG` — exits with error
- Proxy environment propagation (`HTTP_PROXY` → `http_proxy`, `https_proxy`, `no_proxy`)
- JIT config is unset from environment after reading (security-critical behavior)

**File to create:** `tests/integration/test-entrypoint.sh`

### 5. No Tests for `run.sh` Argument Parsing (Medium Priority)

The orchestrator script has argument parsing, config reading, and container lifecycle logic. Unit-testable areas:

- `--project` required validation
- `--repo` required validation
- `--help` output
- Container name derivation from repo (`owner/my-repo` → `rs-my-repo`)
- Default values for `--max-jobs` (5), resources (8g memory, 4 CPUs, 2048 PIDs)
- Docker Compose command auto-detection

**File to create:** `tests/unit/test-run-args.sh`

### 6. No Tests for Tool Recipes (Medium Priority)

The three tool recipes (`cypress.sh`, `playwright.sh`, `semgrep.sh`) are untested. While they're simple install scripts, they can break silently when upstream packages change. Smoke tests should verify:

- Each tool binary is available after install (`cypress verify`, `semgrep --version`, `npx playwright --version`)
- File ownership is correct (especially Playwright's `chown` for runner user)
- Python auto-install in `semgrep.sh` works on non-Python base images

This could be added as a Phase 1.5 in `run-all-tests.sh` or as standalone scripts.

### 7. No Tests for `finalize-hardening.sh` Idempotency (Low Priority)

The hardening script is tested indirectly via `validate-runner.sh`, but there's no test that it's **idempotent** (running it twice doesn't break things) or that it correctly handles edge cases like already-removed files. This matters because tool recipes run between the base hardening and finalization.

### 8. No CI Test Execution (Medium Priority)

The GitHub Actions workflow (`publish-images.yml`) only builds and publishes images — **it never runs the test suite**. A CI job should:

- Build all images
- Run `tests/validation/run-all-tests.sh`
- Optionally run integration tests

This is a process gap, not a code gap, but it means regressions can ship undetected.

### 9. No Negative Tests for `runner.yml` Schema Validation (Low Priority)

There's no validation that a malformed `runner.yml` produces clear errors. Currently, a user could provide invalid runtime names, unsupported languages, or missing fields and get confusing `yq` errors. Test cases:

- Unknown runtime (e.g., `runtime: go:1.22`) — clear error
- Missing runtime field entirely
- Invalid resource values (e.g., `memory: "banana"`)
- Unsupported tool name (e.g., `tools: [nonexistent]`)

### 10. No Multi-Architecture Test Coverage (Low Priority)

The CI publishes `linux/amd64` and `linux/arm64` images, but tests only run on the host architecture. Security hardening behavior (especially seccomp profiles) can differ between architectures.

---

## Summary Priority Matrix

| Priority | Gap | Effort | Impact |
|----------|-----|--------|--------|
| **High** | Rust CI workflow integration test | Low | Parity with Node/Python coverage |
| **High** | `generate-squid-conf.sh` tests | Medium | Core security config generation |
| **High** | `compose-image.sh` tests | Medium | Most complex script, untested |
| **Medium** | `entrypoint.sh` tests | Low | Credential sanitization is security-critical |
| **Medium** | `run.sh` argument parsing tests | Low | Basic input validation |
| **Medium** | Tool recipe smoke tests | Low | Catch upstream breakage |
| **Medium** | CI test execution in GitHub Actions | Low | Prevents shipping regressions |
| **Low** | Hardening idempotency tests | Low | Edge case safety |
| **Low** | `runner.yml` schema validation | Medium | Better UX for misconfiguration |
| **Low** | Multi-architecture testing | High | Architecture-specific security gaps |
