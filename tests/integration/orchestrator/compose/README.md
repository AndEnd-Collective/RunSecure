# Orchestrator integration tests (Compose backend)

These scripts spin up the orchestrator + socket-proxy + a mock-github
container via `docker-compose.test.yml`, drive scenarios via env vars,
and assert on Cornerstone events grepped from the orchestrator's stdout.

The load-bearing test is `compose-network-isolation-property.sh` — it
empirically verifies the spec §4.3 structural-floor property #1 (the
runner has no network path that bypasses the per-spawn proxy stack).

## Usage

```sh
# All tests in sequence:
for f in tests/integration/orchestrator/compose/compose-*.sh; do
  "$f" || { echo "FAIL: $f"; exit 1; }
done

# Or one at a time:
tests/integration/orchestrator/compose/compose-orch-spawn-cycle.sh
```

## Convention

- Each script uses `set -euo pipefail`.
- Each uses an isolated compose project name (`--project-name rs-test-<scope>`).
- Each cleans up on exit via `trap`.
- Failures are reported via `echo` + non-zero exit, not via `set -e` alone.
