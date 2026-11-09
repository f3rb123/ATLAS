# Build security review

This is an implementation review and automated/local validation record, not an external penetration-test certification. No owner VPS or live assessment target was accessed.

Authentication is owner-only with host-issued one-time bootstrap, calibrated Argon2id, passkeys, encrypted TOTP fallback, hashed single-use recovery codes, scoped revocable tokens, server-side session expiry/rotation, same-origin CSRF and audited privileged host recovery. Production gates research access until security enrollment is complete. Read-only identities cannot mutate resources; object APIs enforce ownership. The production Caddy binding is explicit and internal database/Redis/worker ports are unpublished.

Provider credentials use per-secret AES256-GCM data keys wrapped by a separately delivered master key. Endpoint/protocol/auth/header identity is bound into authenticated encryption; database endpoint tampering cannot redirect an existing encrypted key. Keys are write-only, rotatable and excluded from model contexts. Metadata fields reject duplicate credential values and secret-like non-secret headers. Provider generation/discovery/streaming outputs are scrubbed, including keys split across content/tool-argument fragments. Unknown transport outcomes retain conservative billing reservations until a recently authenticated owner reconciles stopped-run billing against independent evidence.

Repository/model/source data never grants authorization. Typed tool registration, immutable policy/version pins, approval state, current run status, quotas, source snapshot integrity and kill state are checked outside model output. Repository execution uses actual networkless Bubblewrap namespaces, read-only runtime/source mounts, private tmp/dev, cleared environment and CPU/memory/file/process/output/time bounds. Workers receive neither Docker socket nor provider master key. The seccomp exception is scoped to workers; there is no privileged mode or SYS_ADMIN grant. Unprivileged user namespaces must be supported by the host.

The public corpus is acquired through fixed official connectors or an exact URL with owner-reviewed rights/robots policy. Native API connectors accept only HTTPS URLs at an explicit official hostname list. Custom provider/target requests use deterministic policy and connection-time validated/pinned addresses. The controlled local transport harness checks rebinding, redirects, bounds and timeouts. No real reports or paid credentials are needed for CI.

## Automated findings disposition

Runtime Python (`pip-audit` on hash-pinned requirements.lock) and production npm (`npm audit --omit=dev`) returned zero known vulnerabilities during this build. Re-run advisory checks before deployment. Scanners do not establish absence of vulnerabilities.

Bandit medium/high scan found the following patterns:

| Pattern | Disposition |
|---|---|
| B113, event-stream timeout=None | Fixed with bounded read/connect timeouts. SSE heartbeat keeps healthy streams alive. |
| B310, urllib official archive/API acquisition | Reviewed: source URLs come from fixed official connector definitions; API URLs require HTTPS and an explicit official-host list. No file/custom scheme or arbitrary owner URL is accepted by these paths. Owner URL acquisition uses the scope-pinned transport instead. |
| B108, literal /tmp in sandbox arguments | Reviewed: these are Bubblewrap's private tmpfs mount/HOME paths, not host temporary-file names. Host captures use securely created TemporaryFile/TemporaryDirectory. |

No high-severity scanner finding was accepted unresolved. The raw advisory/SAST summaries and exact validation commands are recorded in test-results; scanner output is reviewed rather than treated as a substitute for domain tests. Imported executable skill hooks, arbitrary host shell, state-changing target adapters and unsupported advanced category adapters remain disabled.

## Operational boundaries

Owner-supplied paid provider credentials, real-domain ACME issuance, the owner's SSH/firewall/VPN posture and real-target effectiveness require owner configuration/authorization and have not been represented as tested here. Local TLS used a verified Caddy CA. Proposed SSH hardening is supplied as a reviewed drop-in under infra/ubuntu; scripts/preflight-vps.sh is read-only. No script silently installs SSH/firewall changes. Already dispatched bounded GET/HEAD requests can finish their current timeout window after cancellation; new actions fail closed. Backups do not include the KEK and require separate protected recovery material.

A checksum-verified Gitleaks 8.24.3 history scan previously reported only public model-file SHA256 checksums and the OWASP content-hash identity. Exact finding fingerprints are retained in .gitleaksignore; no directory or whole detection rule is excluded. A fresh history scan is required after the current changes are committed.

Public-source text normalization now removes recognizable AWS access-key IDs, Sourcegraph tokens, compact JWTs, private-key blocks, curl basic-auth credentials and common credential assignments. The corpus packager applies the same rules only to delivery copies, re-embeds changed text chunks, and records omitted raw-source hashes. The current expanded corpus candidate still has unresolved scanner findings; the finding report is not suppressed or included in the transfer archive. Do not publish or transfer that candidate until each residual finding is classified. The current secret-scan summary is in test-results/secret-scan.json.
