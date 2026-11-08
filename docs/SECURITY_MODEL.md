# ATLAS security model

## Trust boundaries

The browser is an untrusted client. Sessions are opaque and hashed server-side; origin and CSRF verifiers protect mutations. Production cookies are __Host-atlas, Secure, HttpOnly, SameSite=Strict, Path=/, without Domain. MFA and object ownership are checked by API dependencies. No public registration or remote unauthenticated recovery exists.

Imported repositories, documents, skills, tool output, model JSON and target responses are untrusted data. They cannot authorize actions. Pydantic rejects extra policy-driving fields. Role output is independently validated and cannot set workflow state or confirm findings. Repository reads exclude secrets, symlinks, vendored/generated paths and oversized files. Only predefined execution templates enter a resource-bounded Bubblewrap sandbox with no network and no host filesystem except read-only runtime libraries and the selected source snapshot.

The API handles account/provider configuration. The model gateway alone needs provider credentials during research; production workers have no KEK volume. Research/verifier service tokens differ; the gateway prevents the researcher from using the verifier identity. Provider egress differs from target relay egress. Target requests are GET/HEAD only and pass frozen policy, DNS/all-address checks, connection pinning, quotas, deadlines and audit. State-changing live tools remain unavailable; no model can grant itself an exception. Metadata/link-local destinations are always prohibited, including approved local inference/lab configurations.

## Application threats and controls

- SSRF/rebinding: canonical schemes/hosts/ports, rejected userinfo/ambiguous encodings, all DNS addresses checked, connection pinned to validated IP, same-origin redirect checks in relay, provider redirects denied.
- Credential theft: per-secret AES256-GCM DEKs wrapped under a separately supplied KEK, AAD bound to secret identity, write-only key APIs, exact-value/provider-format redaction, no browser storage of credentials. Request bodies and model prompts are not logged.
- Unauthorized findings: candidates need successful nonzero proof/control tests, independent re-execution and an independent structured verification decision citing both artifact IDs. Errors/timeouts/empty output cannot confirm a finding.
- Resource abuse: bounded inputs/results, CPU/RAM/process/output/wall limits, token/call budgets, global/run/campaign/role reservations, bounded retries and no silent model fallback.
- Workflow tampering: database-backed states, leases, idempotency keys and append-only hash-chained events; database triggers prohibit journal update/delete. Redis is never authoritative.
- XSS/injection: React output encoding, reports escaped, no trusted imported HTML, nonce CSP on the Web UI, strict headers and protected exports.

## Operational boundary

Only the reverse proxy publishes a host port, loopback by default. Postgres, Redis and workers remain internal. Containers are non-root, read-only where practical, capability-dropped and no-new-privileges; initialization alone is a one-shot privileged file-ownership/migration operation. No Docker socket is mounted. Linux user namespace support is a runner prerequisite, not permission to enable privileged containers.

The owner must protect SSH, DNS, TLS renewal, encrypted host storage and off-host recovery material. The supplied scripts do not change a real server or firewall automatically. Deployment approval and live-target authorization remain separate actions.
