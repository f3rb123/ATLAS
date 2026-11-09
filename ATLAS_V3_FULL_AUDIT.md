# ATLAS V3 implementation audit

Audited 2026-11-09 from supplied commit `2a7a348c49ae3d3994d7cf2e7de1f3dcc925475f`.
The current owner handoff supersedes conflicting greenfield and mandatory-MFA requirements in `docs/SPECIFICATION.md`.

## Acquisition and runtime evidence

Both uploaded artifact SHA256 values match RELEASE-MANIFEST.md. `git bundle verify` passed; its complete history and two tags were retained. All 153 ZIP files match the bundle's HEAD byte-for-byte. The previously empty GitHub checkout is now restored locally; nothing was pushed. No prior runtime directory, database, corpus, model weights, credentials, Docker volumes or VPS connection was delivered.

Frozen Python and npm installation passed. Baseline Python: **84 passed, 4 deselected** (`not sandbox and not semantic`); one upstream TestClient deprecation warning. Next.js production build and TypeScript passed. The four excluded cases need separate sandbox/semantic validation, not a passing classification. Historical release evidence is not current-instance validation.

## Implementation truth table at supplied commit

| Capability | Classification | Evidence and boundary |
|---|---|---|
| Backend, frontend, CLI | Implemented and locally build/test verified | FastAPI `atlas/api.py`, Next.js `apps/web`, shared API-backed CLI; no live owner setup here |
| Agent runtime | Implemented, different from requested swarm | `workflow.py` is a 16-state sequential FSM, one shared run lease; source context capped at first six files/80 lines |
| Collaboration/concurrency | Partially implemented | Multiple runs may execute across workers; coding/fast specialist calls are sequential and only allowed at FOCUSED_INVESTIGATION; no eight-agent scheduler/event subscriptions |
| Durable queues | Implemented but needs stronger claims | SQL documents authoritative; Redis wake hints; 600-second run leases. Worker loads/locks all runs and runs stages serially; no per-task fencing or dead-letter queue |
| Blackboard/event bus | Partially implemented | Hash-chained append-only journal/SSE and structured artefacts exist; events do not activate specialists |
| Scope and broker | Implemented, local tests verified | Frozen policy hashes, owner checks, explicit scope, deny precedence, DNS validation/pinning, separate GET/HEAD relay, bounded typed tools; no arbitrary model shell |
| Vector infrastructure | Implemented; historical data unavailable | PostgreSQL pgvector; SQLite development option. Tables `knowledge`, `knowledge_aliases`, `knowledge_chunks`; no external collection server |
| Embeddings | Implemented, current assets missing | Pinned MiniLM revision `d13954661f83248295ba75c1ed411eef3b7b936e`, 384 dimensions, cosine; SHA256 checked before ONNX inference. Explicit 128-dimensional signed-token-hash test fallback is not semantic |
| Historical corpus | Not delivered | Inventory reports 21,012 identities / 34,229 vectors, of which 21,011 advisories and one reference; **zero full-text bounty reports**. Manifest withholds corpus for 26 unresolved secret candidates. Cannot verify persisted counts here |
| RAG ingestion/retrieval | Implemented, unit tested; incomplete universal access | Rights-aware acquisition/conversion, token-window chunking (224, stride 192), dedupe/lineage/metadata, cosine plus exact identity/title; SQLite lexically bounds candidates to 2,000. Not BM25/RRF. Stage-specific retrieval misses specialists/verifier |
| Global knowledge awareness | Missing | SYSTEM mentions untrusted knowledge, but no shared versioned availability policy, universal tool catalogue in model context, retrieval loop or feedback workflow |
| Skills | Governance implemented; library mostly absent | Only scope-boundary-review source skill ships; strict schemas, immutable imports, exact-hash fixture gate and review/validation/enable lifecycle. A registry row alone is not installed capability |
| Providers/models | Implemented, local contract tested | Central encrypted provider connections, discovery/probes, versioned aliases, several protocol serializers, cost reservations. No live HackerAI connection or any owner keys delivered; historical model IDs unverified |
| Gateway reliability | Partially implemented | Remote workflow client has fixed 45s timeout while adapters have separate timeout configuration. No evidence establishes the historical THREAT_MODEL timeout cause. Automatic capability/health fallback and distributed provider concurrency incomplete |
| Recon/MCP management | Partially implemented / missing | Typed source tools and relay exist. Listed third-party scanners/API/MCP adapters and central management UI are not delivered |
| Deep Research | Partially implemented | Threat model, slices, hypotheses and research notes exist; no autonomous research agent/event task graph |
| Verification/reporting | Implemented, controlled fixture tested | Separate verifier context/process, proof and secure-control replay, evidence ID binding, dedupe, Markdown/SARIF/other exports. Not a general remote vulnerability oracle |
| Authentication | Implemented; conflicts with new owner requirements | Argon2id, cookies, CSRF, roles, passkey/TOTP/recovery, encrypted secrets. Ordinary APIs/UI require passkeys/MFA; owner now requests optional factors |
| Operator workflow | Implemented but not requested UX | Campaign/run forms, persisted views and SSE. No chat-based engagement, selectable eight-agent swarm or actual agent/task panels |
| Deployment | Assets present; current deployment unverified | Compose PostgreSQL/Redis/API/gateway/relay/workers/Caddy, migrations/backup scripts. No real VPS access authorized or performed |

## Execution trace

Campaign → frozen scope → optional repository upload → run with pinned model/skill versions → research worker claims run → sequential stages → role() → local/remote gateway → provider adapter → stage-only RAG → typed broker → artifacts/journal → experiment proof/control → separate verifier replay → finding → report. Specialist activation is synchronous role review, not an event-driven swarm. Runtime knowledge tools are not discoverable uniformly from model requests.

## Preserve and change

Preserve database identities/embeddings, migrations, acquisition rights, gateway budget reservations, scope relay/broker, evidence verification, encrypted credentials and release tags. Add a shared knowledge harness first; do not substitute a framework or re-create the withheld corpus. Prioritize durable per-task claims/fencing, bounded event activation, skill retrieval, and truthful persisted visibility in subsequent packages. Never equate a local mock-model test with live provider or target validation.

## Current implementation after the first rebuild package

- `atlas/knowledge.py` supplies versioned global awareness, truthful owner-filtered availability, task-aware bounded retrieval, eleven model-independent typed capabilities, attributed source retrieval, selective skills, and pending-review feedback. `role()` now uses the same harness for initial roles, specialists and verifiers. Schema-mediated tool results return to reasoning in at most three rounds; native vendor tool support is not assumed. Swarm roles also discover the existing typed tool catalogue. Empty and failed retrieval remain explicit. No original record/index is recreated.
- `atlas/swarm.py` and additive migration `0005` introduce SQL-backed independent tasks, eight default responsibilities, 1–16 slots, typed unverified discoveries, cited specialist triggers, targeted review requests, idempotent event/task keys, 128-task cap, 300-second fenced leases with heartbeat, crash recovery, dead letters, pause/cancel/kill checks and persisted completion/reporting. Short per-run advisory transactions enforce claims; this is not an exactly-once provider or general distributed-execution guarantee. Known undispatched capacity waits requeue; ambiguous billed outcomes retain reservations and require reconciliation.
- Existing gateway reservations now serialize concurrent call accounting; provider concurrency is bounded. New runs support one-model-for-all or pinned capability aliases. No automatic cross-provider fallback or live-provider availability claim.
- The existing verifier reexecutes proof/control independently for swarm proposals. Genuine/false deliberately vulnerable source fixtures exercise actual Bubblewrap with synthetic model judgments. A model cannot directly publish a confirmed finding.
- Two licensed/pinned external methodology references are installed per owner as research-only data. Native executable-skill review/fixture gates remain intact. Full upstream library activation is not claimed.
- Default private operator access accepts password sessions; enrolled factors remain required, and explicit strict MFA mode is preserved. Password change rotates/revokes sessions. CSRF, ownership, cookie settings, throttling, secret encryption and audit controls remain.
- The frontend adds instructions, agent count, model mode and execution-mode selection plus a live task/discovery/retrieval/usage panel reading persisted API state. This is not yet a conversational engagement-chat implementation or complete recon/MCP management console.

Current complete backend run: **138 passed, one semantic test deselected**, including the real sandbox and disposable PostgreSQL migration/concurrency/reconnect test. Two warnings: upstream TestClient deprecation and existing pgvector type reflection. The source lab tests are included; models/corpus in them are explicitly synthetic. Frontend production/TypeScript and the full browser flow passed during integration; final evidence is recorded in the implementation ledger. Original corpus, real embedding inference, live models, full web-reference study and VPS deployment remain unverified or blocked.
