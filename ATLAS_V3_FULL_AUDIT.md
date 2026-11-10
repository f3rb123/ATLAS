# ATLAS V3 current implementation audit

> Autonomous build continuation: the owner clarified that SBI smoke restrictions
> apply to build-time acceptance only. The source now includes broader scoped
> web/tool execution and generated source experiments. The 214-test report below
> describes the prior release; newer changes remain pending final verification
> while implementation-first steering is active. See
> [the active checklist](docs/AUTONOMOUS_BUILD_CHECKLIST.md).


Updated 10 November 2026. Current owner instructions supersede the inherited greenfield and mandatory-MFA wording. No push, public deployment, VPS change or SBI target request occurred.

The recovered checkout was extended in place from local checkpoint 64048a4. Original tags, database identities, corpus, vectors, models and keys were preserved. Historical validation is separate from the [current acceptance report](docs/test-results/DEPLOYMENT_ACCEPTANCE_2026-11-10.md).

| Area | Implemented and exercised | Boundary |
|---|---|---|
| Knowledge | Shared policy/capabilities, attributed selective semantic retrieval, per-task provenance, skill discovery and feedback | 21,012 advisory/reference records; zero full-text bounty reports; five-query retrieval diagnostic is small |
| Corpus import | Full-archive preflight, identity-preserving atomic restore, 8 MiB resumable parts, durable worker/UI progress, protected egress views | Original ZIP and embeddings unchanged; missing original private corpus is not recreated |
| Collaboration | Eight initial responsibilities, 1–16 slots, SQL claims/leases/fencing, typed blackboard events, dynamic specialists, handoffs, dependencies | 128 tasks per run; bounded follow-ups; no model authority to expand scope |
| Scheduling | Confidence/evidence/relevance/freshness/aging/effort/fairness terms and failed-dependency cancellation | Scores prioritize work; they do not establish vulnerability validity |
| Providers | Exact HackerAI IDs verified; real JSON/tool probes; capability aliases and automatic pinned routing | Unknown prices remain unconfirmed; unknown billing retains reservations |
| Reliability | Persistent circuits, bounded adapter/gateway timeouts, pre-dispatch fallback, one accounted schema correction | Ambiguous requests are never automatically replayed |
| Budget | Persistent atomic 50M authority, 2M allocation, validator protection, detailed usage, explicit reconciliation | 744,368 reported tokens; 282,255 held; no reset/increase |
| Tools | Central registry/UI, typed source/sandbox/relay tools, encrypted API/MCP resources and keyless-worker credential gateway | Optional scanners/unsupported APIs explicitly disabled; supplied remote API/MCP connections absent |
| Research/findings | Attributed notes, competing explanations, unverified chain links, independent proof/control, evidence binding, timeline and exports | A model or relationship cannot directly confirm a finding |
| Operator UX | Durable engagement chat, explicit scope, saved settings/source attachment, start/pause/stop/resume, persisted live views | New chat messages apply to the next run; active instructions/scope remain pinned |
| Authentication | Owner bootstrap, Argon2id, CSRF, ownership, encrypted secrets, scoped CLI tokens, optional passkeys/TOTP/recovery | Enrolled factors remain enforced; stricter MFA is explicit configuration |
| Deployment | Actual images/Compose, pgvector restore, verified local TLS, encrypted backup/isolated restore and browser acceptance | Local evidence does not establish owner VPS/DNS/ACME readiness |

All eight initial roles and two GraphQL follow-ups completed actual-provider tasks. The run remains partial because its initial independent reviews failed evidence binding; a fresh corrected independent replay confirmed the authored lab with both fresh artifacts. Earlier failures and five uncertain calls remain visible. Synthetic CI uses a separate disposable database/provider.

The original private/full-text corpus, exact historical resource manifest and different-account uncommitted workspace remain external recovery dependencies. Scanner/exploitation breadth is represented by explicit capability maturity, not a claim to find every vulnerability class.
