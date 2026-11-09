# ATLAS target architecture

Incremental proposal grounded in the audit; final acceptance awaits the remaining web references and owner data. Preserve FastAPI/SQLAlchemy/PostgreSQL/pgvector, the gateway, scope broker, separate relay and independent verifier. No framework replacement or historical re-embedding.

1. Shared versioned agent harness: knowledge awareness, truthful persisted availability, owner-filtered retrieval and skill discovery before provider routing. Structured capability requests work with all existing protocol adapters.
2. SQL-authoritative tasks and blackboard artifacts: independent task IDs, idempotency keys, lease owner/token, attempt count, deadlines, bounded retry/dead letters. Short claims release locks before external work. Redis only wakes consumers.
3. Event subscriptions to reviewed capabilities: discovery → bounded rule → targeted task, with source/event parentage and reason. Deduplicate, limit total tasks/concurrency/cost and decay stale priorities. No prompt can grant scope.
4. Eight differentiated initial responsibilities; selectable counts within a host cap. Discovery/hypothesis artifacts remain unverified. Model routing is central; specialists inherit the same knowledge policy and tools automatically.
5. Independent proof/control verification retains a separate worker/context. Fresh reproduction and evidence binding gate confirmed findings; neither historical RAG nor consensus promotes findings.
6. Operator UI reads persisted tasks, retrieval events, source IDs, skills, usage and failures. Add a simple engagement/chat surface without replacing advanced frozen-scope controls.

Knowledge infrastructure is persistent and provider-independent. Public knowledge plus owner-private records are visible; private campaign evidence is not automatically promoted globally. Selected externally sourced skills are immutable, licensed, attributed data until their execution requirements pass the existing governance gates.

## First implemented slice

The proposal now has an implementation in `knowledge.py`, `swarm.py`, the existing broker/gateway/workers/API and a live web component. Relational `swarm_tasks` is added through frozen additive migration `0005`, without modifying any knowledge schema or embeddings. Default eight-role runs coexist with the legacy FSM, so existing callers/runs remain compatible. Current selection is a compact native extension, not a new agent framework.

At-least-once crash recovery is bounded and fenced; it is not exactly-once model billing. Task completion and resulting events are durable/idempotent, and a reconciler covers the last-task/final-report crash window. Reservations gate global/run/campaign/role spending and provider concurrency before dispatch; uncertain costs remain held. Capacity waits before dispatch can safely requeue. Final prioritization/decay, distributed fairness/performance evaluation, automatic provider failover and sophisticated attack-chain relationships remain open design work. Source review and current local tests establish this slice; unavailable references are not claimed as final architecture validation.
