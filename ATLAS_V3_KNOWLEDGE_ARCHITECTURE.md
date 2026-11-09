# Persistent knowledge architecture

## Existing data contract

PostgreSQL/pgvector is authoritative; SQLite is isolated development. SQL `knowledge` records, aliases and `knowledge_chunks` share owner/source/hash lineage. Public records and the requesting owner's records are visible. MiniLM-L6-v2 revision `d13954661f83248295ba75c1ed411eef3b7b936e` supplies 384-dimensional, normalized local embeddings; cosine retrieval. Token chunks use up to 224 tokens with stride 192. Exact advisory identities/title boosts complement similarity. Explicit hash mode is 128-dimensional lexical test retrieval, not semantic search.

Data is persistent independently of agents/providers. Compose stores PostgreSQL in a persistent volume, application artifacts/models in `/data`; backup tooling exists. The current cloud instance contains no original database or corpus. Historical inventory: 21,012 records, 34,229 vectors, zero full-text bounty reports. Those are reported prior-instance counts, not independently verified here. Corpus is withheld for unresolved secret candidates; do not rebuild, export, sanitize-by-guessing, overwrite or re-embed it.

## Shared harness contract

Every role call must receive a versioned global knowledge policy, actual availability/counts and structured capability descriptions. Runtime knowledge access must precede and be independent of model selection. Specialists/verifiers use the same entrypoint, including dynamically assigned roles. Provide bounded automatic task retrieval and allow on-demand requests through the ordinary schema-validated broker. Keep historical source claims distinct from current observations and reproduced findings.

Universal logical tools: search, retrieve/get_source, report filtering, skill search/retrieve, technology/vulnerability/attack-pattern search and structured feedback. Preserve source URL, record ID/hash/chunk hash, excerpt, score/mode, review/validation state, publication date and license. Do not inject the corpus or every skill into prompts. Failed/missing semantic indexing must have an explicit status/event; never silently count fallback as semantic success.

## Feedback and persistence

Feedback stores attribution, run/task, result ID/hash, usefulness and comments as unreviewed data. No feedback automatically edits trusted source records or corpus review status. Owner-controlled review promotes only evidence-backed conclusions. Runtime audit events record result/source IDs, not credentials or whole corpora. Restart and cross-engagement tests must open a fresh SQL session and exercise the same store.

## Acceptance still requiring external data

Verify the original corpus with read-only count/version/dimension/hash checks before migration; take a backup before any risky operation. Real semantic retrieval/evaluation cannot be established by synthetic hash-mode tests. Acquire only pinned, checksummed model artifacts through approved HTTPS or a reviewed owner archive. No knowledge deletion or re-embedding is part of this package.

## Implemented interfaces and evidence

`atlas.knowledge.CAPABILITIES` defines eleven tools: search; reports; technology, vulnerability and attack-pattern search; related research; bounded record retrieval; original source; skill search/full reference retrieval; and feedback. These are JSON-schema requests via `tools.broker`, not provider-specific memory. Existing memory/advisory tools remain backward compatible. `workflow.role()` injects GLOBAL_POLICY at the system level and a versioned capability catalogue plus runtime availability/task results for every role. A bounded follow-up loop feeds requested tool artifacts back to the model. Swarm tasks independently enter this same function; no role-specific knowledge setup is required.

The broker applies run state/deadline, kill switch, tool budget and (for swarm tasks) lease fencing. Search runs with owner/public filtering, report-only filtering before candidate limits, index-version checks and attributed results. Search events and artifacts record mode, IDs, hashes and source URLs. Missing/index-error results have explicit status; no automatic semantic-to-hash downgrade occurs. Private-owner access, source attribution, report filtering, cross-engagement/fresh-session persistence and failure isolation are regression-tested.

Feedback persists separately in `knowledge_feedback` documents. Authenticated owner-admin review uses `PATCH /api/v1/knowledge-feedback/{id}/review`; review is immutable and does not modify a source or confirm a finding. Reviewed usefulness is not factual validation. `GET /api/v1/knowledge-feedback` exposes owner-filtered review state. References live in packaged `atlas/data/skill_references`, with pinned upstream commit/raw SHA/license; their full text is returned only on demand as untrusted research data.

Protocol coverage: seven existing serializers × reasoning/coding/fast/verifier roles, using synthetic model responses. The isolated swarm lab proves dynamic specialist inheritance and real proof/control execution. These tests prove wiring and invariants, not semantic retrieval quality of the missing historical corpus.
