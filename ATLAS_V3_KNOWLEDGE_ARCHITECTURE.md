# ATLAS V3 knowledge architecture

Updated 10 November 2026. Current owner instructions supersede the inherited greenfield and mandatory-MFA wording. No push, public deployment, VPS change or SBI target request occurred.

Every initial role, dynamic specialist and validator enters `workflow.role()` and the same `knowledge.prepare_context()` service. Knowledge tools are independent of LLM vendors and model routing. Switching a reasoning model never re-embeds the corpus or removes knowledge/skill access.

The supplied immutable review ZIP has SHA256 `e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025`. It supplies 21,012 record identities, 34,229 semantic chunks, 39,985 aliases, 21,359 raw artifacts and 994 governance rows; 150 raw omissions are explicit. Records are 21,011 advisories and one reference, with no full-text bounty reports. MiniLM embeddings remain 384-dimensional at full revision `d13954661f83248295ba75c1ed411eef3b7b936e`. Supplied IDs, chunk positions, text/vector mapping, finite dimensions, norms, model/raw hashes and archive safety are verified before writes.

`corpus_package.py` restores only into an empty compatible store or verifies an identical completed fingerprint. It does not overwrite a populated or changed corpus. Model files are installed without replacement. PostgreSQL receives the supplied vectors in pgvector columns; development SQLite preserves the same identities and vectors. Missing semantic assets produce an explicit unavailable result; hash retrieval is confined to labelled fixtures.

`corpus_transfers.py` exposes bounded resumable 8 MiB parts with SHA/order/idempotency checks, owner quotas and a durable fenced restore job. The browser shows actual persisted upload/import state. CLI host inspection/restore uses the same service and supports bounded private stdin.

Retrieved records carry identities, canonical hashes, sources, chunk provenance and curation state. Selective metadata/exact-ID/semantic retrieval avoids whole-corpus prompts. Skill references are discovered separately and retain source/license/version/hash. Feedback is pending review, never automatic trusted promotion. Automatic context retrieval and explicit tool calls record the originating task.

The optional fresh audit classified metadata detections separately and identified fourteen fields across eight records for protected model/UI views. Stored records, vector rows, original hashes, raw files and ZIP remain intact. Known withheld raw artifacts are recorded. Private backup/export remains distinct from a public corpus publication.

Actual acceptance restored the corpus into both application development and isolated PostgreSQL deployment. All 34,229 pgvector columns are populated, actual neural searches returned attributed hits, upstream LFS confirmed the pinned ONNX hash, and five labelled application queries passed hit@5. These measurements do not establish broad recall or replace the missing full-text report collection. See the [current acceptance report](docs/test-results/DEPLOYMENT_ACCEPTANCE_2026-11-10.md).
