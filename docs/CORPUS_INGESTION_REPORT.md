# Corpus acquisition and conversion report

This report describes actual persisted public data acquired on2026-11-08UTC. The source inventory is [corpus_inventory.json](../knowledge/corpus_inventory.json); machine validation evidence is [corpus-validation.json](test-results/corpus-validation.json). Test fixtures and benchmark cases are excluded from these counts.

| Source | Unique canonical records | Acquisition and rights |
|---|---:|---|
| GitHub Advisory Database | 21,000 | Official github-reviewed advisory archive; CC-BY-4.0 |
| CVE Program | 1 | Official CVE List v5 seed; CVE terms retained |
| NVD | 5 | Official public API; NIST public-information terms with marked-content exception |
| CISA KEV | 5 | Official cisagov/kev-data mirror; CC0-1.0; pinned commit e5b3a9b25050a8da26c96266c5bfe438ee0bdebc |
| OWASP Authorization Cheat Sheet | 1 | Licensed training/reference document; CC-BY-SA-4.0; source metadata currently uses the owner-import adapter |
| OSV | 0 additional | Five real GHSA-origin OSV entries linked to existing records; upstream-dependent rights remain restricted for unknown sources |
| **Total** | **21,012** | **21,011 structured advisory/CVE records and1 training/reference** |

Full-text technical/bounty reports: **0**. Patch-only records: **0**. Separately governed historical seed resources and skills do not inflate corpus totals. The missing historical64/67 manifest is not reconstructed or claimed present. Rights-reviewed owner URL/file/ZIP imports are implemented, but no unrestricted bulk-disclosure permission is assumed.

There are **39,985 aliases** and **34,229 chunks**, with genuine pinned MiniLM384 embeddings for all21,012records. These are derived objects, not independent vulnerabilities. Record counts are canonical entities after official alias linking; they are not a claim that every advisory represents a distinct independently verified vulnerability.

## Provenance, exclusions and limitations

Every stored public record validates as ATLAS-RR1.0 and retains a lawful native raw artifact, SHA256, original source URL, parser/version, rights and provenance. API feed wire artifacts additionally preserve the original response bytes and JSON pointer. Date-only sources remain date-only; unknown technical facts stay null. Native aliases/revisions are linked without discarding raw lineage. Owner documents remain private by default. Public-source raw files, canonical exports and model cache are local runtime artifacts; source Git contains code/manifests/evidence, not the bulk corpus or secrets.

The initial GHSA import processed21,491eligible archive entries:21,000ingested and491excluded with a generic ValueError event. All491were subsequently rechecked against the official pinned snapshot `a44cc4e2c07944bd982101942644cebdcc646953`: all are withdrawn advisories, zero unresolved. Each review stores its source artifact/hash and original error ID. Original error events/job counts remain preserved. Parser errors:0; unclassified import errors:0. New imports record explicit upstream-withdrawal exclusions/takedowns.

The first archive was acquired from `main` before snapshot pinning was added. Its original per-record raw bytes/hashes survive, but the exact archive commit cannot be retroactively asserted. Subsequent bulk jobs resolve and persist an immutable Git SHA. The exclusion-review SHA is a new audit snapshot, not a fabricated original-acquisition SHA.

Initial NVD/OSV/KEV jobs failed under the earlier network policy and remain in history. Later NVD and OSV requests succeeded. The CISA primary feed returned403; the official synchronized GitHub mirror, documented by CISA for alternate machine access, succeeded with a pinned commit. No paywall, authentication requirement or robots denial was bypassed. General web writeups require an explicit source policy, rights review and robots check before bounded exact-URL acquisition; there is no recursive crawler.

## Restart and validation evidence

The semantic reindex job `48100d85-1da7-481f-be01-43757e61cd34` was interrupted and resumed from its durable cursor; the first21,007records completed and the five later KEV records indexed on ingestion. PostgreSQL transfer was also interrupted by local container recreation and resumed idempotently; the final active index covers every public parent. Vector import now commits bounded200-record batches and skips byte-identical completed batches.

`python scripts/validate-corpus.py` independently validates canonical schemas, original raw hashes, finite vectors, model dimensions/checksums and complete parent coverage. The same records and all34,229semantic chunks were loaded into local PostgreSQL/pgvector. Retrieval evaluation uses the small versioned `knowledge/retrieval_queries_v1.json` diagnostic set; its scope and measured results are reported separately, without extrapolating to general vulnerability-research precision.

PDF page extraction/provenance, ZIP multi-page grouping, DOCX, Markdown/text/HTML, JSON/JSONL/CSV/native advisory conversion, private-owner isolation, official alias bridges, revisions, malformed records and checkpoint/resume behavior are covered by fixture tests. Fixture data is never counted as acquired public data. Source deletion removes derived records/chunks/aliases; shared feed artifacts and encrypted backups follow the separately documented retention policy.

## Repeatable commands

```sh
uv run atlas host embeddings-prepare
uv run atlas host corpus-sync --source ghsa --limit 21000
uv run atlas host corpus-validate
uv run atlas host corpus-reembed
uv run python scripts/validate-corpus.py
```

Use `--help` for resume/job IDs and export/transfer options. Native source limits and terms remain authoritative. Reacquisition from a later source snapshot can legitimately change counts; compare persisted provenance rather than forcing this build's numbers.
