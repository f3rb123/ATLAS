# ATLAS V3 handoff

The implemented workbench is a controlled-deployment candidate. The real public corpus, semantic index, local integration tests and deployment assets are present. No owner VPS was deployed, no real target was scanned and no paid provider key was supplied or fabricated.

Start with [README](../README.md), [deployment](DEPLOYMENT.md), [API/CLI](API.md), [security review](SECURITY_REVIEW.md), [corpus report](CORPUS_INGESTION_REPORT.md), [requirement ledger](IMPLEMENTATION_GAP_ANALYSIS.md) and the exact [validation report](test-results/VALIDATION.md).

## Local artifacts

The runtime delivery directory is intentionally ignored by Git:

- `.runtime/delivery/atlas-v3.bundle`: complete local source Git history/checkpoints and baseline.
- `.runtime/delivery/atlas-v3-public-corpus.tar.gz`: actual public canonical records, real vectors, original public artifacts, public-source governance and pinned model cache with attribution.
- `.runtime/delivery/SHA256SUMS`: integrity checks for the delivered archives.

The corpus archive is159,978,397bytes. It contains21,012canonical records and34,229vectors, not a mocked or synthetic20K dataset. Full-text bounty-report count remains0. Preserve source-specific licenses/terms under knowledge/licenses. Neither archive contains an application master key, service/API credential, session/user database or private campaign.

Git checkpoints are local and have not been pushed to the user's remote. Do not assume that cloning the remote's original main branch restores this implementation. Use the reviewed bundle/source archive or explicitly publish the local branch through the owner's authorized Git workflow. The cloud setup draft saves tested dependency/start instructions; it does not itself push code or prove remote-ref restoration.

## First owner and models

The disposable build owner was removed from the main development database while preserving public corpus and immutable audit. The local PostgreSQL stack is also left without an owner account. Generate a new single-use bootstrap token on the intended host, redeem it locally, enroll passkeys, TOTP and offline recovery codes, then configure and probe an owner-supplied model connection. Research access in production remains blocked until enrollment completes. There is no default username/password or public signup.

For the development UI on localhost3000, use ATLAS_EXTERNAL_URL=http://localhost:3000 for API/workers, the same database/data directory and the existing separately stored master key. Do not overwrite that key when restarting. Production uses the scoped Docker-secret volumes and HTTPS origin described in DEPLOYMENT.md. Bootstrap/recovery material is displayed only interactively; do not paste it into logs or prompts.

## Corpus transfer to Compose

Review/extract the public corpus package into a private staging directory. From the application checkout with the target stack already initialized:

```sh
# Set this to the reviewed extraction directory, not to a URL.
ATLAS_CORPUS_DIR=/path/to/extracted/public-corpus
tar -C "$ATLAS_CORPUS_DIR" -cf - corpus_raw models | docker compose exec -T api tar -C /data --skip-old-files -xf -
docker compose exec -T api atlas host corpus-load < "$ATLAS_CORPUS_DIR/corpus.semantic.records.jsonl"
docker compose exec -T api atlas host corpus-load-vectors < "$ATLAS_CORPUS_DIR/corpus.semantic.vectors.jsonl"
```

Use the production/cloud/staging overrides appropriate to that host consistently with docker compose commands. Validate canonical records/raw hashes/active vector coverage in the target application context before retrieval. Canonical and vector loading is idempotent/bounded. The public governance JSONL is historical acquisition metadata; it is not permission to overwrite authentication/settings. An encrypted full database/artifact backup is a different operator-controlled recovery product and requires separately protected backup password and KEK.

## External inputs and disabled features

The exact historical64/67resource manifest, rights for unknown full-text writeups, paid-provider live-service behavior, the owner's real-domain certificate and VPS/SSH/firewall posture need owner inputs/authorization. Advanced mobile/cloud/fuzzing/state-changing adapters and unvalidated skills/capabilities remain disabled. The five-query retrieval and local invariant/model fixtures do not establish universal vulnerability discovery or production throughput.

The cloud configuration draft was saved successfully with tested install/start instructions. Review and save it in environment settings, then publish the environment to activate those settings. Network policy and repository membership were preserved. Local-only commits still require the bundle or an owner-authorized remote publication path for reliable fresh-task recovery.
