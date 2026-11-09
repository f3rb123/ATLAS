# ATLAS V3 handoff

The implemented workbench is a controlled-deployment candidate. The real public corpus, semantic index, local integration tests and deployment assets are present. No provider credential was supplied to the application, and no real target was scanned.

Start with the [README](../README.md), [deployment guide](DEPLOYMENT.md), [API/CLI](API.md), [security review](SECURITY_REVIEW.md), [corpus report](CORPUS_INGESTION_REPORT.md), [requirement ledger](IMPLEMENTATION_GAP_ANALYSIS.md) and [validation report](test-results/VALIDATION.md).

## Publication and deployment status

The appropriate GitHub repository is the existing private repository owned by f3rb123. Source publication is paused at the user's request while VPS access is attempted first. No remote branch or release was pushed from this checkpoint.

The operator deployment guide and VPN-only Compose/Caddy configuration are ready. The requested VPS did not accept TCP SSH on port 22, so no credentials were sent and no remote service, database or file was changed. The user must restore an authenticated SSH path and verify the host key before remote setup can continue.

The current corpus transfer archive is a sanitized candidate, not a release asset. It retains 21,012 canonical record identities and 34,229 vectors; 220 text fields were sanitized, 130 affected vectors were recomputed with the pinned model, and 150 raw artifact files were withheld in the delivery copy. The acquisition database and original source artifacts on the build host remain unchanged. A fresh Gitleaks scan of the expanded candidate still reports 2,151 findings. The canonical-key field and pinned model revision explain many detector hits, but residual content findings have not yet been cleared. Do not upload or transfer this candidate until the remaining findings are classified and the full intended-public payload passes review.

Local candidate path: .runtime/delivery/atlas-v3-public-corpus-sanitized.tar.gz

## First owner and models

The disposable build owner was removed from the main development database while preserving public corpus and immutable audit. The local PostgreSQL stack is left without an owner account. Generate a new single-use bootstrap token on the intended host, redeem it locally, enroll passkeys, TOTP and offline recovery codes, then configure and probe an owner-supplied model connection. Production research remains blocked until enrollment completes. There is no default username/password or public signup.

For the development UI on localhost:3000, use ATLAS_EXTERNAL_URL=http://localhost:3000 for API/workers, the same database/data directory and the existing separately stored master key. Do not overwrite that key when restarting. Production uses the scoped Docker-secret volumes and VPN/TLS setup described in DEPLOYMENT.md. Bootstrap and recovery material is displayed only interactively; do not paste it into logs or prompts.

## Corpus transfer procedure

After the corpus scan blocker is resolved and a reviewed private release asset is published, verify its published SHA256 before extraction. Follow DEPLOYMENT.md to import the JSONL records, vectors, raw artifacts and model cache into an initialized target stack. The import is additive and idempotent; do not reset a database or remove volumes to resolve import errors. The packager checks the source inventory, pinned model checksums, archive paths and member types, then records delivery redactions and withheld raw artifacts in CORPUS_REDACTIONS.json.

The public governance JSONL is historical acquisition metadata; it is not permission to overwrite authentication/settings. An encrypted full database/artifact backup is a different operator-controlled recovery product and requires a separately protected backup password and KEK.

## External inputs and disabled features

The exact historical 64/67-resource manifest, rights for unknown full-text writeups, paid-provider live-service behavior, the owner's real-domain certificate and VPS/SSH/firewall posture need owner inputs/authorization. Advanced mobile/cloud/fuzzing/state-changing adapters and unvalidated skills/capabilities remain disabled. The five-query retrieval and local invariant/model fixtures do not establish universal vulnerability discovery or production throughput.
