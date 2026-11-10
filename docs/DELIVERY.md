# ATLAS V3 private source delivery

This is a locally validated private deployment candidate, delivered for owner review/manual installation. No GitHub push, public publication, real VPS change or live target scan occurred. See [current acceptance](test-results/DEPLOYMENT_ACCEPTANCE_2026-11-10.md) for actual versus synthetic evidence and remaining external inputs.

## Artifacts

The ignored `.runtime/delivery/` directory contains:

- `atlas-v3-deployment-source.zip`: the final committed tree under `ATLAS/`.
- `atlas-v3-complete.bundle`: complete available Git history/refs, including branch `work` and preserved original tags.
- `SHA256SUMS`: hashes for the source ZIP and Git bundle.
- `RELEASE-MANIFEST.md`: exact commit, artifact inventory, validation and operational boundaries.

No runtime database, corpus ZIP, model binary, user/session data, provider credential, master key, private certificate, SSH key, bootstrap/recovery code or private program screenshot is included. The `.env.example` and `.env.production.example` files contain placeholders. The owner's raw `.env` is ignored and unchanged. The bundle was verified and round-tripped into a fresh temporary clone; the ZIP is checked against the final tracked tree. Full history/source secret scans and exact credential exclusion checks accompany packaging.

## Preserve intelligence and budgets

The supplied corpus archive is separate and immutable, SHA256 `e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025`. It was actually restored into development and isolated PostgreSQL: 21,012 records, 34,229 384-dimensional vectors, 39,985 aliases and 21,359 raw artifacts. It contains advisories/reference material and no full-text bounty reports. Preserve its explicit omissions, review masks and pinned model. A public corpus publication requires its own review; no such publication occurred.

Existing paid deployments must migrate their complete database, artifacts and matching key material through the verified private backup procedure. Retain the global token ledger and every uncertain reservation. Never create two independently spending copies of the paid ledger. Current recorded usage is 744,368 tokens, held capacity 282,255, initial allocation remaining 973,377; USD pricing/billing remains unverified. A fresh development fixture database is not a substitute for that history.

## Install and restore

Verify SHA256SUMS before and after SFTP transfer. Extract into a new directory; do not overwrite a populated checkout or application store. To restore source from the offline history, use `git clone --branch work atlas-v3-complete.bundle ATLAS` in a fresh destination. Preserve existing release tags rather than moving them.

Follow [DEPLOYMENT.md](DEPLOYMENT.md). Use an explicit `.env.production` configuration file or `ATLAS_COMPOSE_ENV_FILE`; `scripts/compose.sh` never parses the owner's raw `.env`. Generate new host secrets only for a fresh installation, bootstrap the owner interactively, configure the desired optional/strict MFA policy, restore the separately verified corpus and test provider aliases. Original/production database migration, DNS/VPN/ACME and public ingress remain owner-controlled deployment operations.

The next external inputs are verified model pricing and five billing outcomes, a specific verified SBI hostname, missing original private/full-text assets/resource manifest, and an actual authorized deployment destination. Optional scanner/unsupported API adapters and unreviewed executable skills remain visibly disabled with harness/fixture requirements. Their presence in the registry is not a claim of operational scanning capability.
