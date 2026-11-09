# ATLAS V3 local deployment delivery

This release package is for manual installation by the owner. Nothing has been deployed to a VPS or published to GitHub. The source ZIP and offline Git bundle contain no application database, corpus database volume, user/session data, provider credentials, master key, private certificate, SSH key, bootstrap token, recovery code or campaign finding.

## Package contents and provenance

The deployment ZIP is a source-only archive of the final committed tree: backend, frontend, migrations, Compose/Docker configuration, gateway/provider integrations, owner authentication and encrypted secret handling, orchestration/verifier/sandbox, ingestion/conversion tools, tests, deployment scripts and documentation. `.env.example` and `.env.production.example` are placeholders. The separate Git bundle preserves all available refs/history and the existing `v3.0.0-rc1-local` tag. The working release package is based on the verified `12e4bbc` checkpoint plus the narrow kill-switch shadowing fix and regression test; the tag itself is preserved at its existing commit and was not moved.

The ZIP, bundle, `SHA256SUMS` and `RELEASE-MANIFEST.md` are generated under ignored `.runtime/delivery/` and linked as downloadable artifacts in the handoff. SHA256SUMS covers the ZIP and bundle. The manifest includes their hashes, exact commit, retained tag, validation evidence, package inventory, corpus counts and limitations.

## Corpus gate

The validated local corpus inventory is 21,012 unique public record identities and 34,229 finite MiniLM 384-dimensional vectors. The sanitized candidate inventory is 21,012 records, 34,229 vectors, 994 governance documents and 21,636 archive members; 220 text fields were sanitized, 130 vectors re-embedded, and 150 raw artifacts withheld. No application database or Docker volume is distributable.

The expanded Gitleaks scan produced 2,151 detections. The safe finding-by-finding classification is recorded in [corpus-secret-audit.json](test-results/corpus-secret-audit.json), without reproducing any matched values. It classifies 2,125 as detector false positives: 2,067 canonical-key property names, two schema version values, 53 pinned model-revision occurrences, and three verified public model SHA256 values. **Twenty-six content candidates remain unresolved:** 13 in record content/summary fields, nine in vector text fields and four in three raw artifacts. They include generic credential-pattern, Sourcegraph-token-pattern and private-key-pattern detections. Because these values have not been resolved as harmless, the public-corpus tarball is deliberately omitted. Do not transfer the ignored local candidate archive. The source ingestion and validation pipeline remains included.

## Install

Follow [DEPLOYMENT.md](DEPLOYMENT.md) for a clean Ubuntu installation. In brief: verify the downloaded SHA256 values on Windows, transfer the ZIP and bundle with WinSCP over SFTP through the private VPN, verify checksums again on Ubuntu, extract into a new directory, configure `.env.production`, create the host-only master key with `scripts/prepare-secrets.py`, start the VPN-bound Compose stack, enroll the first owner interactively, configure two passkeys/TOTP/recovery, then register a provider through Settings. Do not enable public ingress before those checks pass. Corpus import is unavailable from this delivery until the candidate scan blocker is cleared and a new archive is separately reviewed.

## Validation and limitations

The current backend regression suite is rerun as part of this packaging task; see [test-results/VALIDATION.md](test-results/VALIDATION.md) and `RELEASE-MANIFEST.md` for final results. Existing evidence covers the real local database/corpus, browser/WebAuthn, sandbox, Docker TLS, backup/restore and provider-contract workflows. A full-project Ruff run has pre-existing style findings; Bandit has reviewed medium pattern findings. No external target, GitHub publication or owner VPS operation occurred. Provider credentials, host master key, TLS enrollment, first-owner bootstrap and VPN/firewall configuration must be supplied or performed by the operator on the VPS.
