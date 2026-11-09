# Current rebuild continuation — 2026-11-09

Read ATLAS_HANDOFF.md, ATLAS_V3_IMPLEMENTATION_LEDGER.md and the eight requested project documents first. Native concurrent/knowledge-aware core is implemented and locally verified (138 backend tests, one semantic case unrun; browser/build passed). Full rebuild is not complete.

Saved install/start instructions use existing isolated checkout and .runtime/cloud-dev. No worktrees, reset, push, production-data operation or VPS deployment without authorization. Apply four domain additions before retrying missing references/model preparation. Original corpus/model assets are withheld; do not recreate/re-embed them. Configure owner providers securely before real-model lab acceptance. Continue routing/fairness, advanced recon/MCP, chain analysis and engagement chat from the rebuild roadmap.

## Preserved original release handoff

# ATLAS V3 delivery state

The current release handoff is a manual-install source package. No VPS connection or deployment, GitHub publication, or external target test was performed.

## Verified starting point

- Initial requested checkpoint: `12e4bbc`; existing tag `v3.0.0-rc1-local` was present and is preserved at its original commit.
- Starting backend regression: 87 passed. A latent kill-switch path shadowed the `control()` function with a local result name; the local variable is renamed and a cancellation regression test is added in the final package commit.
- Existing local Compose stack, production frontend build, backend services, database migrations and corpus validation had been checked during the prior checkpoint. Current test and package results are in `docs/test-results/VALIDATION.md` and the generated release manifest.

## Artifacts and security gates

- `atlas-v3-deployment.zip`: source-only tracked project archive; generated with the final package commit.
- `atlas-v3.bundle`: offline Git history/ref bundle; original `v3.0.0-rc1-local` tag retained.
- `SHA256SUMS` and `RELEASE-MANIFEST.md`: generated beside the downloadable artifacts.
- No corpus tarball is delivered. Candidate scan: 2,151 findings, of which 2,125 are documented detector false positives and 26 remain unresolved content candidates. See `docs/test-results/corpus-secret-audit.json`; no finding values are recorded.
- No real credentials, runtime databases, user/session data, private keys/certificates, master key, bootstrap/recovery material or private campaign data are packaged.

## Operator steps

Download and verify the source ZIP and bundle, transfer over WinSCP/SFTP using the private VPN, and follow `docs/DEPLOYMENT.md`. Generate the encryption master key on the VPS, initialize/migrate the database, enroll the first owner interactively, configure recovery and TLS, and register a custom provider through Settings. Keep ingress VPN-only. Corpus import must wait for a future separately reviewed archive.
