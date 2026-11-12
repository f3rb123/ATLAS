# SKUNK build delivery — 12 November 2026

- Public CLI/brand: SKUNK; internal package: atlas.
- Build source: 44000e6, on skunk/cli-20261112, starting from attached owner baseline a3824e5.
- Prebuilt Linux x86_64 archive: skunk-linux-x86_64.tar.gz.
- Archive SHA256: `41d4660e6c32c0823c76905894fac06cf667ef42f520944634bdaafd825c5abb`.
- Original knowledge ZIP remains byte-identical: e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025.
- Payload includes Python 3.12.15, locked dependencies, eight pinned native tools/licenses, ATLAS source/migrations, knowledge/model file and install script.
- Build-only checks: Python bytecode compilation, shell parsing, dependency/package assembly and asset digests. No application startup, tests, model inference, browser exercise, target scans or VPS deployment.
- Runtime/production acceptance remains deferred. Existing source documentation describes original historical acceptance and does not verify this new CLI.

Delivery files are under /workspace/library-files. The knowledge ZIP is inside the full archive and also delivered separately for the requested folder workflow.

## GitHub distribution

Owner authorized uploading the source and all delivery files. Release: [skunk-v3.1.0rc1-20261112](https://github.com/f3rb123/ATLAS/releases/tag/skunk-v3.1.0rc1-20261112). Source branch: `skunk/cli-20261112`. The original six files are unchanged; `SHA256SUMS` covers them. The release tag may include delivery-only documentation after the build commit. See `release/skunk-cli-20261112/RELEASE-NOTES.md` for download/install commands and exact file identities.

Publication complete: seven attachments uploaded through [the attachment-only workflow](https://github.com/f3rb123/ATLAS/actions/runs/43142386193) and published as a prerelease. GitHub byte sizes and SHA256 digests match every local original. The release tag points to 76ef8c7 (delivery documentation); bundle/source archive remain built from 44000e6. See `release/skunk-cli-20261112/PUBLISHED-ASSETS.json`. Runtime acceptance is unchanged.
