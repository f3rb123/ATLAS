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
