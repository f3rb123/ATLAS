# Published all-in-one prebuilt release — 10 November 2026

Release: https://github.com/f3rb123/ATLAS/releases/tag/atlas-v3-prebuilt-20261110

Direct ZIP: https://github.com/f3rb123/ATLAS/releases/download/atlas-v3-prebuilt-20261110/atlas-v3-prebuilt-20261110.zip

Checksum: https://github.com/f3rb123/ATLAS/releases/download/atlas-v3-prebuilt-20261110/atlas-v3-prebuilt-20261110.zip.sha256

- Published at 17:16:51 UTC; GitHub release ID 440649701; public prerelease.
- ZIP: **915,558,886 bytes**, SHA256
  `864592232af31678ca56ae0830fc5ffc60a9529ee8a25e95b386707c6d117b7c`.
- Public download HEAD returned 200 and the expected content length.
- All five assets are uploaded: ZIP, checksum, README-FIRST.md,
  RELEASE-MANIFEST.md and BUILD-RECORD.json.
- Application/installer source is tag bdf49a9957cb3f48559fbaa20ad0642d0700e8e3.
  Its engine/frontend trees equal 5a7834d. GitHub rebuilt the images from bdf49a9.

The ZIP includes five Linux amd64 images: API/workers with eight pinned native
binaries, frontend, PostgreSQL/pgvector, Redis and Caddy. It includes the original
corpus, all 34,229 real 384-dimensional vectors and MiniLM model assets. The
installer imports knowledge automatically without compiling ATLAS, pulling
images, downloading models or re-embedding. Corpus count is 21,012
advisory/reference identities and **zero full-text bounty reports**.

Private provider/SSH/API credentials, accounts/databases and original keys are
excluded. Owner bootstrap and secure provider configuration remain necessary.
Historical consumption/uncertain holds are retained as a conservative non-secret
floor; detailed private history requires the original private store. Keep one
spending instance.

The workspace's first image export produced a different valid archive:
915,809,043 bytes, SHA256 d820d124c110c93aa11d6ee1bea5cd7f58b12e28e7b7f8c1842da9f9c0b04fe8.
That local file is preserved. **Use the checksum beside the GitHub download;
do not interchange hashes between independently built archives.**

Direct workspace uploads returned 401 from uploads.github.com. The build-only
GitHub publisher then built and uploaded the complete assets. Its final
unpublished-release lookup by tag returned 404 after upload; assets were verified
by release ID and published from this workspace. The workflow lookup is fixed
for future use. The historical job remains failed; this is not represented as a
passed workflow or product acceptance.

No application tests, installer execution, candidate container startup, paid
inference or target requests occurred in this phase. Runtime/production
acceptance remains deferred at the owner's request. This is a release candidate,
not completion of every original requirement. VPS access is blocked before
login; no remote changes occurred. Original private state and volumes remain.
