# Current support: Docker 29 prebuilt installer compatibility

The published prebuilt assets remain unchanged. Owner installation stopped at
image identity validation before data initialization. Docker 29.9.3 returns OCI
manifest IDs whereas the builder recorded configuration IDs. Fixed verifier
streams docker save metadata and cryptographically checks the tag/config mapping
and platform. scripts/repair-prebuilt-docker29.py verifies original checksums and
adds separate corrected files; original installer/payload/checksum files are not
changed. Publish the small repair on the existing delivery branch with skip ci;
provide pinned downloads and resume via install-prebuilt-docker29.sh. Do not
skip image checks, reset data, change the Docker storage driver or re-download
the complete bundle. Actual Docker 29 execution awaits the owner's result.

Prior delivery evidence: docs/DELIVERY_PREBUILT_2026-11-10.md. No application
acceptance tests, paid calls or target scans are authorized on startup. Preserve
original private assets/keys, corpus/vectors and the authoritative 50M cap/2M
allocation: 744368 consumed, 282255 held, 973377 available initial after holds.
Never reset/release uncertain holds/replay unknown calls or create spending
clones. Keep SSH credentials and private server metadata out of public commits.
