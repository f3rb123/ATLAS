# Reproducible dependencies

Python3.12+, uv, Node24, npm and Linux Bubblewrap are the development prerequisites. Production uses the pinned images in Dockerfile.api, Dockerfile.web and compose.yaml: Python, Node, PostgreSQL17 with pgvector, Redis7.4 and Caddy2.10.2. No GPU or local generative model is required.

`uv.lock` pins direct/transitive Python packages. `requirements.lock` is a hash-pinned export including the build backend, consumed with pip `--require-hashes` in the multistage image. `apps/web/package-lock.json` pins npm packages; use `npm ci`. Do not replace lockfiles with floating installs during deployment.

| Component | Principal dependencies | Purpose |
|---|---|---|
| API/domain | FastAPI, Pydantic, SQLAlchemy, psycopg, Alembic | Validated contracts and durable PostgreSQL state |
| Authentication/secrets | Argon2-cffi, WebAuthn, pyotp, cryptography | Argon2id, passkeys, TOTP, envelope/backup encryption |
| Workers/transport | Redis, httpx, Bubblewrap, Git | Hints, internal services, offline isolation, bounded source acquisition |
| Corpus | BeautifulSoup, pypdf, python-docx, NumPy, pgvector, FastEmbed/ONNX Runtime | Real conversion, attribution and semantic retrieval |
| Reports/CLI | ReportLab, Typer | PDF and API-backed command interface |
| Web | Next.js16.4.5, React19.3.1, SimpleWebAuthn | Authenticated research workspace |
| Validation | pytest, Hypothesis, Playwright, axe-core | Domain/property/sandbox/browser/accessibility checks |

The semantic model is downloaded separately using `atlas host embeddings-prepare`. Its exact repository revision, file SHA256 values, dimension384 and license are in `knowledge/embedding_model.json` and packaged `atlas/data/embedding_model.json`. Weight integrity is checked before inference. Inference is local and does not send corpus text to an embedding service. The explicit `ATLAS_EMBEDDING_MODEL=hash` setting is a labelled lexical fallback for offline tests; it is not counted as semantic indexing.

The cloud-only Compose override mounts the session's public CA bundle at runtime for egress services. The build uses a CA secret and temporary certificate directory; it does not bake the session CA or credentials into an image. Native target/provider connections retain TLS verification and inherited HTTP proxy behavior. Never use TLS-verification bypasses.

CI installs Bubblewrap on Ubuntu22.04, prepares the genuine pinned embedding model, runs the complete Python suite, builds the Web UI and runs Playwright against disposable fixture databases. CI's one-record training fixture is explicitly synthetic and does not assert the real20K acquisition gate. The local persisted corpus and acquisition report supply scale evidence.

Runtime Python and production npm dependency audits reported zero known vulnerabilities for these locks during the recorded build. This is a dated advisory check, not a permanent guarantee. Review future updates and re-run audits before exposure. Moby's sandbox seccomp profile attribution/license is retained under `infra/security/`.
