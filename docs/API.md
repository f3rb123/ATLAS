# API and CLI

The Web UI and `atlas` CLI use `/api/v1` on the same FastAPI application. The complete generated contract is [openapi.json](openapi.json). The authenticated `/api/v1/schema` endpoint returns the live contract; public interactive API documentation is disabled.

Browser sessions use opaque HttpOnly cookies, same-origin checks and a session-bound `X-CSRF-Token` on mutations. Production requires HTTPS and a `__Host-` cookie. Password login alone grants no research access. Owner settings additionally require recent WebAuthn authentication. CLI tokens are separate, hashed, scoped and revocable; sensitive administrative scopes expire after five minutes.

| Resource | Operations |
|---|---|
| auth | Host bootstrap redemption, password login, WebAuthn registration/authentication, TOTP enrollment/fallback, recovery, sessions and CLI tokens |
| campaigns | Create with authorization attestation, edit/archive, validate/version frozen scope, attach ZIP or bounded HTTPS GitHub source, start run |
| runs | Read, pause/resume/cancel, exact offline approval, SSE journal, source/threat-model/slice/hypothesis/tool evidence, reports |
| providers | Encrypted create/edit/rotate/delete, enablement, safe discovery, model registration/edit, structured capability probe and immutable metadata history |
| model-configs / budgets | Explicit aliases and global cap; run creation pins model/provider/skill/policy versions and hard limits |
| corpus / knowledge | Real statistics, native source sync/resume, background document conversion, indexing, attributed search, schema validation, rights review, deduplication/curation, lineage/export/delete |
| skills / registries | Declarative SKILL.md/ZIP import, human review, exact-hash fixture binding, validation, enable/disable/rollback, review-only historical seed manifests |
| benchmarks | Offline fixture harness and separately budgeted configured-model evaluation |
| admin / doctor | Emergency stop and operational readiness; no public registration or remote account-recovery endpoint |

Object reads/mutations enforce ownership. List endpoints accept bounded `offset`/`limit`. Run creation supports `Idempotency-Key`. SSE accepts the last event ID for reconnect. Denials and state transitions are durable, hash-chained events. Validation responses omit submitted secret values. Reports escape untrusted HTML and distinguish confirmed findings from hypotheses.

## CLI

```sh
uv run atlas --help
uv run atlas campaign --help
uv run atlas run --help
uv run atlas provider --help
uv run atlas corpus --help
uv run atlas host --help
```

Set `ATLAS_API_URL` to the exact API origin. Load a scoped token into `ATLAS_CLI_TOKEN` using your shell's protected secret workflow; do not put it into command arguments, history, Git or shared logs. Provider creation/key rotation use protected prompts. Core examples:

```sh
atlas doctor
atlas campaign list
atlas run status RUN_ID
atlas run events RUN_ID
atlas corpus stats
atlas provider list
```

Use `--help` for versioned argument names and file-based inputs. All remote commands call the API, including corpus administration. `atlas host` operations deliberately require local filesystem/database access: key initialization, migrations, single-use owner bootstrap, audited break-glass reset, KEK rewrapping, lawful acquisition and canonical corpus/vector transfer. Host recovery revokes old sessions/tokens. It is not exposed through the API.

Provider protocols and trusted plugin installation are documented in [PROVIDER_SDK.md](PROVIDER_SDK.md). Declared capabilities are not proof. Research routing requires a successful structured-output probe. Native function calling remains blocked unless independently verified; the production research workflow uses strict structured proposals through the typed broker. Vision metadata does not enable image execution or an unimplemented vision workflow.

## 10 November 2026 additions

The generated `openapi.json` is current. `engagements` provides durable conversation, preferences, readiness and start; creation/message/preferences require campaign scope and start requires run scope. `tools` lists typed capabilities and API/MCP connections; connection mutations use sensitive tool scope and operator authorization. `model-routing` provides status and a zero-token preview. `budgets/tokens` exposes the persistent ledger and explicit allocation/reconciliation. `corpus/transfers` provides bounded resumable package import. Run research-notes/attack-chains/tasks endpoints preserve attribution and independent evidence gates. Finding metadata cannot change verification/evidence; report-ready transitions remain gated and exportable.
