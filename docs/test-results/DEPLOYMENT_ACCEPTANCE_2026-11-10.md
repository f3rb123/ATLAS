# ATLAS V3 local deployment acceptance — 10 November 2026

This is a locally validated deployment candidate. No GitHub push, publication,
public deployment, owner VPS operation or SBI target request was performed.
Dates in the user interface use Asia/Calcutta; persisted event timestamps use UTC.

## Actual provider and credential evidence

HackerAI at `https://api.hackerai.sh/v1` was reached using
`custom_openai_compatible`. Actual discovery confirmed both exact owner-selected
IDs: `deepseek-v4.1-flash` and `deepseek-v4-pro`. Each passed a real structured
JSON probe and native `acceptance_echo` tool-call probe. The primary reasoning,
fast and coding aliases use Flash; deep research and independent verification
use Pro. Automatic routing considers only explicitly configured aliases pinned
to provider/model versions. No unavailable model was silently substituted.

The owner's `/workspace/ATLAS/.env` remains a raw credential file, mode 0600,
ignored and untracked, with its original format preserved. The selector is
`ATLAS_PROVIDER_KEY_FILE`; the application credential binding is the existing
write-only `ProviderInput.api_key`, encrypted in provider settings. Runtime
adapters decrypt the envelope in the credential service. Keys do not enter
worker containers, prompts, command arguments, reports or release artifacts.
Dotenv parsing requires the separate explicit `ATLAS_CONFIG_FILE` selector.
Compose uses an explicit configuration file and does not parse the raw `.env`.

## Actual model acceptance and failures

The authored local source lab used the real provider, existing corpus and
original global ledger. Eight distinct initial roles completed real reasoning
tasks. Cited discoveries activated two GraphQL follow-ups, which also completed.
All roles used the shared model-independent knowledge interface and attributed
skill/reference discovery. These are actual provider responses over an explicitly
authored local fixture, not evidence of a vulnerability on any public target.

Earlier attempts exposed real defects: a nested 30-second adapter timeout,
untyped hypothesis/experiment schemas, lost tool-result context and incomplete
JSON responses. Those defects were fixed. The adapter timeout is now separately
bounded at 90 seconds, the internal gateway client defaults to 150 seconds,
hypotheses/experiments have complete schemas, evidence survives tool rounds,
and one separately metered schema correction is permitted. Raw JSON envelopes
are parsed before recursive credential scrubbing; exact JSON code fences are
normalized with an explicit warning. Completed malformed responses retain
reported usage. Unknown transport outcomes are never automatically replayed.

The eight-role run is retained as **partial**, because two independent reviews
failed their evidence-binding gate. A subsequent fresh independent proof/control
replay completed and confirmed the authored lab finding, citing both fresh
artifact IDs exactly. It used Pro through the same knowledge/gateway/budget
services. Rejected reviews remain unconfirmed. The report does not relabel an
earlier failed run as an entirely successful run.

Private evidence is retained under ignored `.runtime/readiness/`:
`hackerai-capability-probes.json`, `real-provider-acceptance-*.json`,
`independent-validation-corrected.json` and `token-budget-final.json`.

## Actual token accounting

| Counter | Tokens |
|---|---:|
| Persistent global authority | 50,000,000 |
| Explicit initial allocation | 2,000,000 |
| Provider-reported input | 615,895 |
| Provider-reported output | 128,473 |
| Total recorded consumption | 744,368 |
| Cached input, included in input | 28,730 |
| Reasoning, included in output | 54,892 |
| Outstanding uncertain reservations | 282,255 |
| Allocation remaining after reservations | 973,377 |
| Global allowance remaining after reservations | 48,973,377 |

Five early calls have uncertain billing. Their full reservations remain held;
none was guessed to cost zero or silently reconciled. They no longer occupy
finished local HTTP concurrency slots. Reconciliation requires verified provider
billing evidence. The initial protected validation capacity was 200,000 tokens;
110,298 have been consumed by validation and the remaining protection also
accounts for its pending reservation. No ledger reset or allocation increase
occurred. Synthetic fixture providers in separate disposable test databases are
not represented as paid consumption.

The provider's available metadata and public pricing page did not establish
verified model-specific prices. USD values remain estimates, with actual cost
unconfirmed. Cached-token discounts and reasoning billing are not invented.

## Actual knowledge and deployment evidence

The immutable supplied archive retains SHA256
`e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025`.
Identity-preserving restore ran in the development application and the isolated
Docker PostgreSQL/pgvector deployment: 21,012 records, 34,229 vectors of dimension
384, 39,985 aliases and 21,359 raw artifacts, with 150 supplied omissions recorded.
All 34,229 PostgreSQL vector columns are populated. Actual neural retrieval works.
The model's ONNX hash was also independently matched to upstream Hugging Face
LFS metadata at the pinned full commit. No hash-based substitute or corpus
re-embedding was used. The small labelled retrieval diagnostic passed 5/5 queries;
this is not a broad recall benchmark.

The candidate comprises 21,011 advisories and one reference, with zero full-text
bug-bounty reports. It must not be advertised as 20,000 full research reports.
Eight audited records have fourteen fields masked in model/UI content views;
the original records, vectors, archive and raw files are preserved. Three raw
artifacts remain flagged for withholding from public export. The fresh optional
audit's finding counts differ from the historical audit and are retained separately.

Pinned API/web images built. The isolated Compose stack started with PostgreSQL,
Redis, API, web, gateway, relay and separate workers. TLS was verified against the
stack's generated local CA, without disabling verification. First-owner bootstrap
and database readiness passed. An encrypted database/artifact backup was created,
authenticated and restored into a newly created isolated check database. It
retained migration 0005, 21,012 records and 34,229 chunks. No original/application
database was reset or replaced. Worker restart checks and final image identifiers
are recorded in the release manifest and retained readiness evidence.

The production frontend build and expanded Playwright browser flow passed,
including actual persisted engagement chat/settings, eight-task execution with
an explicitly synthetic local provider, reload persistence, controls, source
upload, CLI, WebAuthn and corpus search. Accessibility checks on welcome, memory,
engagements, tools and budgets found no serious/critical violations. Browser
fixture success is distinct from the real-provider lab above.

## Reference, scope and remaining boundaries

All requested references were read using primary sources. ZSEC's canonical page
returned 403, but its official public RSS supplied the complete article. The
DeepSeek public share read endpoint returned the two-message conversation. The
Maestro source was read at `e46c2ebe1602d8faecb2f6920c091fa7ca105282`.
AntiFox, Armur and Maestro are architecture references; their AGPL code was not
copied. Six MIT methodology texts ship with pinned provenance and license notices
as research data, not automatically enabled executable procedures.

SBI smoke is **blocked on a specific verified hostname**. The owner-supplied
private screenshot authorizes the wildcard `*.sbicard.org`, while the observed
certificate lists only the wildcard and excluded apex. No hostname was guessed,
no `.com` asset substituted, and zero target requests occurred. The available
execution profile allows only root HEAD requests without cookies/query/auth,
at most two requests, and rejects destructive actions outside model control.

Optional scanners, unsupported API adapters, advanced exploitation/fuzzing and
unreviewed executable skills remain explicitly disabled with concrete harness
requirements. SecurityTrails and MCP JSON resource adapters passed controlled
local HTTP tests; no actual third-party API credential/server was supplied.
Original full-text/private assets and the exact historical 64-resource manifest
still require recovery or separately permitted acquisition. No supported transfer
mechanism for a different account's uncommitted workspace was exposed here.

The next operational milestone is an owner-approved private VPS rehearsal with
domain/VPN/TLS settings, verified provider pricing/billing reconciliation, and an
explicitly observed test hostname. Public deployment and live exploitation are
outside this completed local acceptance.

## Final regression and operational refinements

The final complete backend suite passed **213 tests**, including actual semantic
inference, Linux namespaces and disposable PostgreSQL migrations/concurrency.
The two warnings are upstream TestClient deprecation and pgvector reflection.
Finding metadata review now preserves verification/evidence, and confirmed
findings remain exportable after entering report-ready/reported/fixed/closed.
A real temporary SQLite writer-lock test verifies that corpus polling survives
contention. Idle heartbeats are limited to one per process/engine every five
seconds; the SQLite busy wait is 30 seconds. No database replacement is involved.
Destructive target queries reject SQL comment-separated DROP and all remote
command interfaces, in addition to the root-only smoke constraints.

The live application browser also verified Engagements, Recon Tools and Budgets
with zero serious/critical accessibility violations. Its displayed consumption
remained 744,368 tokens with 282,255 held and 973,377 remaining; this UI check
performed no paid inference. Machine evidence is in `test-results/current/`.
