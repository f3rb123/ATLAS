# ATLAS skills inventory

## 10 November 2026 — current deployment work

[Verified through actual execution, 10 November 2026] Deployment completion is now authorized and in progress. The real public candidate was restored into the previously empty development corpus through the new identity-preserving package service: 21,012 records, 34,229 384-dimensional MiniLM vectors, 39,985 aliases, 21,359 hash-verified raw files and 150 explicitly withheld artifacts. A consistent pre-import DB backup was retained. Repeat restore verified the persisted fingerprint without replacing rows. All five existing labelled hybrid queries found the expected record in the top five through the application's own corpus service. The real pinned-model semantic test now passes. No corpus re-embedding or original-archive modification occurred.

[Verified through actual execution] Corpus package rejection/atomicity, resumable API upload and restore jobs are covered by 17 focused tests; the combined corpus/knowledge/auth regression set passed 61 tests. Frontend TypeScript passed. Skill retrieval/search events now include direct task IDs; password-only authorized scope configuration no longer mandates optional MFA. A real provider, complete web-reference access, remaining features and full release/Compose acceptance are still pending. See docs/DEPLOYMENT_READINESS.md for the live checklist; prior missing-corpus/model statements below describe earlier milestones.


Inventory date: 2026-11-09. No installed historical skill database supplied.

| Source/version | Actual contents | Review/integration status |
|---|---|---|
| Native ATLAS `scope-boundary-review` 1.0.0 | One authored source/policy skill, `search_text`; draft manifest. Runtime supports immutable imports, review, exact-hash fixtures, validation/enable/rollback | Preserved; existence is not enabled runtime state. Its dedicated deterministic fixture exists |
| BugBountySkills `0accf5fdc71ec7f03273aebb99268a8609f8dfd4` | 689 files inventoried, MIT. SKILL_FILES: recon, vulnerabilities, source review, reporting, mindset, automation, scripting, payloads, platform intelligence, exploit development; separate reference/knowledge/checklist materials | Complete checkout and machine inventory available. Selective source-review/reporting content manually inspected; broad tools (Semgrep, CodeQL, Nuclei, ffuf etc.) are dependencies, not ATLAS adapters. No installer executed. Full procedure review pending |
| Claude-Red `a8de813edc9f66f60d44cfe42d47750e89d9930b` | 97 files inventoried, MIT. Web/API/auth/recon/cloud/fuzzing, reporting, source/CI, mobile/container/network, infrastructure/AD and other red-team categories | Complete checkout/manifest inspected; selected reporting and GraphQL methods reviewed. GraphQL includes state changes/amplification and is unsuitable for automatic activation. Shell/TLS-bypass/evasion/post-exploitation material cannot become execution authority |
| AntiFox `070f798bf590667bc2a0a13c687dd87d8a4413bf` | Embedded domain skill library and dynamic agent skill/tool assembly; AGPL-3.0 | Architecture reference only; no code or skills copied |

External checkout inventories record relative path, byte count, SHA256 and headings at `/workspace/atlas-reference/{BugBountySkills,Claude-Red}-inventory.json`. These are an inventory, not a claim every instruction was individually approved. Dependencies, invocation limits, original source/commit/license and adaptation hashes must accompany each curated package. Original licenses must ship with copied content.

Use selective read-only reference integration first. Do not replace native skills, globally install upstream tools, import master identity prompts, or authorize live testing from a skill. Executable procedures retain the original owner review and independently bound fixture gate. Recommend OWASP WSTG/ASVS as additional authoritative methodology; avoid installing another entire red-team framework.

## Installed curated references

`atlas/data/skill_references/catalog.json` is the immutable repeatable installation catalogue. `skills.install_references()` verifies raw SHA256, path confinement and license presence; installs idempotently per owner when a run starts; and refuses altered versions. Full texts are research data, **not enabled executable skills**, with no granted tools. Retrieval checks content integrity. Runtime discovery returns metadata and source attribution, and full content requires a separate request.

| ATLAS ID / version | Origin at pinned commit above | Dependencies / adaptation / status |
|---|---|---|
| `source-review-methodology` 1.0.0 | BugBountySkills `SKILL_FILES/SOURCE_CODE_REVIEW/scr_methodology_general.md` | Full original text preserved; MIT notice packaged. Tool examples are references only; Semgrep/CodeQL/etc. are not installed or authorized. Metadata adapted to read-only research registry; source-reviewed by coding agent, not represented as operator execution approval |
| `evidence-reporting-methodology` 1.0.0 | Claude-Red `Skills/utility/offensive-reporting/SKILL.md` | Full original reporting methodology preserved; MIT notice packaged. No report shell/dependency execution; metadata adapted to reference-only retrieval. Same explicit review boundary |

Both source inventories are also saved in `docs/research/skills-source-inventory.json`. No external installer, model prompt identity, evasion procedure or uncontrolled tool dependency was executed. Tests cover repeat installation, exact-content integrity, owner isolation, dynamic-role discoverability and inability to mark references enabled. Broad upstream semantic review/integration remains future work, rather than silently approving hundreds of procedures.
