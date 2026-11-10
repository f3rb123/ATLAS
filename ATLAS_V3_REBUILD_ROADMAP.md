# ATLAS rebuild roadmap

## 10 November 2026 — current deployment work

[Verified through actual execution, 10 November 2026] Deployment completion is now authorized and in progress. The real public candidate was restored into the previously empty development corpus through the new identity-preserving package service: 21,012 records, 34,229 384-dimensional MiniLM vectors, 39,985 aliases, 21,359 hash-verified raw files and 150 explicitly withheld artifacts. A consistent pre-import DB backup was retained. Repeat restore verified the persisted fingerprint without replacing rows. All five existing labelled hybrid queries found the expected record in the top five through the application's own corpus service. The real pinned-model semantic test now passes. No corpus re-embedding or original-archive modification occurred.

[Verified through actual execution] Corpus package rejection/atomicity, resumable API upload and restore jobs are covered by 17 focused tests; the combined corpus/knowledge/auth regression set passed 61 tests. Frontend TypeScript passed. Skill retrieval/search events now include direct task IDs; password-only authorized scope configuration no longer mandates optional MFA. A real provider, complete web-reference access, remaining features and full release/Compose acceptance are still pending. See docs/DEPLOYMENT_READINESS.md for the live checklist; prior missing-corpus/model statements below describe earlier milestones.


| Package | Status | Acceptance |
|---|---|---|
| Restore release, preserve refs, audit source/data | Complete for delivered files | Hashes/bundle/ZIP comparison; no original runtime DB supplied |
| Mandatory eight-reference study | Partial | Five GitHub repositories inspected; three websites blocked; exhaustive skill content review not claimed |
| Shared knowledge harness | Implemented and locally tested | Shared policy/tools/retrieval/feedback; real historical semantic acceptance remains blocked |
| Reviewed skill references | Two installed as research-only references | Pinned hashes/licenses and selective retrieval; full libraries/executable adapters remain unapproved |
| Durable event-driven swarm | Core implemented and locally tested | Independent concurrency, fenced claims, idempotent events, activation, recovery/cancellation/dead letters; needs production/scale evaluation |
| Provider and tool management | Partial baseline | Central settings exist; routing/timeout/concurrency improvements and reviewed adapters need tests |
| Optional-factor operator authentication | Implemented and tested | Password sessions, change/rotation/logout and optional/strict-factor policy; host-only recovery preserved |
| Deep research, independent validation, chains | Partial baseline | Local proof/control replay preserved; connect swarm candidates without model-only confirmation |
| Live swarm/operator UX | Partial, tested | Persisted task/discovery/retrieval/usage panel, instructions, agent count/model mode; conversational chat/recon console still pending |
| Corpus restoration and real semantic acceptance | Externally blocked | Original sanitized corpus/model assets or permitted model download; validate counts/hashes without replacing or rebuilding original intelligence |
| End-to-end lab and deployment | Pending | Label mock providers; real models require owner settings; VPS requires separate approval |

Follow current source/tests, not historical green checkmarks. Full rebuild is not complete. Work checkpoints and exact commands/results belong in the implementation ledger and handoff.
