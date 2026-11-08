# Provider adapter SDK

OpenAI-compatible endpoints use configuration only. Responses, Anthropic Messages, Gemini and DeepSeek/Ollama/vLLM-compatible protocols have explicit serializers/normalizers. A proprietary incompatible API requires a trusted code adapter, not response guessing or an arbitrary HTTP template.

Implement a factory accepting the server-side provider Document and returning an object with `generate(ModelRequest) -> ModelResponse`, real `stream(ModelRequest)` event iteration, `health_check()`, `list_models()` and `capabilities(model_id)`. Use atlas.policy's pinned transport/provider_scope, strict header validation, vault identity binding and exact-secret scrubbing; never return raw provider bodies/errors or credentials. Normalized usage must be nonnegative and bounded; missing usage is conservatively estimated. Gateway budgets and final application schemas remain authoritative.

A reviewed installed module exposes `register_atlas_providers(register)` and calls `register('vendor_protocol', factory)`. Enable that module through the operator-controlled ATLAS_PROVIDER_PLUGINS JSON list when building/deploying the reviewed source. IDs must be stable lowercase identifiers and cannot replace built-ins. The API adapter registry and Web UI then include the protocol.

Adapters are trusted backend code and require the same review/pinning as the application. There is no UI upload/install/exec mechanism. Imported skills, source files, model outputs and API callers cannot install plugins. Add recorded synthetic contract tests for serialization, authentication, streaming, usage, errors, timeouts, cancellation, redaction and SSRF before enabling an adapter. Never claim compatibility for an unimplemented protocol.
