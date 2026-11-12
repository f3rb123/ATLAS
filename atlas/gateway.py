"""Provider-neutral typed adapters, identity-bound credentials and budget reservations."""

import json, time, threading, re
from typing import Literal, Protocol, AsyncIterator
from urllib.parse import urlsplit, urlunsplit
from pydantic import Field, field_validator, model_validator
from .policy import Strict, Scope, Rule, normalize, addresses, request, Denied
from .config import settings
from .db import Document, document, canonical, append, uid, digest, now
from .vault import seal, open_secret

ADAPTERS = [
    "openai_chat_completions",
    "openai_responses",
    "anthropic_messages",
    "gemini",
    "ollama_openai_compatible",
    "custom_openai_compatible",
    "deepseek",
]
BLOCK_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-for",
    "cookie",
    "set-cookie",
    "te",
    "trailer",
}


class ProviderInput(Strict):
    display_name: str = Field(min_length=1, max_length=100)
    adapter_type: str = Field(
        default="custom_openai_compatible", pattern=r"^[a-z][a-z0-9_]{0,79}$"
    )

    @field_validator("adapter_type")
    @classmethod
    def registered_protocol(cls, value):
        if value not in ADAPTERS:
            raise ValueError(
                "Protocol is not registered; install a reviewed adapter before configuring it"
            )
        return value

    base_url: str
    api_path: str | None = None
    auth_mode: Literal[
        "bearer", "x-api-key", "anthropic", "gemini", "custom", "none"
    ] = "bearer"
    auth_header_name: str | None = None
    api_key: str = Field(default="", max_length=8192, repr=False)
    headers: dict[str, str] = {}
    secret_headers: dict[str, str] = Field(default={}, repr=False)
    organization_id: str | None = None
    enabled: bool = True


class ModelInput(Strict):
    model_id: str = Field(min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_.:/-]+$")
    display_name: str = ""
    context_window: int = Field(default=32000, ge=512, le=2000000)
    max_output_tokens: int = Field(default=2048, ge=1, le=100000)
    capabilities: dict[str, bool] = {}
    input_price: float = Field(default=10, ge=0, le=1000)
    output_price: float = Field(default=30, ge=0, le=1000)
    pricing_status: Literal["unverified", "verified"] = "unverified"
    pricing_source: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_pricing_evidence(self):
        if (
            self.pricing_status == "verified"
            and not (self.pricing_source or "").strip()
        ):
            raise ValueError("Verified pricing requires an attributable pricing source")
        return self


class ModelRequest(Strict):
    model: str
    messages: list[dict]
    max_tokens: int = Field(default=2048, ge=1, le=100000)
    temperature: float = Field(default=0.2, ge=0, le=2)
    structured: bool = True
    tools: list[dict] = []


class ModelResponse(Strict):
    content: str
    structured_content: dict | None = None
    tool_calls: list[dict] = []
    finish_reason: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int | None = None
    usage_estimated: bool = False
    model_id: str = ""
    request_id: str | None = None
    latency_ms: float = 0
    warnings: list[str] = []


class ModelProvider(Protocol):
    def generate(self, request: ModelRequest) -> ModelResponse: ...
    def stream(self, request: ModelRequest): ...
    def list_models(self) -> list: ...
    def health_check(self) -> dict: ...


class ProviderError(ValueError):
    pass


class ProviderHTTPError(ProviderError):
    """Retain HTTP metadata, never a raw vendor error body or credential."""

    def __init__(self, status, headers=None, body=None):
        from email.utils import parsedate_to_datetime
        super().__init__({401: "authentication_failed", 403: "access_denied", 429: "rate_limited"}.get(status, "provider_http_error"))
        self.http_status = int(status)
        self.retry_after = None
        self.error_parameter = None
        value = next((v for k, v in (headers or {}).items() if k.lower() == "retry-after"), None)
        if value is not None:
            try:
                delay = int(value)
            except (ValueError, TypeError):
                try:
                    delay = parsedate_to_datetime(value).timestamp() - time.time()
                except (ValueError, TypeError, OverflowError):
                    delay = None
            if delay is not None:
                self.retry_after = min(300, max(0, delay))
        try:
            error = json.loads(body or b"{}").get("error", {})
            param = error.get("param") if isinstance(error, dict) else None
            if param in {"model", "response_format", "max_tokens", "max_completion_tokens", "temperature"}:
                self.error_parameter = param
        except (ValueError, TypeError, AttributeError):
            pass


class StructuredOutputError(ProviderError):
    def __init__(self, response):
        super().__init__(
            "Provider returned invalid structured output; reported usage was accounted"
        )
        self.response = response


class RunInterrupted(ProviderError):
    """Dispatch stopped or a known, accounted response arrived during pause/cancel."""


class CapacityWait(ProviderError):
    """Safe to retry: no model request or billable dispatch has occurred."""


def validate_headers(h):
    import re

    for k, v in h.items():
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", k)
            or k.lower() in BLOCK_HEADERS
            or k.lower().startswith(("proxy-", "x-forwarded-"))
            or "\r" in v
            or "\n" in v
        ):
            raise Denied("Unsafe provider header")


def provider_scope(url):
    n, h, p, path, scheme = normalize(url)
    exact = f"{h}:{p}"
    local = exact in settings().provider_local_allowlist
    if scheme != "https" and not local:
        raise Denied("HTTPS required; local inference requires operator allowlist")
    if (
        settings().provider_allowlist
        and exact not in settings().provider_allowlist
        and not local
    ):
        raise Denied("Provider not in operator egress allowlist")
    labs = []
    if local:
        import socket

        labs = [
            ip + ("/128" if ":" in ip else "/32")
            for ip in {
                r[4][0] for r in socket.getaddrinfo(h, p, type=socket.SOCK_STREAM)
            }
        ]
    addresses(h, p, labs)
    return Scope(
        allow=[Rule(host=h, ports=[p], schemes=[scheme], methods=["GET", "POST"])],
        lab_networks=labs,
    )


def validate_provider_configuration(url):
    """Validate an untested connection without requiring working DNS/egress.

    Actual dispatch still resolves and pins addresses through provider_scope.
    Saving an encrypted connection never marks it healthy or enables a model.
    """
    import ipaddress

    _, hostname, port, _, scheme = normalize(url)
    exact = f"{hostname}:{port}"
    local = exact in settings().provider_local_allowlist
    if scheme != "https" and not local:
        raise Denied("HTTPS required; local inference requires operator allowlist")
    if (
        settings().provider_allowlist
        and exact not in settings().provider_allowlist
        and not local
    ):
        raise Denied("Provider not in operator egress allowlist")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global and not local:
        raise Denied("Private provider address requires explicit operator allowlist")


def safe_metadata(d):
    v = d.value()
    return {
        "id": d.id,
        "version": d.version,
        **{
            k: x
            for k, x in v.items()
            if k not in ("secret", "secret_headers", "headers")
        },
        "headers": {
            k: val
            for k, val in v.get("headers", {}).items()
            if k.lower() not in ("authorization", "x-api-key")
        },
        "secret_configured": bool(v.get("secret")),
    }


def secret_identity(owner, id, configuration, kind="provider"):
    if configuration.get("aad_scheme") != "endpoint-bound-v2":
        return f"{kind}:{owner}:{id}:1"
    approved = {
        key: configuration.get(key)
        for key in (
            "base_url",
            "adapter_type",
            "api_path",
            "auth_mode",
            "auth_header_name",
            "headers",
            "organization_id",
        )
    }
    return f"{kind}:{owner}:{id}:2:" + digest(canonical(approved))


def create_provider(db, owner, input, id=None):
    v = input.model_dump()
    if urlsplit(v["base_url"]).query or urlsplit(v["base_url"]).fragment:
        raise Denied("Provider base URL cannot include query credentials or fragments")
    if v["auth_mode"] == "custom" and not v["auth_header_name"]:
        raise Denied("Custom authentication requires a header name")
    validate_headers(v["headers"])
    validate_headers(v["secret_headers"])
    validate_provider_configuration(v["base_url"])
    if v["auth_header_name"]:
        validate_headers({v["auth_header_name"]: "x"})
    if any(
        __import__("re").search(
            r"(?i)(?:^|-)(?:authorization|auth|token|key|secret|password|credential|cookie)(?:$|-)",
            k,
        )
        for k in v["headers"]
    ):
        raise Denied("Credentials must use encrypted fields")
    if v["api_path"] and (
        not v["api_path"].startswith("/")
        or "://" in v["api_path"]
        or ".." in v["api_path"]
        or "?" in v["api_path"]
    ):
        raise Denied("Invalid path override")
    id = id or uid()
    key = v.pop("api_key")
    secret_headers = v.pop("secret_headers")
    nonsecret_metadata = canonical(v)
    if any(
        value and len(value) >= 4 and value in nonsecret_metadata
        for value in [key, *secret_headers.values()]
    ):
        raise Denied(
            "A credential also appears in non-secret metadata; use encrypted fields only"
        )
    v["fingerprint"] = digest(key)[:12] if key else None
    v["aad_scheme"] = "endpoint-bound-v2"
    v["secret"] = seal(key, secret_identity(owner, id, v)) if key else None
    v["secret_headers"] = seal(
        canonical(secret_headers), secret_identity(owner, id, v, "headers")
    )
    v["health_status"] = "untested"
    v["created_at"] = now()
    d = document(db, "provider", owner, v, id)
    append(
        db,
        owner,
        owner,
        "provider_created",
        {"id": id, "fingerprint": v["fingerprint"]},
    )
    return d


class Adapter:
    version = "1.0"

    def __init__(self, d):
        self.d = d
        self.v = d.value()

    def path(self, kind, model=""):
        base = self.v["base_url"].rstrip("/")
        u = urlsplit(base)
        if u.query or u.fragment:
            raise Denied("Provider base URLs cannot include query or fragment")
        protocol = self.v["adapter_type"]
        override = self.v.get("api_path")
        if kind == "models":
            suffix = "/models"
        elif override:
            suffix = override
        elif protocol == "openai_responses":
            suffix = "/responses"
        elif protocol == "anthropic_messages":
            suffix = "/messages"
        elif protocol == "gemini":
            suffix = f"/models/{model}:generateContent"
        else:
            suffix = "/chat/completions"
        return base + suffix

    def headers(self):
        v = self.v
        h = {
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
            **v.get("headers", {}),
        }
        key = (
            open_secret(v["secret"], secret_identity(self.d.owner, self.d.id, v))
            if v.get("secret")
            else ""
        )
        h.update(
            json.loads(
                open_secret(
                    v["secret_headers"],
                    secret_identity(self.d.owner, self.d.id, v, "headers"),
                )
            )
        )
        if v["auth_mode"] == "bearer":
            h["Authorization"] = "Bearer " + key
        elif v["auth_mode"] in ("x-api-key", "anthropic"):
            h["x-api-key"] = key
        elif v["auth_mode"] == "gemini":
            h["x-goog-api-key"] = key
        elif v["auth_mode"] == "custom":
            h[v["auth_header_name"]] = key
        if v["adapter_type"] == "anthropic_messages":
            h["anthropic-version"] = "2023-06-01"
        if v.get("organization_id"):
            h["OpenAI-Organization"] = v["organization_id"]
        validate_headers(h)
        return h

    def serialize(self, r, stream=False):
        protocol = self.v["adapter_type"]
        messages = r.messages
        if protocol == "anthropic_messages":
            result = {
                "model": r.model,
                "max_tokens": r.max_tokens,
                "messages": [m for m in messages if m["role"] != "system"],
                "system": "\n".join(
                    m["content"] for m in messages if m["role"] == "system"
                ),
            }
        elif protocol == "gemini":
            result = {
                "contents": [
                    {
                        "role": "model" if m["role"] == "assistant" else "user",
                        "parts": [{"text": m["content"]}],
                    }
                    for m in messages
                    if m["role"] != "system"
                ],
                "generationConfig": {
                    "maxOutputTokens": r.max_tokens,
                    "temperature": r.temperature,
                },
            }
            system = "\n".join(m["content"] for m in messages if m["role"] == "system")
            if system:
                result["systemInstruction"] = {"parts": [{"text": system}]}
            if r.structured:
                result["generationConfig"]["responseMimeType"] = "application/json"
        elif protocol == "openai_responses":
            result = {
                "model": r.model,
                "input": messages,
                "max_output_tokens": r.max_tokens,
            }
            if r.structured:
                result["text"] = {"format": {"type": "json_object"}}
        else:
            result = {
                "model": r.model,
                "messages": messages,
                "max_tokens": r.max_tokens,
                "temperature": r.temperature,
            }
            if r.structured:
                result["response_format"] = {"type": "json_object"}
            if r.tools:
                result["tools"] = r.tools
        if r.tools and protocol in ("anthropic_messages", "gemini", "openai_responses"):
            functions = [t["function"] for t in r.tools]
            if protocol == "anthropic_messages":
                result["tools"] = [
                    {
                        "name": f["name"],
                        "description": f.get("description", ""),
                        "input_schema": f["parameters"],
                    }
                    for f in functions
                ]
            elif protocol == "gemini":
                result["tools"] = [{"functionDeclarations": functions}]
            else:
                result["tools"] = [{"type": "function", **f} for f in functions]
        if stream:
            if protocol != "gemini":
                result["stream"] = True
        return result

    def normalize(self, p, r):
        protocol = self.v["adapter_type"]
        usage = p.get("usage") or {}
        calls = []
        finish = None
        if protocol == "anthropic_messages":
            content = "".join(
                c.get("text", "") for c in p["content"] if c["type"] == "text"
            )
            calls = [c for c in p["content"] if c["type"] == "tool_use"]
            inp = usage.get("input_tokens")
            out = usage.get("output_tokens")
            finish = p.get("stop_reason")
        elif protocol == "gemini":
            cand = p["candidates"][0]
            parts = cand["content"]["parts"]
            content = "".join(c.get("text", "") for c in parts)
            calls = [c["functionCall"] for c in parts if "functionCall" in c]
            u = p.get("usageMetadata", {})
            inp = u.get("promptTokenCount")
            out = u.get("candidatesTokenCount")
            finish = cand.get("finishReason")
        elif protocol == "openai_responses":
            content = "".join(
                c.get("text", "")
                for o in p.get("output", [])
                for c in o.get("content", [])
                if c.get("type") == "output_text"
            )
            calls = [o for o in p.get("output", []) if o.get("type") == "function_call"]
            inp = usage.get("input_tokens")
            out = usage.get("output_tokens")
            finish = p.get("status")
        else:
            c = p["choices"][0]
            m = c["message"]
            content = m.get("content") or ""
            calls = m.get("tool_calls", [])
            inp = usage.get("prompt_tokens")
            out = usage.get("completion_tokens")
            finish = c.get("finish_reason")
        for count in (inp, out):
            if count is not None and (type(count) is not int or count < 0):
                raise ProviderError("Malformed usage counters")
        cached = usage.get(
            "prompt_cache_hit_tokens",
            usage.get("prompt_tokens_details", {}).get(
                "cached_tokens",
                usage.get("input_tokens_details", {}).get("cached_tokens", 0),
            ),
        )
        created = 0
        reasoning = usage.get("completion_tokens_details", {}).get(
            "reasoning_tokens",
            usage.get("output_tokens_details", {}).get(
                "reasoning_tokens", usage.get("reasoning_tokens", 0)
            ),
        )
        reported_total = usage.get("total_tokens")
        if protocol == "anthropic_messages":
            cached = usage.get("cache_read_input_tokens", 0)
            created = usage.get("cache_creation_input_tokens", 0)
            if inp is not None:
                inp += cached + created
        elif protocol == "gemini":
            cached = u.get("cachedContentTokenCount", 0)
            reasoning = u.get("thoughtsTokenCount", 0)
            if out is not None:
                out += reasoning
            reported_total = u.get("totalTokenCount")
        for count in (cached, created, reasoning, reported_total):
            if count is not None and (type(count) is not int or count < 0):
                raise ProviderError("Malformed detailed usage counters")
        est = inp is None or out is None
        inp = (
            inp
            if isinstance(inp, int) and inp >= 0
            else sum(len(m.get("content", "")) for m in r.messages)
        )
        out = out if isinstance(out, int) and out >= 0 else len(content)
        if inp > 10000000 or out > 10000000:
            raise ProviderError("Malformed usage counters")
        if cached + created > inp:
            raise ProviderError("Cached usage exceeds input usage")
        structured = None
        warnings = []
        if r.structured:
            candidate = content
            fenced = re.fullmatch(
                r"\s*```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*", content
            )
            if fenced:
                candidate = fenced.group(1)
                warnings.append("exact_json_fence_normalized")
            try:
                structured = json.loads(candidate)
            except (TypeError, json.JSONDecodeError):
                warnings.append("invalid_structured_json")
            if not isinstance(structured, dict):
                structured = None
                if not warnings:
                    warnings.append("structured_object_required")
        return ModelResponse(
            content=self.scrub(content),
            structured_content=self.scrub_data(structured),
            tool_calls=self.scrub_data(calls),
            finish_reason=finish,
            input_tokens=inp,
            output_tokens=out,
            cached_input_tokens=cached,
            cache_creation_input_tokens=created,
            reasoning_tokens=reasoning,
            total_tokens=max(reported_total or 0, inp + out),
            usage_estimated=est,
            model_id=r.model,
            request_id=p.get("id"),
            warnings=warnings,
        )

    def capabilities(self, model_id):
        return {
            "streaming": True,
            "structured_output": "requires_probe",
            "tool_calling": "requires_probe",
            "vision": "requires_configuration",
            "usage": "provider_or_estimated",
            "adapter_version": self.version,
        }

    def scrub(self, text):
        from .vault import redact

        values = []
        if self.v.get("secret"):
            values.append(
                open_secret(
                    self.v["secret"], secret_identity(self.d.owner, self.d.id, self.v)
                )
            )
        if self.v.get("secret_headers"):
            values.extend(
                json.loads(
                    open_secret(
                        self.v["secret_headers"],
                        secret_identity(self.d.owner, self.d.id, self.v, "headers"),
                    )
                ).values()
            )
        for value in values:
            if value:
                text = text.replace(value, "[REDACTED]")
        return redact(text)

    def scrub_data(self, value):
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, list):
            return [self.scrub_data(v) for v in value]
        if isinstance(value, dict):
            return {k: self.scrub_data(v) for k, v in value.items()}
        return value

    def generate(self, r):
        url = self.path("generate", r.model)
        scope = provider_scope(url)
        t = time.monotonic()
        try:
            status, received_headers, body = request(
                url,
                "POST",
                self.headers(),
                canonical(self.serialize(r)).encode(),
                scope,
                2 * 1024 * 1024,
                settings().provider_timeout_seconds,
            )
            if status != 200:
                raise ProviderHTTPError(status, received_headers, body)
            result = self.normalize(json.loads(body.decode()), r)
            result.latency_ms = (time.monotonic() - t) * 1000
            return result
        except __import__("ssl").SSLError:
            raise ProviderError("TLS verification or handshake failure") from None
        except TimeoutError:
            raise ProviderError("Provider request timed out") from None
        except (ConnectionError, OSError):
            raise ProviderError("Provider transport failure") from None
        except (KeyError, IndexError, json.JSONDecodeError):
            raise ProviderError("Provider response parse failure") from None

    def stream(self, r):
        # Real protocol event iterator; no simulated streaming of a buffered response.
        from .policy import authorize, PinnedConnection

        url = self.path("generate", r.model)
        if self.v["adapter_type"] == "gemini":
            url = url.replace(":generateContent", ":streamGenerateContent") + "?alt=sse"
        n, h, p, ips = authorize(provider_scope(url), url, "POST")
        u = urlsplit(n)
        c = PinnedConnection(h, ips[0], p, u.scheme == "https", 30)
        buffered = ""
        calls = {}
        secrets = []
        if self.v.get("secret"):
            secrets.append(
                open_secret(
                    self.v["secret"], secret_identity(self.d.owner, self.d.id, self.v)
                )
            )
        if self.v.get("secret_headers"):
            secrets.extend(
                json.loads(
                    open_secret(
                        self.v["secret_headers"],
                        secret_identity(self.d.owner, self.d.id, self.v, "headers"),
                    )
                ).values()
            )
        holdback = max([1024] + [len(value) for value in secrets])
        try:
            c.request(
                "POST",
                u.path + ("?" + u.query if u.query else ""),
                body=canonical(self.serialize(r, True)).encode(),
                headers=self.headers(),
            )
            response = c.getresponse()
            if response.status != 200:
                raise ProviderError("Streaming provider request failed")
            total = 0
            while True:
                line = response.readline(65537)
                total += len(line)
                if len(line) > 65536 or total > 2 * 1024 * 1024:
                    raise ProviderError("Stream quota exceeded")
                if not line:
                    break
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    break
                event = json.loads(self.scrub(data.decode()))
                protocol = self.v["adapter_type"]
                if protocol == "anthropic_messages":
                    text = event.get("delta", {}).get("text", "")
                elif protocol == "gemini":
                    text = "".join(
                        part.get("text", "")
                        for cand in event.get("candidates", [])
                        for part in cand.get("content", {}).get("parts", [])
                    )
                elif protocol == "openai_responses":
                    text = (
                        event.get("delta", "")
                        if event.get("type") == "response.output_text.delta"
                        else ""
                    )
                else:
                    text = (
                        next(iter(event.get("choices", [])), {})
                        .get("delta", {})
                        .get("content", "")
                    )
                buffered = self.scrub(buffered + text)
                if len(buffered) > holdback:
                    yield {"type": "content_delta", "text": buffered[:-holdback]}
                    buffered = buffered[-holdback:]
                if event.get("usage") or event.get("usageMetadata"):
                    yield {
                        "type": "usage",
                        "usage": event.get("usage", event.get("usageMetadata")),
                    }
                if protocol not in ("gemini", "anthropic_messages", "openai_responses"):
                    for choice in event.get("choices", []):
                        for call in choice.get("delta", {}).get("tool_calls", []):
                            key = call.get("index", 0)
                            target = calls.setdefault(
                                key, {"id": "", "name": "", "arguments": ""}
                            )
                            target["id"] += call.get("id", "")
                            target["name"] += call.get("function", {}).get("name", "")
                            target["arguments"] += call.get("function", {}).get(
                                "arguments", ""
                            )
                elif protocol == "anthropic_messages":
                    key = event.get("index", 0)
                    block = event.get("content_block", {})
                    if block.get("type") == "tool_use":
                        calls[key] = {
                            "id": block["id"],
                            "name": block["name"],
                            "arguments": "",
                        }
                    if event.get("delta", {}).get("type") == "input_json_delta":
                        calls.setdefault(key, {"id": "", "name": "", "arguments": ""})[
                            "arguments"
                        ] += event["delta"]["partial_json"]
                elif protocol == "openai_responses":
                    key = event.get("output_index", 0)
                    item = event.get("item", {})
                    if (
                        item.get("type") == "function_call"
                        and event.get("type") == "response.output_item.added"
                    ):
                        calls[key] = {
                            "id": item.get("call_id", ""),
                            "name": item["name"],
                            "arguments": item.get("arguments", ""),
                        }
                    if event.get("type") == "response.function_call_arguments.delta":
                        calls.setdefault(key, {"id": "", "name": "", "arguments": ""})[
                            "arguments"
                        ] += event["delta"]
                elif protocol == "gemini":
                    for cand in event.get("candidates", []):
                        for part in cand.get("content", {}).get("parts", []):
                            if "functionCall" in part:
                                fn = part["functionCall"]
                                calls[len(calls)] = {
                                    "id": "",
                                    "name": fn["name"],
                                    "arguments": canonical(fn.get("args", {})),
                                }
            if buffered:
                yield {"type": "content_delta", "text": self.scrub(buffered)}
            for call in calls.values():
                safe = json.loads(self.scrub(canonical(call)))
                try:
                    safe["arguments"] = json.loads(safe["arguments"] or "{}")
                except json.JSONDecodeError:
                    raise ProviderError("Malformed streamed tool arguments") from None
                yield {
                    "type": "tool_call_complete",
                    "tool_call": safe,
                    "trust": "untrusted_model_output",
                }
        except (KeyError, IndexError, json.JSONDecodeError):
            raise ProviderError("Streaming provider response parse failure") from None
        except (TimeoutError, ConnectionError, OSError):
            raise ProviderError("Streaming provider transport failure") from None
        finally:
            c.close()

    def list_models(self):
        url = self.path("models")
        status, _, body = request(
            url,
            "GET",
            self.headers(),
            scope=provider_scope(url),
            max_bytes=256000,
            timeout=10,
        )
        if status != 200:
            raise ProviderError(
                "Model discovery unavailable; manual entry is supported"
            )
        p = self.scrub_data(json.loads(body.decode()))
        return p.get("data", p.get("models", []))

    def health_check(self):
        return {"status": "reachable", "models": self.list_models()}


def reserve(db, owner, run_id, ceiling, role=None, provider_id=None, token_ceiling=0):
    # Serialize initial creation as well as existing-row reservations.
    from .db import transaction_lock

    transaction_lock(db, "budget-global")
    d = db.query(Document).filter_by(id="budget-global").with_for_update().first()
    if not d:
        d = document(
            db,
            "budget",
            "system",
            {"cap": settings().monthly_budget, "spent": {}, "reserved": {}},
            "budget-global",
        )
    v = d.value()
    run = db.get(Document, run_id)
    from .skunk_usage import tracking_only
    track_only = tracking_only(run)
    token_ledger = db.get(Document, "token-budget-global")
    token_reservations = (
        token_ledger.value().get("reserved", {}) if token_ledger else {}
    )
    if (
        provider_id
        and sum(
            r.get("provider_id") == provider_id
            and token_reservations.get(id, {}).get("state") != "unknown_billing"
            for id, r in v["reserved"].items()
        )
        >= settings().max_provider_concurrency
    ):
        raise CapacityWait("Provider concurrency reserved by in-flight requests")
    month = now()[:7]
    spent = v["spent"].get(month, 0)
    pending = sum(x["amount"] for x in v["reserved"].values())
    if not track_only and spent + pending + ceiling > v["cap"]:
        if pending and spent + ceiling <= v["cap"]:
            raise CapacityWait("Monthly budget capacity reserved by in-flight requests")
        raise ProviderError("Monthly budget exhausted")
    if run and run.kind == "run":
        rv = run.value()
        pending_run = sum(
            x["amount"] for x in v["reserved"].values() if x["run_id"] == run_id
        )
        if not track_only and rv.get("budget_used", 0) + pending_run + ceiling > rv["budget_limit"]:
            if pending_run and rv.get("budget_used", 0) + ceiling <= rv["budget_limit"]:
                raise CapacityWait("Run budget capacity reserved by in-flight requests")
            raise ProviderError("Run budget exhausted")
        if role and not track_only:
            pending_role = sum(
                x["amount"]
                for x in v["reserved"].values()
                if x["run_id"] == run_id and x.get("role") == role
            )
            if rv.get("role_spent", {}).get(role, 0) + pending_role + ceiling > rv.get(
                "role_budgets", {}
            ).get(role, rv["budget_limit"]):
                if pending_role and rv.get("role_spent", {}).get(
                    role, 0
                ) + ceiling <= rv.get("role_budgets", {}).get(role, rv["budget_limit"]):
                    raise CapacityWait(
                        "Role budget capacity reserved by in-flight requests"
                    )
                raise ProviderError("Role budget exhausted")
        campaign = db.get(Document, rv.get("campaign_id", ""))
        if campaign and not track_only:
            campaign_runs = {
                r.id
                for r in db.query(Document).filter_by(kind="run", owner=owner)
                if r.value().get("campaign_id") == campaign.id
            }
            used = sum(
                u.value()["cost"]
                for u in db.query(Document).filter_by(kind="usage", owner=owner)
                if u.value().get("campaign_id") == campaign.id
            )
            pending_campaign = sum(
                x["amount"]
                for x in v["reserved"].values()
                if x["run_id"] in campaign_runs
            )
            if used + pending_campaign + ceiling > campaign.value().get(
                "budget_limit", 10
            ):
                if pending_campaign and used + ceiling <= campaign.value().get(
                    "budget_limit", 10
                ):
                    raise CapacityWait(
                        "Campaign budget capacity reserved by in-flight requests"
                    )
                raise ProviderError("Campaign budget exhausted")
    id = uid()
    if provider_id:
        from .model_routing import require_dispatchable

        require_dispatchable(db, provider_id)
    if token_ceiling:
        from .token_budget import reserve as reserve_tokens

        reserve_tokens(db, id, token_ceiling, owner, run_id, role, provider_id)
    v["reserved"][id] = {
        "amount": ceiling,
        "owner": owner,
        "month": month,
        "run_id": run_id,
        "role": role,
        "provider_id": provider_id,
        "task_id": getattr(run, "_swarm_claim", (None, None))[0] if run else None,
        "token_ceiling": token_ceiling,
        "enforcement": "tracking_only" if track_only else "bounded",
    }
    d.data = canonical(v)
    db.commit()
    return id


def settle(db, reservation, cost, token_usage=None, not_dispatched=False):
    from .db import transaction_lock

    transaction_lock(db, "budget-global")
    d = db.query(Document).filter_by(id="budget-global").with_for_update().one()
    v = d.value()
    r = v["reserved"].pop(reservation)
    v["spent"][r["month"]] = v["spent"].get(r["month"], 0) + cost
    d.data = canonical(v)
    from .token_budget import settle as settle_tokens

    settle_tokens(db, reservation, token_usage, not_dispatched)


def token_usage(response):
    return {
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "cached_input_tokens": response.cached_input_tokens,
        "cache_creation_input_tokens": response.cache_creation_input_tokens,
        "reasoning_tokens": response.reasoning_tokens,
        "total_tokens": response.total_tokens
        if response.total_tokens is not None
        else response.input_tokens + response.output_tokens,
        "estimated": response.usage_estimated,
    }


def generate_budgeted(db, provider, model, req, run, role="reasoning"):
    m = model.value()
    rv = run.value()
    from .skunk_usage import tracking_only
    track_only = tracking_only(run)
    if req.max_tokens > m["max_output_tokens"]:
        raise ProviderError("Model output limit exceeded")
    from .skunk_models import runtime_contract
    if req.structured and not m.get("verified_structured") and not runtime_contract(provider, model, run):
        raise ProviderError("Structured output capability unverified")
    if req.tools and not m.get("verified_tools"):
        raise ProviderError(
            "Native tool calling capability unverified; use the schema-validated broker workflow"
        )
    input_upper = sum(len(x["content"].encode("utf-8")) for x in req.messages)
    if input_upper + req.max_tokens > m["context_window"]:
        raise ProviderError("Conservative context/token limit exceeded")
    estimate = (
        input_upper * m["input_price"] + req.max_tokens * m["output_price"]
    ) / 1000000
    if not track_only and rv.get("budget_used", 0) + estimate > rv["budget_limit"]:
        raise ProviderError("Run budget exhausted")
    if rv.get("model_calls", 0) >= rv.get("max_model_calls", 20):
        raise ProviderError("Model call limit exhausted")
    role_spent = rv.get("role_spent", {}).get(role, 0)
    if not track_only and role_spent + estimate > rv.get("role_budgets", {}).get(role, rv["budget_limit"]):
        raise ProviderError("Role budget exhausted")
    from .token_budget import ceiling as token_ceiling, mark_unknown

    reservation = reserve(
        db,
        run.owner,
        run.id,
        estimate,
        role,
        provider_id=provider.id,
        token_ceiling=token_ceiling(req),
    )
    campaign = db.get(Document, rv["campaign_id"]) if rv.get("campaign_id") else None
    if campaign and not track_only:
        campaign_id = rv["campaign_id"]
        total = 0
        for usage in db.query(Document).filter_by(kind="usage", owner=run.owner):
            if usage.value().get("campaign_id") == campaign_id:
                total += usage.value()["cost"]
        if total + estimate > campaign.value().get("budget_limit", 10):
            settle(db, reservation, 0, not_dispatched=True)
            db.commit()
            raise ProviderError("Campaign budget exhausted")
    from .db import transaction_lock

    transaction_lock(db, "budget-global")
    db.refresh(run, with_for_update=True)
    rv = run.value()
    kill = db.get(Document, "kill-switch")
    if rv["status"] not in ("queued", "running") or (kill and kill.value()["enabled"]):
        settle(db, reservation, 0, not_dispatched=True)
        db.commit()
        raise RunInterrupted("Run was stopped before dispatch")
    if rv.get("model_calls", 0) >= rv.get("max_model_calls", 20):
        settle(db, reservation, 0, not_dispatched=True)
        db.commit()
        raise ProviderError("Model call limit exhausted")
    rv["model_calls"] = rv.get("model_calls", 0) + 1
    run.data = canonical(rv)
    db.commit()
    # Unknown transport outcomes retain their full reservation; never assume no bill.
    try:
        response = construct_adapter(provider).generate(req)
    except Exception:
        mark_unknown(db, reservation)
        from .model_routing import outcome

        outcome(db, provider, False)
        db.commit()
        raise
    cost = (
        response.input_tokens * m["input_price"]
        + response.output_tokens * m["output_price"]
    ) / 1000000
    cost = max(cost, estimate) if response.usage_estimated else cost
    settle(db, reservation, cost, token_usage(response))
    from .model_routing import outcome

    outcome(db, provider, True, response.latency_ms)
    document(
        db,
        "usage",
        run.owner,
        {
            "run_id": run.id,
            "task_id": getattr(run, "_swarm_claim", (None, None))[0],
            "provider_id": provider.id,
            "model": req.model,
            "campaign_id": rv.get("campaign_id"),
            "role": role,
            "pricing_version": model.version,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "cached_input_tokens": response.cached_input_tokens,
            "cache_creation_input_tokens": response.cache_creation_input_tokens,
            "reasoning_tokens": response.reasoning_tokens,
            "total_tokens": response.total_tokens
            if response.total_tokens is not None
            else response.input_tokens + response.output_tokens,
            "cost": cost,
            "cost_confirmed": m.get("pricing_status") == "verified"
            and not response.usage_estimated,
            "pricing_source": m.get("pricing_source"),
            "actual_cost_usd": cost
            if m.get("pricing_status") == "verified" and not response.usage_estimated
            else None,
            "estimated": response.usage_estimated
            or m.get("pricing_status") != "verified",
            "token_usage_estimated": response.usage_estimated,
            "reservation_id": reservation,
            "latency_ms": response.latency_ms,
            "finish_reason": response.finish_reason,
            "warnings": response.warnings,
        },
    )
    db.refresh(run, with_for_update=True)
    rv = run.value()
    rv["budget_used"] = rv.get("budget_used", 0) + cost
    rv.setdefault("role_spent", {})[role] = rv.get("role_spent", {}).get(role, 0) + cost
    run.data = canonical(rv)
    db.commit()
    if rv["status"] not in ("running", "queued"):
        raise RunInterrupted("Run was paused or cancelled during provider request")
    if req.structured and response.structured_content is None:
        raise StructuredOutputError(response)
    return response


# Immutable, credential-free configuration history for pinned runs.
def snapshot_provider(db, d):
    id = digest("provider-version:" + d.id + ":" + str(d.version))[:36]
    if not db.get(Document, id):
        document(
            db,
            "provider_version",
            d.owner,
            {
                "provider_id": d.id,
                "config_version": d.version,
                "configuration": safe_metadata(d),
            },
            id,
        )


def snapshot_model(db, d):
    id = digest("model-version:" + d.id + ":" + str(d.version))[:36]
    if not db.get(Document, id):
        document(
            db,
            "model_version",
            d.owner,
            {
                "provider_model_id": d.id,
                "config_version": d.version,
                "configuration": d.value(),
            },
            id,
        )


PLUGIN_FACTORIES = {}


def register_adapter(protocol_id, factory):
    import re

    if (
        not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", protocol_id)
        or protocol_id in ADAPTERS
    ):
        raise ValueError("Invalid or duplicate adapter identifier")
    if not callable(factory):
        raise TypeError("Adapter factory must be callable")
    PLUGIN_FACTORIES[protocol_id] = factory
    ADAPTERS.append(protocol_id)


def construct_adapter(provider):
    protocol = provider.value()["adapter_type"]
    if protocol in PLUGIN_FACTORIES:
        adapter = PLUGIN_FACTORIES[protocol](provider)
        if not all(
            callable(getattr(adapter, name, None))
            for name in (
                "generate",
                "stream",
                "list_models",
                "health_check",
                "capabilities",
            )
        ):
            raise ProviderError("Adapter does not implement the provider contract")
        return adapter
    if protocol not in ADAPTERS:
        raise ProviderError("Provider protocol is unavailable")
    return Adapter(provider)


def load_plugins():
    import importlib, re

    for name in settings().provider_plugins:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,100}", name):
            raise ValueError("Invalid trusted provider module name")
        module = importlib.import_module(name)
        module.register_atlas_providers(register_adapter)


load_plugins()
