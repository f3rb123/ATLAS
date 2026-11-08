import json, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import pytest
from atlas.gateway import *
from atlas.db import *
from atlas.config import settings


@pytest.fixture
def provider_server(db):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"test-model"}]}')

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert payload["model"] == "test-model"
            assert self.headers["Authorization"] == "Bearer fixture-not-real-secret"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b'{"id":"response-1","choices":[{"message":{"content":"{\\"ok\\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":5}}'
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings().provider_local_allowlist = [f"127.0.0.1:{server.server_port}"]
    yield f"http://127.0.0.1:{server.server_port}/custom/v1"
    server.shutdown()


def test_custom_endpoint_real_http_and_write_only(db, provider_server):
    d = create_provider(
        db,
        "owner",
        ProviderInput(
            display_name="Custom",
            base_url=provider_server,
            api_key="fixture-not-real-secret",
        ),
    )
    db.commit()
    assert "fixture-not-real-secret" not in d.data
    assert "secret" not in safe_metadata(d)
    a = Adapter(d)
    assert a.list_models()[0]["id"] == "test-model"
    r = a.generate(
        ModelRequest(model="test-model", messages=[{"role": "user", "content": "JSON"}])
    )
    assert r.structured_content == {"ok": True} and r.input_tokens == 20


@pytest.mark.parametrize(
    "protocol,payload",
    [
        (
            "anthropic_messages",
            {
                "content": [{"type": "text", "text": '{"ok":true}'}],
                "usage": {"input_tokens": 2, "output_tokens": 3},
            },
        ),
        (
            "openai_responses",
            {
                "output": [
                    {"content": [{"type": "output_text", "text": '{"ok":true}'}]}
                ],
                "usage": {"input_tokens": 2, "output_tokens": 3},
            },
        ),
        (
            "gemini",
            {
                "candidates": [{"content": {"parts": [{"text": '{"ok":true}'}]}}],
                "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 3},
            },
        ),
    ],
)
def test_protocol_normalization(db, protocol, payload):
    d = Document(
        id=uid(),
        owner="owner",
        kind="provider",
        data=canonical(
            {"adapter_type": protocol, "base_url": "https://example.com/v1"}
        ),
    )
    r = Adapter(d).normalize(payload, ModelRequest(model="m", messages=[]))
    assert (
        r.structured_content == {"ok": True}
        and r.input_tokens == 2
        and r.output_tokens == 3
    )


@pytest.mark.parametrize(
    "header",
    ["Host", "Connection", "Proxy-Authorization", "x-forwarded-for", "Content-Length"],
)
def test_unsafe_headers(header):
    with pytest.raises(Denied):
        validate_headers({header: "evil"})


def test_provider_ssrf(db):
    for url in [
        "http://example.com",
        "https://169.254.169.254",
        "https://127.0.0.1",
        "file:///etc/passwd",
        "https://u:p@example.com",
    ]:
        with pytest.raises(Denied):
            provider_scope(url)


def test_budget_reservations(db):
    a = reserve(db, "u", "r", 60)
    with pytest.raises(ProviderError):
        reserve(db, "u", "r", 41)
    settle(db, a, 20)
    db.commit()
    assert reserve(db, "u", "r", 80)


def test_run_role_campaign_pending_caps(db):
    c = document(db, "campaign", "u", {"budget_limit": 3})
    r = document(
        db,
        "run",
        "u",
        {
            "campaign_id": c.id,
            "budget_limit": 2,
            "budget_used": 0,
            "role_budgets": {"reasoning": 1},
        },
    )
    db.commit()
    a = reserve(db, "u", r.id, 0.75, "reasoning")
    with pytest.raises(ProviderError, match="Role budget"):
        reserve(db, "u", r.id, 0.5, "reasoning")
    b = reserve(db, "u", r.id, 1, "verifier")
    with pytest.raises(ProviderError, match="Run budget"):
        reserve(db, "u", r.id, 0.5, "verifier")
    other = document(
        db, "run", "u", {"campaign_id": c.id, "budget_limit": 2, "budget_used": 0}
    )
    db.commit()
    with pytest.raises(ProviderError, match="Campaign budget"):
        reserve(db, "u", other.id, 1.5, "reasoning")


@pytest.mark.parametrize(
    "protocol",
    [
        "openai_chat_completions",
        "openai_responses",
        "anthropic_messages",
        "gemini",
        "deepseek",
        "ollama_openai_compatible",
    ],
)
def test_protocol_serialization_tools_and_real_stream_option(protocol):
    d = Document(
        id=uid(),
        owner="u",
        kind="provider",
        data=canonical(
            {"adapter_type": protocol, "base_url": "https://example.invalid/v1"}
        ),
    )
    request = ModelRequest(
        model="fixture",
        messages=[
            {"role": "system", "content": "Stay in scope"},
            {"role": "user", "content": "Analyze a synthetic fixture"},
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "read_file_range",
                    "description": "Read authorized source",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )
    payload = Adapter(d).serialize(request, True)
    assert payload.get("tools") and (
        payload.get("stream") is True or protocol == "gemini"
    )


def test_registered_trusted_adapter_sdk(db):
    import atlas.gateway as g

    class Custom(g.Adapter):
        pass

    g.register_adapter("fixture_protocol", Custom)
    try:
        v = ProviderInput(
            display_name="Fixture protocol",
            adapter_type="fixture_protocol",
            base_url="https://example.invalid/v1",
        )
        d = Document(
            id=uid(),
            owner="u",
            kind="provider",
            data=canonical({"adapter_type": v.adapter_type, "base_url": v.base_url}),
        )
        assert isinstance(g.construct_adapter(d), Custom)
    finally:
        g.ADAPTERS.remove("fixture_protocol")
        g.PLUGIN_FACTORIES.pop("fixture_protocol")


def test_database_endpoint_tampering_cannot_redirect_credentials(db, provider_server):
    from cryptography.exceptions import InvalidTag

    d = create_provider(
        db,
        "owner",
        ProviderInput(
            display_name="Bound endpoint",
            base_url=provider_server,
            api_key="fixture-not-real-key",
        ),
    )
    db.commit()
    assert Adapter(d).headers()["Authorization"] == "Bearer fixture-not-real-key"
    v = d.value()
    v["base_url"] = provider_server + "/unapproved-path"
    d.data = canonical(v)
    with pytest.raises(InvalidTag):
        Adapter(d).headers()
