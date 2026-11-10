"""Controlled local HTTP integration; no public scanner/API is invoked."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from pydantic import ValidationError

from atlas.config import settings
from atlas.db import canonical, digest, document
from atlas.policy import Denied
from atlas.tool_registry import (
    IntegrationInput,
    MCPRead,
    IntelligenceLookup,
    create,
    enable,
    execute,
    identity,
    mcp,
    safe,
    test_connection as probe,
)
from atlas.vault import master, open_secret, rotate_database_keys


@pytest.fixture
def mcp_server(db):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["Authorization"] == "Bearer fixture-tool-key"
            method = value["method"]
            calls.append(method)
            if method == "notifications/initialized":
                self.send_response(202)
                self.end_headers()
                return
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "fixture", "version": "1"},
                }
            elif method == "resources/list":
                result = {
                    "resources": [
                        {"uri": "fixture://reviewed", "name": "Reviewed fixture"}
                    ]
                }
            else:
                assert (
                    method == "resources/read"
                    and self.headers["Mcp-Session-Id"] == "fixture-session"
                )
                result = {
                    "contents": [
                        {
                            "uri": value["params"]["uri"],
                            "text": "Untrusted fixture-tool-key",
                        }
                    ]
                }
            self.send_response(200)
            self.send_header("Mcp-Session-Id", "fixture-session")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": value["id"], "result": result}
                ).encode()
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings().provider_local_allowlist = [f"127.0.0.1:{server.server_port}"]
    yield f"http://127.0.0.1:{server.server_port}/mcp", calls
    server.shutdown()


def test_mcp_handshake_reviewed_resources_and_write_only_secret(db, mcp_server):
    url, calls = mcp_server
    row = create(
        db,
        "u",
        IntegrationInput(
            name="Local resource fixture",
            adapter="mcp_resources",
            base_url=url,
            api_key="fixture-tool-key",
            readonly_contract_attested=True,
            reviewed_resource_uris=["fixture://reviewed"],
        ),
    )
    assert (
        "fixture-tool-key" not in canonical(safe(row))
        and "fixture-tool-key" not in row.data
    )
    with pytest.raises(Denied, match="Test"):
        enable(db, row, True, "u")
    assert probe(db, row, "u")["health"] == "tested"
    enable(db, row, True, "u")
    run = document(db, "run", "u", {})
    result = execute(
        db,
        run,
        "mcp_read_resource",
        MCPRead(integration_id=row.id, uri="fixture://reviewed"),
    )
    assert "fixture-tool-key" not in canonical(result)
    assert calls == [
        "initialize",
        "notifications/initialized",
        "resources/list",
        "initialize",
        "notifications/initialized",
        "resources/read",
    ]
    with pytest.raises(Denied, match="reviewed"):
        execute(
            db,
            run,
            "mcp_read_resource",
            MCPRead(integration_id=row.id, uri="file:///unreviewed"),
        )
    with pytest.raises(Denied, match="not registered"):
        mcp(row, "tools/call", {"name": "delete_database"})
    run.owner = "other"
    with pytest.raises(Denied, match="owned"):
        execute(
            db,
            run,
            "mcp_read_resource",
            MCPRead(integration_id=row.id, uri="fixture://reviewed"),
        )


def test_api_target_scope_denial_precedes_external_request(db, monkeypatch):
    row = create(
        db,
        "u",
        IntegrationInput(
            name="SecurityTrails",
            adapter="securitytrails",
            base_url="https://api.securitytrails.com",
        ),
    )
    value = row.value()
    value.update(enabled=True, health="tested")
    row.data = canonical(value)
    scope = {"allow": [{"host": "allowed.example.invalid"}], "deny": []}
    policy = document(db, "policy", "u", {"scope": scope})
    run = document(
        db,
        "run",
        "u",
        {"policy_id": policy.id, "policy_hash": digest(canonical(scope))},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Out-of-scope request reached external API")

    monkeypatch.setattr("atlas.tool_registry.http_json", forbidden)
    with pytest.raises(Denied, match="scope"):
        execute(
            db,
            run,
            "external_intelligence_lookup",
            IntelligenceLookup(
                integration_id=row.id, hostname="excluded.example.invalid"
            ),
        )


def test_key_rotation_includes_integrations_and_endpoint_identity(db, mcp_server):
    row = create(
        db,
        "u",
        IntegrationInput(
            name="Resource fixture",
            adapter="mcp_resources",
            base_url=mcp_server[0],
            api_key="fixture-tool-key",
            readonly_contract_attested=True,
        ),
    )
    old = master()
    new = b"n" * 32
    assert rotate_database_keys(db, new, old) == 1
    assert open_secret(row.value()["secret"], identity(row), new) == "fixture-tool-key"
    value = row.value()
    value["base_url"] += "/changed"
    row.data = canonical(value)
    with pytest.raises(Exception):
        open_secret(row.value()["secret"], identity(row), new)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.securitytrails.com/?key=untrusted",
        "https://api.securitytrails.com/#fragment",
        "https://unrelated.invalid/",
    ],
)
def test_fixed_api_endpoint_rejects_key_query_fragments_and_other_origins(url):
    with pytest.raises((ValidationError, Denied)):
        IntegrationInput(name="bad", adapter="securitytrails", base_url=url)
