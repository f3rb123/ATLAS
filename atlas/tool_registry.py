"""Central integration metadata and narrow, reviewed read-only adapters.

No installation hooks, shell templates, generic MCP calls or arbitrary HTTP
paths are configurable. Scanner entries explain their disabled harness state.
"""

import json
import shutil
import sys
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from .db import Document, append, canonical, digest, document, now
from .gateway import provider_scope, validate_provider_configuration
from .policy import Denied, Strict, authorize, normalize, request
from .vault import open_secret, redact, seal

BINARIES = {
    name: "A version-pinned, scoped execution harness is required before activation"
    for name in (
        "subfinder",
        "amass",
        "httpx",
        "dnsx",
        "naabu",
        "nuclei",
        "katana",
        "ffuf",
        "gau",
        "waybackurls",
        "masscan",
    )
}
APIS = {
    "securitytrails": "supported_readonly",
    "shodan": "disabled: reviewed scoped adapter required",
    "censys": "disabled: reviewed scoped adapter required",
    "virustotal": "disabled: reviewed scoped adapter required",
    "fofa": "disabled: reviewed scoped adapter required",
}


class IntegrationInput(Strict):
    name: str = Field(min_length=1, max_length=100)
    adapter: Literal["securitytrails", "mcp_resources"]
    base_url: str = Field(max_length=4096)
    api_key: str = Field(default="", max_length=8192, repr=False)
    reviewed_resource_uris: list[str] = Field(default_factory=list, max_length=30)
    readonly_contract_attested: bool = False

    @model_validator(mode="after")
    def validate_endpoint(self):
        normalized, h, _, _, _ = normalize(self.base_url)
        if urlsplit(self.base_url).query or urlsplit(self.base_url).fragment:
            raise ValueError(
                "Integration endpoints cannot contain credentials/query/fragment"
            )
        validate_provider_configuration(self.base_url)
        if self.adapter == "securitytrails" and (
            h != "api.securitytrails.com"
            or urlsplit(self.base_url).path not in ("", "/")
        ):
            raise ValueError("SecurityTrails uses its fixed official API origin")
        if self.adapter == "mcp_resources" and not self.readonly_contract_attested:
            raise ValueError(
                "MCP resources require an operator-reviewed read-only server contract"
            )
        if any(
            not uri or len(uri) > 2000 or any(ord(c) < 32 for c in uri)
            for uri in self.reviewed_resource_uris
        ):
            raise ValueError("Invalid reviewed MCP resource URI")
        return self


class IntelligenceLookup(Strict):
    integration_id: str = Field(max_length=36)
    hostname: str = Field(min_length=1, max_length=253)


class MCPRead(Strict):
    integration_id: str = Field(max_length=36)
    uri: str = Field(min_length=1, max_length=2000)


def identity(row):
    value = row.value()
    return f"tool-integration:{row.owner}:{row.id}:{value['adapter']}:{digest(value['base_url'])}"


def safe(row):
    value = row.value()
    return {
        "id": row.id,
        "version": row.version,
        **{k: v for k, v in value.items() if k != "secret"},
        "credential_configured": bool(value.get("secret")),
    }


def create(db, owner, body):
    value = body.model_dump(exclude={"api_key"})
    value.update(
        enabled=False,
        health="untested",
        last_error=None,
        adapter_version="1.0.0",
        created_at=now(),
    )
    row = document(db, "tool_integration", owner, value)
    if body.api_key:
        value["secret"] = seal(body.api_key, identity(row))
        row.data = canonical(value)
    append(
        db,
        owner,
        owner,
        "tool_integration_created",
        {"id": row.id, "adapter": body.adapter},
    )
    return row


def headers(row):
    value = row.value()
    token = open_secret(value["secret"], identity(row)) if value.get("secret") else ""
    if value["adapter"] == "securitytrails":
        return {"APIKEY": token, "Accept": "application/json"}
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        **({"Authorization": "Bearer " + token} if token else {}),
    }


def http_json(
    row, path, body=None, extra_headers=None, response_headers=False, notification=False
):
    value = row.value()
    url = value["base_url"].rstrip("/") + path
    # Fresh DNS validation/pinning applies to every request, including MCP POSTs.
    scope = provider_scope(value["base_url"])
    response, received_headers, data = request(
        url,
        "POST" if body is not None else "GET",
        headers={**headers(row), **(extra_headers or {})},
        body=canonical(body).encode() if body is not None else None,
        scope=scope,
        max_bytes=65536,
        timeout=15,
    )
    if notification and response in (200, 202, 204):
        return None
    if response != 200:
        raise Denied(f"Integration returned HTTP {response}; response content withheld")
    try:
        text = data.decode("utf-8")
        if value.get("secret"):
            text = text.replace(
                open_secret(value["secret"], identity(row)), "[REDACTED CREDENTIAL]"
            )
        parsed = json.loads(redact(text))
        return (parsed, received_headers) if response_headers else parsed
    except (ValueError, UnicodeError):
        raise Denied(
            "Integration requires a bounded JSON response; streaming responses are unsupported"
        ) from None


def mcp(row, method, params):
    # Only these two read-only JSON-RPC methods are exposed. The server's
    # resources are untrusted; it cannot advertise new executable capabilities.
    if method not in ("resources/list", "resources/read"):
        raise Denied("MCP method is not registered")
    initialized, received = http_json(
        row,
        "",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ATLAS-readonly-resources", "version": "1.0.0"},
            },
        },
        response_headers=True,
    )
    if (
        not isinstance(initialized, dict)
        or initialized.get("error")
        or not isinstance(initialized.get("result"), dict)
    ):
        raise Denied("MCP initialization failed")
    session_id = next(
        (v for k, v in received.items() if k.lower() == "mcp-session-id"), None
    )
    protocol = initialized["result"].get("protocolVersion")
    if protocol != "2025-03-26":
        raise Denied(
            "Unsupported MCP protocol version; reviewed adapter upgrade required"
        )
    session_headers = {
        "MCP-Protocol-Version": protocol,
        **({"Mcp-Session-Id": session_id} if session_id else {}),
    }
    http_json(
        row,
        "",
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        extra_headers=session_headers,
        notification=True,
    )
    result = http_json(
        row,
        "",
        {"jsonrpc": "2.0", "id": 2, "method": method, "params": params},
        extra_headers=session_headers,
    )
    if not isinstance(result, dict) or result.get("error") or "result" not in result:
        raise Denied("MCP resource request failed; server content withheld")
    return result["result"]


def test_connection(db, row, actor):
    value = row.value()
    try:
        result = (
            http_json(row, "/v1/ping")
            if value["adapter"] == "securitytrails"
            else mcp(row, "resources/list", {})
        )
        value.update(health="tested", last_error=None, tested_at=now())
        metadata = (
            {"resource_count": len(result.get("resources", []))}
            if value["adapter"] == "mcp_resources"
            else {"connection": "responded"}
        )
    except Exception as exc:
        value.update(
            health="failed",
            enabled=False,
            last_error=type(exc).__name__,
            tested_at=now(),
        )
        metadata = {"error_type": type(exc).__name__}
    row.data = canonical(value)
    append(
        db,
        row.owner,
        actor,
        "tool_connection_tested",
        {"id": row.id, "health": value["health"], **metadata},
    )
    return {"health": value["health"], **metadata}


def enable(db, row, enabled, actor):
    value = row.value()
    if enabled and value.get("health") != "tested":
        raise Denied("Test the integration before enabling it")
    value["enabled"] = enabled
    row.data = canonical(value)
    append(
        db,
        row.owner,
        actor,
        "tool_enablement_changed",
        {"id": row.id, "enabled": enabled},
    )


def execute(db, run, capability, args):
    row = db.get(Document, args.integration_id)
    if (
        not row
        or row.kind != "tool_integration"
        or row.owner != run.owner
        or not row.value().get("enabled")
        or row.value().get("health") != "tested"
    ):
        raise Denied("Integration is not owned, tested and enabled")
    if run.value().get("assessment_profile") == "smoke_readonly":
        raise Denied(
            "External intelligence and MCP collection are disabled in minimal target smoke tests"
        )
    if (
        capability == "external_intelligence_lookup"
        and row.value()["adapter"] == "securitytrails"
    ):
        from .policy import host

        hostname = host(args.hostname)
        policy = db.get(Document, run.value()["policy_id"])
        if (
            not policy
            or policy.owner != run.owner
            or digest(canonical(policy.value()["scope"])) != run.value()["policy_hash"]
        ):
            raise Denied("Frozen target policy integrity failed")
        authorize(policy.value()["scope"], "https://" + hostname + "/", "HEAD")
        data = http_json(row, "/v1/domain/" + hostname)
    elif (
        capability == "mcp_read_resource" and row.value()["adapter"] == "mcp_resources"
    ):
        if args.uri not in row.value()["reviewed_resource_uris"]:
            raise Denied("MCP resource URI was not explicitly reviewed")
        data = mcp(row, "resources/read", {"uri": args.uri})
    else:
        raise Denied("Integration does not implement the requested capability")
    return {
        "integration_id": row.id,
        "adapter_version": row.value()["adapter_version"],
        "trust": "untrusted_external_evidence",
        "result": data,
    }


def inventory(db, owner):
    from .tools import TOOLS

    return {
        "capabilities": [
            {
                "name": name,
                "risk": risk,
                "state": "registered; run policy and quotas required",
                "schema": model.model_json_schema() if model else {},
            }
            for name, (risk, model) in TOOLS.items()
        ],
        "binaries": [
            {
                "name": name,
                "installed": bool(shutil.which(name)),
                "version": None,
                "enabled": False,
                "reason": reason,
            }
            for name, reason in BINARIES.items()
        ],
        "runtime": {
            "python": sys.version.split()[0],
            "offline_tests": "typed Python unittest/compile sandbox; explicit run approval required",
        },
        "api_adapters": APIS,
        "mcp": "JSON resource list/read only; exact reviewed URIs; no generic tool calls or server commands",
        "integrations": [
            safe(row)
            for row in db.query(Document).filter_by(
                kind="tool_integration", owner=owner
            )
        ],
    }
