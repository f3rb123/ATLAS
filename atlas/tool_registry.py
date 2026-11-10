"""Central integration metadata and narrow, reviewed read-only adapters.

No installation hooks, shell templates, generic MCP calls or arbitrary HTTP
paths are configurable. Scanner entries explain their disabled harness state.
"""

import json
import shutil
import sys
import re
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
    "shodan": "supported_readonly; account/API entitlement required",
    "censys": "supported_readonly_v2; account/API entitlement required",
    "virustotal": "supported_readonly; account/API entitlement required",
    "fofa": "supported_readonly; account/API entitlement required",
}

API_ORIGINS = {
    "securitytrails": "api.securitytrails.com",
    "shodan": "api.shodan.io",
    "censys": "search.censys.io",
    "virustotal": "www.virustotal.com",
    "fofa": "fofa.info",
}


class IntegrationInput(Strict):
    name: str = Field(min_length=1, max_length=100)
    adapter: Literal[
        "securitytrails", "shodan", "censys", "virustotal", "fofa", "mcp_resources"
    ]
    base_url: str = Field(max_length=4096)
    api_key: str = Field(default="", max_length=8192, repr=False)
    reviewed_resource_uris: list[str] = Field(default_factory=list, max_length=30)
    readonly_contract_attested: bool = False
    reviewed_tool_names: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_endpoint(self):
        if any(
            re.search(
                r"(?i)delete|drop|truncate|destroy|purge|wipe|shell|exec|command|write|create|update|remove",
                name,
            )
            for name in self.reviewed_tool_names
        ):
            raise ValueError(
                "Destructive or command-like MCP tools cannot be registered"
            )
        if any(ord(c) < 33 or ord(c) > 126 for c in self.api_key):
            raise ValueError(
                "Integration credentials require printable ASCII without whitespace/control characters"
            )
        normalized, h, _, _, _ = normalize(self.base_url)
        if urlsplit(self.base_url).query or urlsplit(self.base_url).fragment:
            raise ValueError(
                "Integration endpoints cannot contain credentials/query/fragment"
            )
        validate_provider_configuration(self.base_url)
        if self.adapter in API_ORIGINS and (
            h != API_ORIGINS[self.adapter]
            or urlsplit(self.base_url).path not in ("", "/")
        ):
            raise ValueError(
                "Intelligence adapters use their fixed official API origin"
            )
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


class MCPResourceList(Strict):
    integration_id: str = Field(max_length=36)


class MCPToolLookup(IntelligenceLookup):
    tool_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")


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
    if value["adapter"] == "virustotal":
        return {"x-apikey": token, "Accept": "application/json"}
    if value["adapter"] == "censys":
        import base64

        return {
            "Authorization": "Basic " + base64.b64encode(token.encode()).decode(),
            "Accept": "application/json",
        }
    if value["adapter"] in ("shodan", "fofa"):
        return {"Accept": "application/json"}
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
        fragments = []
        if value.get("secret"):
            import base64

            secret = open_secret(value["secret"], identity(row))
            fragments = [secret, base64.b64encode(secret.encode()).decode()]
            if value["adapter"] in ("fofa", "censys"):
                fragments += secret.split(":", 1)

        def clean(item):
            if isinstance(item, str):
                for fragment in fragments:
                    if len(fragment) >= 4:
                        item = item.replace(fragment, "[REDACTED CREDENTIAL]")
                return redact(item)
            if isinstance(item, list):
                return [clean(v) for v in item]
            if isinstance(item, dict):
                return {k: clean(v) for k, v in item.items()}
            return item

        parsed = clean(json.loads(text))
        return (parsed, received_headers) if response_headers else parsed
    except (ValueError, UnicodeError):
        raise Denied(
            "Integration requires a bounded JSON response; streaming responses are unsupported"
        ) from None


def mcp(row, method, params):
    # Only these two read-only JSON-RPC methods are exposed. The server's
    # resources are untrusted; it cannot advertise new executable capabilities.
    if method not in ("resources/list", "resources/read", "tools/list", "tools/call"):
        raise Denied("MCP method is not registered")
    if method == "tools/list" and not row.value().get("reviewed_tool_names"):
        raise Denied("MCP tools are not registered for this resource connection")
    if method == "tools/call":
        from .policy import host

        allowed = [t["name"] for t in row.value().get("verified_tools", [])]
        if params.get("name") not in allowed or set(params.get("arguments", {})) != {
            "hostname"
        }:
            raise Denied("MCP tool is not registered and independently reviewed")
        host(params["arguments"]["hostname"])
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
            mcp(row, "resources/list", {})
            if value["adapter"] == "mcp_resources"
            else intelligence_read(row, None)
        )
        if value["adapter"] == "mcp_resources" and value.get("reviewed_tool_names"):
            listed = mcp(row, "tools/list", {}).get("tools", [])
            verified = []
            for name in value["reviewed_tool_names"]:
                tool = next((t for t in listed if t.get("name") == name), None)
                schema = tool.get("inputSchema", {}) if tool else {}
                if (
                    schema.get("type") != "object"
                    or set(schema.get("properties", {})) != {"hostname"}
                    or schema["properties"]["hostname"].get("type") != "string"
                    or schema.get("required") != ["hostname"]
                    or schema.get("additionalProperties") is not False
                ):
                    raise Denied(
                        "Reviewed MCP intelligence tools require exactly one bounded hostname argument"
                    )
                verified.append(
                    {"name": name, "schema_hash": digest(canonical(schema))}
                )
            value["verified_tools"] = verified
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
    row.version += 1
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
    row.version += 1
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
        "integration_pins" in run.value()
        and run.value()["integration_pins"].get(row.id) != row.version
    ):
        raise Denied(
            "Integration was not pinned to this run or its configuration changed"
        )
    if (
        capability == "mcp_list_reviewed_resources"
        and row.value()["adapter"] == "mcp_resources"
    ):
        return {
            "integration_id": row.id,
            "resources": row.value().get("reviewed_resource_uris", []),
            "hostname_tools": [
                t["name"] for t in row.value().get("verified_tools", [])
            ],
            "trust": "operator-reviewed metadata; no new authority",
        }
    from .db import transaction_lock

    transaction_lock(db, "integration-quota:" + run.id)
    db.refresh(run, with_for_update=True)
    usage = run.value()
    if usage.get("integration_requests", 0) >= 20:
        raise Denied("External integration request quota exhausted for this run")
    usage["integration_requests"] = usage.get("integration_requests", 0) + 1
    usage["unverified_external_billing"] = True
    run.data = canonical(usage)
    append(
        db,
        run.id,
        "tool-gateway",
        "integration_read_reserved",
        {
            "integration_id": row.id,
            "capability": capability,
            "billing": "provider-account charges unverified",
        },
        usage.get("campaign_id"),
    )
    db.commit()
    if (
        capability == "external_intelligence_lookup"
        and row.value()["adapter"] in API_ORIGINS
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
        from .network_research import scoped_origin

        scoped_origin(
            __import__("atlas.policy", fromlist=["Scope"]).Scope.model_validate(
                policy.value()["scope"]
            ),
            hostname,
            metadata=True,
        )
        data = intelligence_read(row, hostname)
    elif (
        capability == "mcp_read_resource" and row.value()["adapter"] == "mcp_resources"
    ):
        if args.uri not in row.value()["reviewed_resource_uris"]:
            raise Denied("MCP resource URI was not explicitly reviewed")
        data = mcp(row, "resources/read", {"uri": args.uri})
    elif (
        capability == "mcp_intelligence_lookup"
        and row.value()["adapter"] == "mcp_resources"
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
        from .network_research import scoped_origin

        scoped_origin(
            __import__("atlas.policy", fromlist=["Scope"]).Scope.model_validate(
                policy.value()["scope"]
            ),
            hostname,
            metadata=True,
        )
        if args.tool_name not in [
            t["name"] for t in row.value().get("verified_tools", [])
        ]:
            raise Denied("MCP intelligence tool is not explicitly reviewed and tested")
        data = mcp(
            row,
            "tools/call",
            {"name": args.tool_name, "arguments": {"hostname": hostname}},
        )
    else:
        raise Denied("Integration does not implement the requested capability")
    return {
        "integration_id": row.id,
        "adapter_version": row.value()["adapter_version"],
        "trust": "untrusted_external_evidence",
        "billing": "Provider-account charges are unverified; bounded integration quota applies",
        "result": data,
    }


def intelligence_read(row, hostname):
    """Fixed read-only query shapes, bounded output; no operator/model URL templates."""
    import base64
    from urllib.parse import urlencode

    adapter = row.value()["adapter"]
    token = (
        open_secret(row.value()["secret"], identity(row))
        if row.value().get("secret")
        else ""
    )
    if not token:
        raise Denied("This intelligence API requires a configured credential")
    if adapter == "securitytrails":
        return http_json(row, "/v1/domain/" + hostname if hostname else "/v1/ping")
    if adapter == "virustotal":
        # A bounded official domain lookup also verifies the credential without
        # submitting files, URLs or samples to a third party.
        return http_json(row, "/api/v3/domains/" + (hostname or "example.com"))
    if adapter == "shodan":
        path = "/dns/domain/" + hostname if hostname else "/api-info"
        return http_json(
            row,
            path + "?" + urlencode({"key": token, **({"page": 1} if hostname else {})}),
        )
    if adapter == "censys":
        if ":" not in token:
            raise Denied("Censys v2 credential binding requires API_ID:API_SECRET")
        return http_json(
            row,
            "/api/v2/hosts/search?"
            + urlencode(
                {
                    "q": "services.tls.certificates.leaf_data.names: " + hostname,
                    "per_page": 10,
                }
            )
            if hostname
            else "/api/v1/account",
        )
    if adapter == "fofa":
        if ":" not in token:
            raise Denied("FOFA credential binding requires EMAIL:API_KEY")
        email, key = token.split(":", 1)
        if not hostname:
            return http_json(
                row, "/api/v1/info/my?" + urlencode({"email": email, "key": key})
            )
        query = base64.b64encode(('domain="' + hostname + '"').encode()).decode()
        return http_json(
            row,
            "/api/v1/search/all?"
            + urlencode(
                {
                    "email": email,
                    "key": key,
                    "qbase64": query,
                    "fields": "host,ip,port",
                    "size": 10,
                }
            ),
        )
    raise Denied("Unknown intelligence adapter")


def inventory(db, owner):
    from .tools import TOOLS
    from .scanner_runtime import EXECUTABLE_TOOLS, tool_state

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
        "binaries": [tool_state(db, owner, name) for name in sorted(EXECUTABLE_TOOLS)]
        + [
            {
                "name": name,
                "installed": bool(shutil.which(name)),
                "version": None,
                "enabled": False,
                "import_supported": name in ("amass", "masscan"),
                "reason": "Scoped owner-supplied JSON imports; execution is external to this worker"
                if name in ("amass", "masscan")
                else reason,
            }
            for name, reason in BINARIES.items()
            if name not in EXECUTABLE_TOOLS
        ],
        "runtime": {
            "python": sys.version.split()[0],
            "offline_tests": "typed Python unittest/compile sandbox; explicit run approval required",
        },
        "api_adapters": APIS,
        "templates": [
            {
                "id": row.id,
                "template_id": row.value()["template_id"],
                "version": row.value()["version"],
                "sha256": row.value()["sha256"],
                "enabled": row.value().get("enabled"),
            }
            for row in db.query(Document).filter_by(
                kind="scanner_template", owner=owner
            )
        ],
        "mcp": "JSON resource list/read only; exact reviewed URIs; no generic tool calls or server commands",
        "integrations": [
            safe(row)
            for row in db.query(Document).filter_by(
                kind="tool_integration", owner=owner
            )
        ],
    }
