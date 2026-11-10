"""Scoped, attributed imports of externally executed scanner output."""

import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from .db import append, canonical, digest, document
from .network_research import scoped_origin
from .policy import Denied, Strict, host, match, normalize
from .web_research import scope_for


class ToolImport(Strict):
    run_id: str
    tool: Literal[
        "amass",
        "masscan",
        "subfinder",
        "dnsx",
        "naabu",
        "httpx",
        "katana",
        "nuclei",
        "ffuf",
        "gau",
        "waybackurls",
    ]
    version: str = Field(default="owner-supplied/unverified", max_length=100)
    content: str = Field(min_length=1, max_length=1024 * 1024, repr=False)


def import_output(db, run, body, actor):
    scope = scope_for(db, run)
    try:
        value = json.loads(body.content)
        rows = (
            value
            if isinstance(value, list)
            else value.get("results", [value])
            if isinstance(value, dict)
            else []
        )
    except ValueError:
        rows = []
        for line in body.content.splitlines()[:5000]:
            try:
                rows.append(json.loads(line))
            except ValueError:
                if line.startswith(("http://", "https://")):
                    rows.append({"url": line.strip()})
    if len(rows) > 5000:
        raise Denied("Scanner output record quota exceeded")
    accepted = []
    rejected = 0
    for row in rows:
        if not isinstance(row, dict):
            rejected += 1
            continue
        url = (
            row.get("url")
            or row.get("matched-at")
            or (
                row.get("request", {}).get("endpoint")
                if isinstance(row.get("request"), dict)
                else None
            )
        )
        name = (
            row.get("name") or row.get("hostname") or row.get("host") or row.get("ip")
        )
        try:
            if url:
                url, h, p, path, scheme = normalize(url)
                if not any(
                    match(r, h, p, path, scheme, "GET") for r in scope.allow
                ) or any(match(r, h, p, path, scheme, "GET") for r in scope.deny):
                    raise Denied("Imported URL outside scope")
                name = h
            else:
                name = host(name)
                scoped_origin(scope, name)
            ports = [
                item.get("port")
                for item in row.get("ports", [])
                if isinstance(item, dict)
                and type(item.get("port")) is int
                and 1 <= item["port"] <= 65535
            ][:20]
            if row.get("port") and type(row["port"]) is int:
                ports.append(row["port"])
            for port in ports:
                scoped_origin(scope, name, port)
            accepted.append(
                {
                    "hostname": name,
                    "url": url,
                    "ports": ports,
                    "template_id": str(row.get("template-id", ""))[:100] or None,
                }
            )
        except (Denied, ValueError, TypeError, AttributeError):
            rejected += 1
    record = document(
        db,
        "external_tool_import",
        run.owner,
        {
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "tool": body.tool,
            "version": body.version,
            "source_sha256": digest(body.content),
            "provided_by": actor,
            "execution": "owner-supplied output; not executed by ATLAS",
            "trust": "unverified_external_observations",
            "records": accepted,
            "accepted": len(accepted),
            "rejected": rejected,
        },
    )
    append(
        db,
        run.id,
        actor,
        "external_tool_output_imported",
        {
            "id": record.id,
            "tool": body.tool,
            "accepted": len(accepted),
            "rejected": rejected,
        },
        run.value()["campaign_id"],
    )
    return {
        "id": record.id,
        "accepted": len(accepted),
        "rejected": rejected,
        "status": "unverified_external_observations",
    }
