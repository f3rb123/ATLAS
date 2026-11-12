"""Bounded DNS, TCP-connect and public-index lookups through the target relay."""

import ipaddress
import socket
import time
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import Field

from .db import Document, append, canonical, digest, document, session, transaction_lock
from .policy import (
    Denied,
    Rule,
    Scope,
    Strict,
    addresses,
    authorize,
    host,
    match,
    request,
)
from .target_transport import (
    TargetRequest,
    fail_observation,
    validate_run,
    wait_for_dispatch,
)
from .vault import redact


METADATA_HOSTS = {"crt.sh", "web.archive.org", "index.commoncrawl.org"}


class NetworkRequest(Strict):
    run_id: str
    kind: Literal["dns", "connect", "metadata"]
    hostname: str = Field(max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    record_type: Literal["A", "AAAA"] = "A"
    url: str | None = Field(default=None, max_length=4096)
    task_id: str | None = None
    lease_token: str | None = Field(default=None, repr=False)
    request_deadline: float | None = Field(default=None, gt=0, allow_inf_nan=False)


def scoped_origin(scope, hostname, port=None, metadata=False):
    hostname = host(hostname)
    for rule in scope.allow:
        if metadata and rule.host == "*." + hostname:
            if not any(r.host in (hostname, "*." + hostname) for r in scope.deny):
                return hostname
        for p in [port] if port else rule.ports:
            for scheme in rule.schemes:
                for path in rule.paths:
                    for method in ("HEAD", "GET"):
                        if match(rule, hostname, p, path, scheme, method) and not any(
                            match(r, hostname, p, path, scheme, method)
                            for r in scope.deny
                        ):
                            net = "[" + hostname + "]" if ":" in hostname else hostname
                            return f"{scheme}://{net}:{p}{path}"
    raise Denied("Network lookup is outside the frozen hostname/port scope")


def metadata_allowed(url, domain):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in METADATA_HOSTS
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise Denied("Public index destination is not registered")
    if (
        parsed.hostname == "index.commoncrawl.org"
        and parsed.path == "/collinfo.json"
        and not query
    ):
        return
    if parsed.hostname == "crt.sh" and parsed.path == "/":
        value = query.get("q", [""])[0].replace("%", "").lstrip(".")
        if value == domain and set(query) <= {"q", "output", "exclude"}:
            return
    if parsed.hostname in ("web.archive.org", "index.commoncrawl.org") and (
        parsed.path == "/cdx/search/cdx" or parsed.path.endswith("-index")
    ):
        value = query.get("url", [""])[0]
        value = (
            value.removeprefix("https://")
            .removeprefix("http://")
            .removeprefix("*.")
            .split("/", 1)[0]
        )
        if value == domain and set(query) <= {
            "url",
            "output",
            "fl",
            "collapse",
            "filter",
            "matchType",
            "from",
            "to",
            "limit",
            "page",
            "pageSize",
            "showNumPages",
        }:
            return
    raise Denied("Public index query is not a registered scoped domain lookup")


def execute(body, actor="network-relay"):
    hostname = host(body.hostname)
    with session() as db:
        transaction_lock(db, "relay:" + body.run_id)
        run = (
            db.query(Document)
            .filter_by(id=body.run_id, kind="run")
            .with_for_update()
            .first()
        )
        if not run:
            raise Denied("Run unavailable")
        value, scope, campaign = validate_run(
            db,
            run,
            TargetRequest(
                run_id=body.run_id,
                url="https://" + hostname + "/",
                task_id=body.task_id,
                lease_token=body.lease_token,
                request_deadline=body.request_deadline,
            ),
        )
        if value.get("assessment_profile") == "smoke_readonly":
            raise Denied(
                "Network discovery is unavailable in the smoke acceptance profile"
            )
        required = {"dns": "dns", "connect": "ports", "metadata": "passive_sources"}[
            body.kind
        ]
        if required not in scope.test_classes:
            raise Denied("Network capability is outside the frozen campaign policy")
        origin = scoped_origin(
            scope,
            hostname,
            body.port if body.kind == "connect" else None,
            metadata=body.kind == "metadata",
        )
        if body.kind == "metadata":
            metadata_allowed(body.url or "", hostname)
        if value.get("http_requests", 0) >= scope.max_requests:
            raise Denied("Network request quota exhausted")
        timestamp = time.time()
        slot = max(timestamp, value.get("next_request_at", 0))
        if slot + 5 > value["deadline"]:
            raise Denied("Run deadline prevents network dispatch")
        if body.request_deadline is not None and slot >= body.request_deadline:
            raise Denied("Tool deadline prevents reserved network request")
        value.update(
            http_requests=value.get("http_requests", 0) + 1,
            next_request_at=slot + scope.min_request_interval,
        )
        run.data = canonical(value)
        observation = document(
            db,
            "network_observation",
            run.owner,
            {
                "run_id": run.id,
                "campaign_id": value["campaign_id"],
                "kind": body.kind,
                "hostname": hostname,
                "port": body.port if body.kind == "connect" else None,
                "state": "reserved",
                "url": body.url,
            },
        )
        id = observation.id
        append(
            db,
            run.id,
            actor,
            "network_request_reserved",
            {
                "observation_id": id,
                "kind": body.kind,
                "hostname": hostname,
                "port": body.port,
            },
            value["campaign_id"],
        )
        db.commit()
    try:
        wait_for_dispatch(
            TargetRequest(
                run_id=body.run_id,
                url="https://" + hostname + "/",
                task_id=body.task_id,
                lease_token=body.lease_token,
                request_deadline=body.request_deadline,
            ),
            slot,
        )
    except Exception as exc:
        fail_observation(id, exc, actor, state="cancelled")
        raise
    try:
        if body.kind == "metadata":
            destination = urlsplit(body.url).hostname
            transport_scope = Scope(allow=[Rule(host=destination)])
            status, headers, content = request(
                body.url,
                "GET",
                headers={
                    "Accept": "application/json",
                    "User-Agent": "ATLAS-authorized-passive-research/1",
                    "Accept-Encoding": "identity",
                },
                scope=transport_scope,
                max_bytes=min(scope.max_response_bytes, 1024 * 1024),
                timeout=10,
                deadline=min(
                    value["deadline"], body.request_deadline or value["deadline"]
                ),
            )
            result = {
                "status": status,
                "headers": {
                    k.lower(): redact(v)
                    for k, v in headers.items()
                    if k.lower() in ("content-type", "content-length")
                },
                "body": redact(content.decode(errors="replace"))[:65536],
                "body_sha256": digest(content),
                "body_truncated": len(content.decode(errors="replace")) > 65536 or len(content) >= min(scope.max_response_bytes, 1024 * 1024),
            }
        elif body.kind == "dns":
            ips = addresses(hostname, body.port, scope.lab_networks)
            version = 4 if body.record_type == "A" else 6
            result = {
                "addresses": [
                    ip for ip in ips if ipaddress.ip_address(ip).version == version
                ],
                "record_type": body.record_type,
            }
        else:
            _, _, port, ips = authorize(
                scope,
                origin,
                "HEAD" if any("HEAD" in r.methods for r in scope.allow) else "GET",
            )
            connection = socket.socket(
                socket.AF_INET6 if ":" in ips[0] else socket.AF_INET, socket.SOCK_STREAM
            )
            left = min(2, (body.request_deadline or value["deadline"]) - time.time())
            if left <= 0:
                raise Denied("Network tool deadline exhausted before connect")
            connection.settimeout(left)
            try:
                opened = connection.connect_ex((ips[0], port)) == 0
            finally:
                connection.close()
            result = {"open": opened, "port": port, "application_bytes_sent": 0}
        result.update(
            observation_id=id, hostname=hostname, trust="untrusted_network_evidence"
        )
        with session() as db:
            row = db.get(Document, id)
            value = row.value()
            value.update(state="completed", result=result)
            row.data = canonical(value)
            db.commit()
        return result
    except Exception as exc:
        fail_observation(id, exc, actor)
        raise


def send(db, run, body, request_deadline=None):
    from .config import settings
    from .swarm import check_fence
    from pathlib import Path

    check_fence(db, run)
    claim = getattr(run, "_swarm_claim", (None, None))
    request = NetworkRequest(
        run_id=run.id,
        task_id=claim[0],
        lease_token=claim[1],
        request_deadline=request_deadline,
        **body,
    )
    db.commit()
    if settings().relay_url:
        import httpx

        with httpx.Client(timeout=30, trust_env=False) as client:
            response = client.post(
                settings().relay_url + "/network",
                headers={
                    "Authorization": "Bearer "
                    + Path(settings().service_token_file).read_text().strip()
                },
                json=request.model_dump(),
            )
        if response.status_code != 200:
            raise Denied("Network relay denied or failed the lookup")
        result = response.json()
    else:
        if settings().production:
            raise Denied("Production network discovery requires the target relay")
        result = execute(request)
    db.expire_all()
    check_fence(db, run)
    return result
