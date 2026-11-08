"""Human-reviewed source permissions. No recursive crawling, credentials or arbitrary targets."""

import time, urllib.robotparser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Literal
from pydantic import Field
from .policy import Strict, Scope, Rule, Denied, normalize, request
from .db import Document, document, canonical, digest, now, append


class SourcePolicy(Strict):
    native_source: Literal["ghsa", "cve", "nvd", "osv", "kev"] | None = None
    name: str = Field(min_length=1, max_length=150)
    source_url: str = Field(max_length=4096)
    terms_url: str = Field(max_length=4096)
    license: str = Field(min_length=1, max_length=150)
    full_text_policy: Literal["allowed", "metadata_only", "unknown_or_restricted"] = (
        "unknown_or_restricted"
    )
    owner_reviewed: bool = False
    record_type: Literal[
        "research_report", "bug_bounty_disclosure", "training_reference"
    ] = "research_report"
    enabled: bool = False
    rate_seconds: int = Field(default=2, ge=1, le=60)


def register(db, owner, policy):
    n, h, p, _, scheme = normalize(policy.source_url)
    if scheme != "https":
        raise Denied("Source acquisition requires HTTPS")
    if policy.enabled and (
        not policy.owner_reviewed
        or policy.full_text_policy != "allowed"
        or policy.license.lower() == "unknown"
    ):
        raise Denied("Review source terms and full-text permission before enabling")
    normalize(policy.terms_url)
    d = document(
        db,
        "source_policy",
        owner,
        {
            **policy.model_dump(),
            "source_url": n,
            "reviewed_by": owner if policy.owner_reviewed else None,
            "reviewed_at": now() if policy.owner_reviewed else None,
        },
    )
    append(
        db,
        owner,
        owner,
        "source_policy_registered",
        {"id": d.id, "enabled": policy.enabled, "license": policy.license},
    )
    return d


def acquire(db, d):
    from .corpus import import_file

    policy = SourcePolicy.model_validate(
        {k: v for k, v in d.value().items() if k in SourcePolicy.model_fields}
    )
    if (
        not policy.enabled
        or not policy.owner_reviewed
        or policy.full_text_policy != "allowed"
    ):
        raise Denied("Source permission review required")
    n, h, p, path, scheme = normalize(policy.source_url)
    scope = Scope(allow=[Rule(host=h, ports=[p], schemes=["https"], methods=["GET"])])
    robots_url = urlunsplit(("https", urlsplit(n).netloc, "/robots.txt", "", ""))
    status, _, robots = request(robots_url, scope=scope, max_bytes=256000, timeout=10)
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    if status == 200:
        parser.parse(robots.decode("utf-8", errors="replace").splitlines())
    elif status == 404:
        parser.parse([])
    else:
        raise Denied("Cannot establish robots policy")
    if not parser.can_fetch("ATLAS", n):
        raise Denied("Source robots policy denies acquisition")
    delay = max(policy.rate_seconds, parser.crawl_delay("ATLAS") or 0)
    if delay > 60:
        raise Denied(
            "Source requires scheduled backoff beyond this bounded request; schedule manually"
        )
    time.sleep(delay)
    status, headers, content = request(
        n, scope=scope, max_bytes=20 * 1024 * 1024, timeout=30
    )
    if status != 200:
        raise Denied("Source returned an unsuccessful response")
    media = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    suffix = Path(path).suffix.lower()
    if suffix not in (
        ".md",
        ".txt",
        ".html",
        ".htm",
        ".json",
        ".jsonl",
        ".csv",
        ".pdf",
        ".docx",
        ".zip",
    ):
        suffix = ".html" if "html" in media else ".txt"
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / ("source" + suffix)
        path.write_bytes(content)
        counts = import_file(
            db, path, policy.license, n, policy.record_type, owner=d.owner
        )
    append(
        db,
        d.owner,
        d.owner,
        "source_acquired",
        {"source_id": d.id, "counts": counts, "content_hash": digest(content)},
    )
    v = d.value()
    v["last_sync"] = now()
    v["last_counts"] = counts
    d.data = canonical(v)
    return counts
