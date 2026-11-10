"""Autonomous web discovery and typed, non-destructive differential checks.

Every network operation is relayed. Scanner observations are never findings;
only fresh independent replay and an evidence-bound reviewer can promote one.
"""

import json
import re
import secrets
from collections import deque
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from pydantic import Field

from .config import settings
from .db import Document, append, canonical, digest, document, now
from .policy import Denied, Scope, Strict, authorize, normalize
from .target_transport import TargetRequest


class AuthorizationCase(Strict):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    resource_url: str = Field(max_length=4096)
    owner_identity_id: str
    other_identity_id: str
    other_resource_url: str = Field(max_length=4096)
    owner_marker: str = Field(min_length=8, max_length=200)
    other_marker: str = Field(min_length=8, max_length=200)
    isolated_owned_resources: bool


class WebPlan(Strict):
    enabled: bool = False
    scanner_tools: list[
        Literal[
            "httpx",
            "katana",
            "ffuf",
            "nuclei",
            "subfinder",
            "dnsx",
            "naabu",
            "gau",
            "waybackurls",
        ]
    ] = Field(
        default=["httpx", "katana", "nuclei", "subfinder", "dnsx", "gau"], max_length=9
    )
    max_pages: int = Field(default=12, ge=1, le=100)
    max_depth: int = Field(default=3, ge=0, le=6)
    max_checks: int = Field(default=12, ge=1, le=100)
    check_classes: list[
        Literal["headers", "redirect", "cors", "reflection", "graphql", "authorization"]
    ] = Field(
        default=[
            "headers",
            "redirect",
            "cors",
            "reflection",
            "graphql",
            "authorization",
        ],
        max_length=6,
    )
    seed_urls: list[str] = Field(default=[], max_length=50)
    identity_ids: list[str] = Field(default=[], max_length=10)
    authorization_cases: list[AuthorizationCase] = Field(default=[], max_length=10)


class WebRequest(Strict):
    url: str = Field(max_length=4096)
    method: Literal["GET", "HEAD", "OPTIONS", "POST"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict, max_length=6)
    body: str | None = Field(default=None, max_length=16384)
    identity_id: str | None = None
    purpose: Literal[
        "navigation", "probe", "graphql_read", "authentication", "read_json"
    ] = "navigation"


class CrawlInput(Strict):
    url: str | None = Field(default=None, max_length=4096)
    max_pages: int = Field(default=8, ge=1, le=100)
    max_depth: int = Field(default=2, ge=0, le=6)
    identity_id: str | None = None


class CheckInput(Strict):
    kind: Literal[
        "headers", "redirect", "cors", "reflection", "graphql", "authorization"
    ]
    url: str = Field(max_length=4096)
    parameter: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.-]{1,80}$")
    identity_id: str | None = None
    case_id: str | None = None


CAPABILITIES = {
    "web.request": WebRequest,
    "web.crawl": CrawlInput,
    "web.check": CheckInput,
}


def scope_for(db, run):
    value = run.value()
    row = db.get(Document, value["policy_id"])
    if (
        not row
        or row.owner != run.owner
        or digest(canonical(row.value()["scope"])) != value["policy_hash"]
    ):
        raise Denied("Frozen web scope integrity failure")
    return Scope.model_validate(row.value()["scope"])


def send(db, run, args, actor="web-research", request_deadline=None):
    from .swarm import check_fence

    check_fence(db, run)
    claim = getattr(run, "_swarm_claim", (None, None))
    body = TargetRequest(
        run_id=run.id,
        task_id=claim[0],
        lease_token=claim[1],
        request_deadline=request_deadline,
        **args.model_dump(),
    )
    # Commit before calling the relay: it independently reserves a rate slot and
    # checks current run state. Never hold a worker row lock across network I/O.
    db.commit()
    if settings().relay_url:
        import httpx
        from pathlib import Path

        if not settings().service_token_file:
            raise Denied("Relay service credential missing")
        with httpx.Client(timeout=60, trust_env=False) as client:
            response = client.post(
                settings().relay_url + "/request",
                headers={
                    "Authorization": "Bearer "
                    + Path(settings().service_token_file).read_text().strip()
                },
                json=body.model_dump(),
            )
        if response.status_code != 200:
            raise Denied("Scoped relay denied or failed the request")
        result = response.json()
    else:
        if settings().production:
            raise Denied("Production web research requires the target relay")
        from .relay import execute

        result = execute(body, actor)
    db.expire_all()
    check_fence(db, run)
    return result


def page_links(url, text, content_type):
    links = []
    forms = []
    technologies = []
    if "html" in content_type or "<html" in text[:500].lower():
        soup = BeautifulSoup(text, "html.parser")
        for item in soup.find_all(["a", "script", "link", "form"], limit=1000):
            path = item.get("href") or item.get("src") or item.get("action")
            if path and not path.startswith(("javascript:", "data:", "mailto:", "#")):
                links.append(urljoin(url, path))
            if item.name == "form":
                forms.append(
                    {
                        "action": urljoin(url, item.get("action") or url),
                        "method": item.get("method", "GET").upper(),
                        "fields": [
                            i.get("name")
                            for i in item.find_all("input", limit=50)
                            if i.get("name")
                        ],
                    }
                )
        for name, pattern in [
            ("graphql", r"graphql"),
            ("oauth", r"oauth|openid"),
            ("javascript", r"<script"),
            ("api", r"/api/"),
        ]:
            if re.search(pattern, text, re.I):
                technologies.append(name)
    if "json" in content_type:
        try:
            value = json.loads(text)
            if isinstance(value, dict) and ("openapi" in value or "swagger" in value):
                technologies.append("api")
                links.extend(
                    urljoin(url, p)
                    for p in list(value.get("paths", {}))[:100]
                    if isinstance(p, str) and "{" not in p
                )
        except ValueError:
            pass
    # Static JS/JSON route references are candidates; never evaluate scripts.
    if any(t in content_type for t in ["javascript", "json"]):
        links.extend(
            urljoin(url, p)
            for p in re.findall(
                r"""["'](/(?:api|graphql|oauth|auth)/[^"'\s<>]{0,200})["']""", text
            )[:100]
        )
    return list(dict.fromkeys(links))[:200], forms, technologies


def crawl(db, run, args):
    plan = WebPlan.model_validate(run.value().get("web", {}))
    scope = scope_for(db, run)
    start = args.url or run.value().get("target_url")
    if not start:
        raise Denied("Web discovery needs an exact target URL")
    queue = deque([(start, 0), *((url, 0) for url in plan.seed_urls)])
    seen = set()
    pages = []
    skipped = []
    max_pages = min(args.max_pages, plan.max_pages)
    max_depth = min(args.max_depth, plan.max_depth)
    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        try:
            normalized = normalize(url)[0]
            if normalized in seen:
                continue
            seen.add(normalized)
            authorize(scope, normalized, "GET")
            if re.search(
                r"(?i)\.(?:zip|exe|pdf|png|jpg|woff2?|mp4)(?:\?|$)", normalized
            ):
                continue
            result = send(
                db, run, WebRequest(url=normalized, identity_id=args.identity_id)
            )
        except Denied as exc:
            if len(skipped) < 30:
                skipped.append({"url_hash": digest(url), "reason": str(exc)[:120]})
            # Scope/deadline/kill checks run again for every subsequent request.
            continue
        links, forms, technologies = page_links(
            normalized, result["body"], result["headers"].get("content-type", "")
        )
        pages.append(
            {
                "url": normalized,
                "status": result["status"],
                "observation_id": result["observation_id"],
                "headers": result["headers"],
                "forms": forms,
                "technologies": technologies,
                "links": links[:50],
            }
        )
        if depth < max_depth:
            for link in links:
                if len(queue) < 500:
                    queue.append((link, depth + 1))
            location = result["headers"].get("location")
            if location:
                queue.append((urljoin(normalized, location), depth + 1))
    return {
        "pages": pages,
        "skipped": skipped,
        "visited": len(pages),
        "remaining_frontier": len(queue),
        "bounded": True,
    }


def changed_query(url, parameter, value):
    parsed = urlsplit(url)
    items = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k != parameter
    ]
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(items + [(parameter, value)]),
            "",
        )
    )


def check(db, run, args, record=True):
    scope = scope_for(db, run)
    if args.kind not in scope.test_classes:
        raise Denied("Check class is outside the frozen campaign policy")
    if run.value().get("assessment_profile") == "smoke_readonly":
        raise Denied("Active checks are unavailable in smoke acceptance")
    proof = []
    control = []
    candidate = False
    notes = []

    def get(url, identity_id=args.identity_id, headers=None):
        return send(
            db,
            run,
            WebRequest(
                url=url, identity_id=identity_id, headers=headers or {}, purpose="probe"
            ),
        )

    if args.kind == "headers":
        p = get(args.url)
        proof = [p]
        notes = [
            f"Missing {name}; contextual review required"
            for name in [
                "content-security-policy",
                "x-content-type-options",
                "strict-transport-security",
            ]
            if name not in p["headers"]
        ]
    elif args.kind == "redirect":
        if not args.parameter:
            raise Denied("Redirect check needs an observed query parameter")
        destination = "https://atlas-" + secrets.token_hex(8) + ".invalid/"
        p = get(changed_query(args.url, args.parameter, destination))
        c = get(changed_query(args.url, args.parameter, "/"))
        proof = [p]
        control = [c]
        candidate = (
            300 <= p["status"] < 400
            and p["headers"].get("location") == destination
            and (
                not c["headers"].get("location")
                or urlsplit(urljoin(args.url, c["headers"]["location"])).netloc
                == urlsplit(args.url).netloc
            )
        )
        notes = [
            "An external redirect is reported only as an unrestricted redirect, never as account takeover."
        ]
    elif args.kind == "reflection":
        if not args.parameter:
            raise Denied("Reflection check needs an observed query parameter")
        marker = "atlas" + secrets.token_hex(8) + '<>"'
        p = get(changed_query(args.url, args.parameter, marker))
        proof = [p]
        notes = (
            ["Unescaped reflection detected; browser execution is unverified"]
            if marker in p["body"]
            else ["No raw marker reflection"]
        )
    elif args.kind == "cors":
        origin = "https://atlas-" + secrets.token_hex(8) + ".invalid"
        p = get(args.url, headers={"Origin": origin})
        c = get(args.url, identity_id=None)
        proof = [p]
        control = [c]
        # Configuration alone does not prove browser-readable authenticated data.
        notes = (
            [
                "Arbitrary origin with credentials; browser/cookie prerequisites need proof"
            ]
            if p["headers"].get("access-control-allow-origin") == origin
            and p["headers"].get("access-control-allow-credentials", "").lower()
            == "true"
            else ["No credentialed arbitrary-origin policy observed"]
        )
    elif args.kind == "graphql":
        p = send(
            db,
            run,
            WebRequest(
                url=args.url,
                method="POST",
                body=canonical(
                    {"query": "query AtlasSchema { __schema { queryType { name } } }"}
                ),
                headers={"Content-Type": "application/json"},
                identity_id=args.identity_id,
                purpose="graphql_read",
            ),
        )
        proof = [p]
        notes = (
            [
                "Read-only GraphQL schema response observed; introspection alone is not a vulnerability"
            ]
            if "__schema" in p["body"]
            else ["No schema disclosure observed"]
        )
    elif args.kind == "authorization":
        cases = WebPlan.model_validate(run.value().get("web", {})).authorization_cases
        case = next((c for c in cases if c.id == args.case_id), None)
        if (
            not case
            or not case.isolated_owned_resources
            or case.owner_identity_id == case.other_identity_id
            or case.owner_marker == case.other_marker
        ):
            raise Denied(
                "Authorization testing requires a frozen pair of distinct owned test accounts/resources"
            )
        if args.url != case.resource_url:
            raise Denied("Authorization check must use the frozen owned resource")
        owner = get(case.resource_url, case.owner_identity_id)
        other = get(case.resource_url, case.other_identity_id)
        own_control = get(case.other_resource_url, case.other_identity_id)
        anonymous = get(case.resource_url, None)
        proof = [owner, other]
        control = [own_control, anonymous]
        candidate = (
            all(p["status"] == 200 for p in [owner, other, own_control])
            and anonymous["status"] in (401, 403, 404)
            and case.owner_marker in owner["body"]
            and case.owner_marker in other["body"]
            and case.other_marker in own_control["body"]
            and case.owner_marker not in own_control["body"]
            and case.owner_marker not in anonymous["body"]
        )
        notes = ["Only explicitly attested isolated test resources were compared."]
    result = {
        "kind": args.kind,
        "url": args.url,
        "candidate": candidate,
        "notes": notes,
        "proof_ids": [p["observation_id"] for p in proof],
        "control_ids": [c["observation_id"] for c in control],
        "responses": [
            {
                "id": p["observation_id"],
                "status": p["status"],
                "body_sha256": p["body_sha256"],
            }
            for p in proof + control
        ],
    }
    if candidate and record:
        from .swarm import enqueue

        key = digest("web-candidate:" + run.id + canonical(args.model_dump()))[:36]
        row = db.get(Document, key)
        if not row:
            row = document(
                db,
                "web_candidate",
                run.owner,
                {
                    "run_id": run.id,
                    "campaign_id": run.value()["campaign_id"],
                    "check": args.model_dump(),
                    "research_result": result,
                    "status": "candidate",
                    "created_at": now(),
                },
                key,
            )
            enqueue(
                db,
                run,
                "web-verification",
                {
                    "candidate_id": row.id,
                    "reason": "Independent fresh web proof/control replay",
                },
                digest("web-verify:" + row.id),
            )
            from .swarm import Discovery, publish_current

            publish_current(
                db,
                run,
                Discovery(
                    kind="hypothesis",
                    topic="idor" if args.kind == "authorization" else "general",
                    title="Observed " + args.kind + " differential",
                    text=(
                        "Candidate behavior at "
                        + args.url
                        + "; independent confirmation is pending"
                    )[:2000],
                    citations=result["proof_ids"] + result["control_ids"],
                    confidence=0.8,
                ),
            )
        result["candidate_id"] = row.id
    return result


def execute(db, run, name, args):
    if name == "web.request":
        scope = scope_for(db, run)
        if args.purpose != "navigation" and "surface" not in scope.test_classes:
            raise Denied("Web probes require authorized surface checks")
        return send(db, run, args)
    if name == "web.crawl":
        return crawl(db, run, args)
    if name == "web.check":
        return check(db, run, args)
    raise Denied("Unknown web capability")


def discover(db, run, task):
    from .tools import broker
    from .swarm import Discovery, publish

    plan = WebPlan.model_validate(run.value().get("web", {}))
    target = run.value()["target_url"]
    # Spend bounded discovery capacity before paid reasoning. No agent/model
    # can enable profiles that were absent from the frozen run configuration.
    if run.value().get("assessment_profile") == "smoke_readonly":
        return broker(
            db, run, None, "web.request", {"url": target, "method": "HEAD"}, task.role
        )
    result = broker(
        db,
        run,
        None,
        "web.crawl",
        {
            "url": target,
            "max_pages": plan.max_pages,
            "max_depth": plan.max_depth,
            "identity_id": plan.identity_ids[0] if plan.identity_ids else None,
        },
        task.role,
    )
    pages = result["result"]["pages"]
    if not pages:
        raise Denied(
            "No authorized target response was collected; web discovery did not succeed"
        )
    checks = []
    scope = scope_for(db, run)
    for page in pages:
        for topic in page["technologies"] or ["general"]:
            publish(
                db,
                run,
                task,
                Discovery(
                    kind="endpoint",
                    topic=topic
                    if topic in ["graphql", "oauth", "javascript", "api"]
                    else "general",
                    title="Observed web endpoint",
                    text=page["url"],
                    citations=[page["observation_id"]],
                    confidence=1,
                ),
            )
        for parameter, _ in parse_qsl(
            urlsplit(page["url"]).query, keep_blank_values=True
        ):
            kind = (
                "redirect"
                if parameter.lower()
                in (
                    "url",
                    "next",
                    "redirect",
                    "redirect_uri",
                    "return",
                    "returnto",
                    "continue",
                )
                else "reflection"
            )
            if kind in scope.test_classes and kind in plan.check_classes:
                checks.append(
                    CheckInput(kind=kind, url=page["url"], parameter=parameter)
                )
        if (
            "graphql" in page["url"]
            and "graphql" in scope.test_classes
            and "graphql" in plan.check_classes
            and urlsplit(page["url"]).path in scope.post_paths
        ):
            checks.append(CheckInput(kind="graphql", url=page["url"]))
    for case in plan.authorization_cases:
        if (
            "authorization" in scope.test_classes
            and "authorization" in plan.check_classes
        ):
            checks.insert(
                0,
                CheckInput(
                    kind="authorization", url=case.resource_url, case_id=case.id
                ),
            )
    if pages and "headers" in scope.test_classes and "headers" in plan.check_classes:
        checks.append(CheckInput(kind="headers", url=pages[0]["url"]))
    if pages and "cors" in scope.test_classes and "cors" in plan.check_classes:
        checks.append(
            CheckInput(
                kind="cors",
                url=pages[0]["url"],
                identity_id=plan.identity_ids[0] if plan.identity_ids else None,
            )
        )
    outcomes = []
    frontier = []
    if any(
        name in scope.test_classes
        for name in ("scanners", "dns", "ports", "passive_sources")
    ):
        for name in plan.scanner_tools:
            if name in run.value().get("tool_pins", {}):
                try:
                    tool_result = broker(
                        db,
                        run,
                        None,
                        "scanner.run",
                        {
                            "tool": name,
                            "url": target,
                            "max_requests": min(15, scope.max_requests),
                            "timeout_seconds": 25,
                        },
                        task.role,
                    )
                    outcomes.append(tool_result)
                    content = tool_result["result"]
                    frontier.extend(content.get("discovered_urls", []))
                    from .policy import match

                    for hostname in content.get("discovered_hosts", []):
                        for rule in scope.allow:
                            scheme = rule.schemes[0]
                            port = rule.ports[0]
                            path = rule.paths[0]
                            if match(rule, hostname, port, path, scheme, "GET"):
                                frontier.append(f"{scheme}://{hostname}:{port}{path}")
                                break
                except Denied as exc:
                    outcomes.append(
                        {"tool": name, "status": "blocked", "reason": str(exc)[:150]}
                    )
    seen = {page["url"] for page in pages}
    for url in dict.fromkeys(frontier):
        if len(pages) >= plan.max_pages:
            break
        if url in seen:
            continue
        seen.add(url)
        try:
            extra = broker(
                db,
                run,
                None,
                "web.crawl",
                {
                    "url": url,
                    "max_pages": min(3, plan.max_pages - len(pages)),
                    "max_depth": 1,
                },
                task.role,
            )
            for page in extra["result"]["pages"]:
                if page["url"] not in {p["url"] for p in pages}:
                    pages.append(page)
                    publish(
                        db,
                        run,
                        task,
                        Discovery(
                            kind="endpoint",
                            topic="api" if "/api" in page["url"] else "general",
                            title="Tool-discovered scoped endpoint",
                            text=page["url"],
                            citations=[page["observation_id"]],
                            confidence=1,
                        ),
                    )
        except Denied as exc:
            outcomes.append(
                {"url_hash": digest(url), "status": "blocked", "reason": str(exc)[:150]}
            )
    for item in checks[: plan.max_checks]:
        try:
            outcomes.append(
                broker(db, run, None, "web.check", item.model_dump(), task.role)
            )
        except Denied as exc:
            outcomes.append(
                {"kind": item.kind, "status": "blocked", "reason": str(exc)[:150]}
            )
    return {
        "surface_artifact": result["artifact_id"],
        "pages": len(pages),
        "checks": outcomes,
    }


def verify(db, run, task):
    from .workflow import role, VerificationOutput
    from .tools import broker

    candidate = db.get(Document, json.loads(task.payload)["candidate_id"])
    if (
        not candidate
        or candidate.kind != "web_candidate"
        or candidate.owner != run.owner
        or candidate.value()["run_id"] != run.id
    ):
        raise Denied("Invalid web candidate provenance")
    specification = candidate.value()["check"]
    if specification["kind"] == "differential":
        from .web_experiments import HTTPExperiment, execute as execute_experiment

        experiment = HTTPExperiment.model_validate(specification["input"])
        fresh = execute_experiment(db, run, experiment, record=False)
        metadata = {
            "kind": experiment.vulnerability_class,
            "url": experiment.proof[0].request.url,
            "parameter": None,
            "case_id": None,
            "title": experiment.claim,
            "impact": experiment.impact,
            "capability": "web.experiment",
            "input": experiment.model_dump(),
        }
    else:
        args = CheckInput.model_validate(specification)
        fresh = check(db, run, args, record=False)
        metadata = {
            "kind": args.kind,
            "url": args.url,
            "parameter": args.parameter,
            "case_id": args.case_id,
            "title": {
                "authorization": "Cross-account access to an isolated owned resource",
                "redirect": "Unrestricted external redirect",
            }.get(args.kind, args.kind),
            "impact": "Unauthorized test-account resource access"
            if args.kind == "authorization"
            else "Navigation can be redirected to an arbitrary external origin",
            "capability": "web.check",
            "input": args.model_dump(),
        }
    evidence = fresh["proof_ids"] + fresh["control_ids"]
    if not fresh["candidate"] or not fresh["proof_ids"] or not fresh["control_ids"]:
        value = candidate.value()
        value.update(status="refuted", independent_result=fresh)
        candidate.data = canonical(value)
        return {"status": "refuted", "candidate_id": candidate.id}
    review = role(
        db,
        run,
        "INDEPENDENT_WEB_VERIFICATION",
        {
            "claim": metadata,
            "research": candidate.value()["research_result"],
            "fresh_independent_evidence": fresh,
            "expected_evidence_ids": evidence,
            "fresh_observations": [
                {
                    **row.value(),
                    "response": {
                        **row.value()["response"],
                        "body": row.value()["response"].get("body", "")[:2000],
                        "headers": {
                            k: v[:256]
                            for k, v in list(
                                row.value()["response"].get("headers", {}).items()
                            )[:12]
                        },
                    },
                }
                for id in evidence
                if (row := db.get(Document, id))
                and row.owner == run.owner
                and row.value().get("run_id") == run.id
            ],
            "instruction": "Return confirmed only when the fresh paired observations demonstrate this precise claim. Copy every expected_evidence_id exactly. Assess secure controls and alternatives. Do not infer other impacts.",
        },
        "verifier",
        response_schema=VerificationOutput,
    )
    status = review.status
    if status == "confirmed" and (
        set(review.evidence_ids) != set(evidence) or not review.counterfactual
    ):
        status = "inconclusive"
    review_row = document(
        db,
        "verification_review",
        run.owner,
        {
            "run_id": run.id,
            "candidate_id": candidate.id,
            "model_review": review.model_dump(),
            "expected_evidence_ids": evidence,
            "effective_status": status,
            "finding_confirmed": status == "confirmed",
        },
    )
    key = digest(
        canonical(
            {
                "campaign": run.value()["campaign_id"],
                "class": metadata["kind"],
                "url": metadata["url"],
                "parameter": metadata["parameter"],
                "case": metadata["case_id"],
            }
        )
    )
    from .finding_reviews import matching_findings, record_duplicate

    prior = matching_findings(db, run, key)
    existing = next((f for f in prior if f.value().get("status") == "confirmed"), None)
    if status == "confirmed" and existing:
        return record_duplicate(
            db, run, existing, candidate, fresh, review_row, "independent-web-verifier"
        )
    title = metadata["title"]
    finding = document(
        db,
        "finding",
        run.owner,
        {
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "title": title,
            "status": status,
            "severity": "unscored",
            "vulnerability_class": metadata["kind"],
            "asset": urlsplit(metadata["url"]).hostname,
            "endpoint": metadata["url"],
            "parameter_or_component": metadata["parameter"],
            "confidence": None,
            "technical_explanation": review.reason,
            "impact": metadata["impact"],
            "reproduction_steps": {
                "capability": metadata["capability"],
                "input": metadata["input"],
                "owned_test_resources_only": True,
            },
            "discovery_agent": "web-research",
            "validation_agent": "independent-web-verifier",
            "source_references": candidate.value()["research_result"]["proof_ids"],
            "related_findings": [f.id for f in prior],
            "independent_review_ids": [review_row.id],
            "timeline": [
                {"at": now(), "actor": "independent-web-verifier", "status": status}
            ],
            "hypothesis": {
                "claim": title,
                "impact": "Scope limited to the observed differential behavior",
                "preconditions": [
                    "Authorized test context and supplied account/resource bindings"
                ],
                "citations": evidence,
                "check": metadata["input"],
            },
            "verification": {**review.model_dump(), "status": status},
            "evidence_ids": evidence,
            "root_cause_key": key,
            "policy_hash": run.value()["policy_hash"],
        },
    )
    value = candidate.value()
    value.update(
        status=status,
        finding_id=finding.id,
        independent_result=fresh,
        review_id=review_row.id,
    )
    candidate.data = canonical(value)
    append(
        db,
        run.id,
        "independent-web-verifier",
        "web_finding_reviewed",
        {"candidate_id": candidate.id, "finding_id": finding.id, "status": status},
        run.value()["campaign_id"],
    )
    from .swarm import Discovery, publish_current

    publish_current(
        db,
        run,
        Discovery(
            kind="observation",
            topic="general",
            title="Independent review: " + status,
            text=(title + "; finding " + finding.id)[:2000],
            citations=evidence,
            confidence=1,
        ),
    )
    return {"status": status, "finding_id": finding.id, "candidate_id": candidate.id}
