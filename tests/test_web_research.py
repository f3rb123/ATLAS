"""Actual loopback web transport and proof/control checks; model review is synthetic."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from atlas.db import Document, canonical, digest, document
from atlas.policy import Denied, Rule, Scope, nondestructive_target_request
from atlas.target_auth import TargetIdentityInput, create, safe
from atlas.target_transport import TargetRequest
from atlas.web_research import (
    AuthorizationCase,
    CheckInput,
    CrawlInput,
    WebPlan,
    WebRequest,
    check,
    crawl,
    send,
    verify,
)


@pytest.fixture
def web_lab(db):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def answer(self, status, text, headers=None):
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "text/html" if text.startswith("<") else "application/json",
            )
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(text.encode())

        def do_GET(self):
            path = urlsplit(self.path).path
            calls.append((self.command, self.path))
            token = self.headers.get("Authorization", "")
            if path == "/":
                return self.answer(
                    200,
                    '<html><a href="/redirect?next=/">Next</a><a href="/graphql">GraphQL</a><a href="https://excluded.invalid/">Excluded</a></html>',
                )
            if path == "/redirect":
                return self.answer(
                    302,
                    "",
                    {
                        "Location": parse_qs(urlsplit(self.path).query).get(
                            "next", ["/"]
                        )[0]
                    },
                )
            if path == "/token-echo":
                return self.answer(200, json.dumps({"value": token}))
            if "account/" in path:
                resource = path.rsplit("/", 1)[-1]
                if not token:
                    return self.answer(401, '{"error":"unauthenticated"}')
                if (
                    path.startswith("/secure/")
                    and token != "Bearer fixture-owned-" + resource
                ):
                    return self.answer(403, '{"error":"forbidden"}')
                return self.answer(
                    200, json.dumps({"marker": "atlas-owned-resource-" + resource})
                )
            return self.answer(200, '{"message":"lab route"}')

        def do_POST(self):
            calls.append((self.command, self.path))
            query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            return self.answer(
                200,
                json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    scope = Scope(
        allow=[
            Rule(
                host="127.0.0.1",
                ports=[server.server_port],
                schemes=["http"],
                methods=["GET", "HEAD", "OPTIONS", "POST"],
            )
        ],
        lab_networks=["127.0.0.1/32"],
        max_requests=150,
        min_request_interval=0.01,
        test_classes=[
            "surface",
            "headers",
            "redirect",
            "reflection",
            "cors",
            "graphql",
            "authorization",
        ],
        post_paths=["/graphql"],
    ).model_dump()
    campaign = document(
        db,
        "campaign",
        "u",
        {"mode": "lab", "target_url": origin + "/", "authorization_attested": True},
    )
    policy = document(db, "policy", "u", {"scope": scope})
    value = campaign.value()
    value["policy_id"] = policy.id
    campaign.data = canonical(value)
    identities = [
        create(
            db,
            campaign,
            TargetIdentityInput(
                name=name,
                origin=origin,
                headers={"Authorization": "Bearer fixture-owned-" + name},
                owned_test_account=True,
            ),
            "u",
        )
        for name in ("alpha", "beta")
    ]
    case = AuthorizationCase(
        id="owned-pair",
        resource_url=origin + "/api/account/alpha",
        owner_identity_id=identities[0].id,
        other_identity_id=identities[1].id,
        other_resource_url=origin + "/api/account/beta",
        owner_marker="atlas-owned-resource-alpha",
        other_marker="atlas-owned-resource-beta",
        isolated_owned_resources=True,
    )
    run = document(
        db,
        "run",
        "u",
        {
            "campaign_id": campaign.id,
            "policy_id": policy.id,
            "policy_hash": digest(canonical(scope)),
            "status": "running",
            "deadline": time.time() + 120,
            "target_url": origin + "/",
            "target_identities": {i.id: i.version for i in identities},
            "web": WebPlan(
                enabled=True,
                authorization_cases=[case],
                identity_ids=[i.id for i in identities],
            ).model_dump(),
            "max_tool_calls": 50,
        },
    )
    db.commit()
    yield SimpleNamespace(
        origin=origin,
        run=run,
        identities=identities,
        case=case,
        calls=calls,
        campaign=campaign,
    )
    server.shutdown()
    server.server_close()


def test_real_crawl_follows_scoped_links_and_rejects_external(db, web_lab):
    result = crawl(db, web_lab.run, CrawlInput(max_pages=5))
    assert result["visited"] == 3
    assert any(item["reason"] == "Out of scope" for item in result["skipped"])
    assert all(
        urlsplit(page["url"]).hostname == "127.0.0.1" for page in result["pages"]
    )
    assert db.query(Document).filter_by(kind="http_observation").count() == 3


def test_owned_account_authorization_candidate_and_fresh_replay(
    db, web_lab, monkeypatch
):
    from atlas.workflow import VerificationOutput

    args = CheckInput(
        kind="authorization", url=web_lab.case.resource_url, case_id=web_lab.case.id
    )
    research = check(db, web_lab.run, args)
    assert (
        research["candidate"]
        and len(research["proof_ids"]) == 2
        and len(research["control_ids"]) == 2
    )

    def review(_db, _run, _stage, context, *_, **__):
        assert not set(context["expected_evidence_ids"]) & set(
            research["proof_ids"] + research["control_ids"]
        )
        return VerificationOutput(
            status="confirmed",
            reason="Synthetic reviewer of actual HTTP evidence",
            counterfactual="Anonymous is rejected; the second account accesses its own distinct resource",
            evidence_ids=context["expected_evidence_ids"],
        )

    monkeypatch.setattr("atlas.workflow.role", review)
    result = verify(
        db,
        web_lab.run,
        SimpleNamespace(payload=canonical({"candidate_id": research["candidate_id"]})),
    )
    finding = db.get(Document, result["finding_id"]).value()
    assert finding["status"] == "confirmed" and len(finding["evidence_ids"]) == 4
    assert len(web_lab.calls) == 8


def test_secure_account_control_refutes_candidate(db, web_lab):
    value = web_lab.run.value()
    case = value["web"]["authorization_cases"][0]
    case["resource_url"] = web_lab.origin + "/secure/account/alpha"
    case["other_resource_url"] = web_lab.origin + "/secure/account/beta"
    web_lab.run.data = canonical(value)
    db.commit()
    result = check(
        db,
        web_lab.run,
        CheckInput(kind="authorization", url=case["resource_url"], case_id=case["id"]),
    )
    assert not result["candidate"] and "candidate_id" not in result


def test_redirect_proof_uses_reserved_domain_without_following(db, web_lab):
    result = check(
        db,
        web_lab.run,
        CheckInput(
            kind="redirect", url=web_lab.origin + "/redirect?next=/", parameter="next"
        ),
    )
    assert result["candidate"] and len(web_lab.calls) == 2
    assert ".invalid" in web_lab.calls[0][1] and all(
        path.startswith("/redirect") for _, path in web_lab.calls
    )


def test_graphql_read_query_and_destructive_operations_blocked(db, web_lab):
    result = check(
        db, web_lab.run, CheckInput(kind="graphql", url=web_lab.origin + "/graphql")
    )
    assert not result["candidate"] and result["proof_ids"]
    assert "introspection alone is not a vulnerability" in result["notes"][0]
    before = len(web_lab.calls)
    with pytest.raises(Denied):
        send(
            db,
            web_lab.run,
            WebRequest(
                url=web_lab.origin + "/graphql",
                method="POST",
                body=json.dumps({"query": "mutation { removeAccount }"}),
                purpose="graphql_read",
            ),
        )
    with pytest.raises(Denied):
        send(db, web_lab.run, WebRequest(url=web_lab.origin + "/api/drop-table"))
    assert len(web_lab.calls) == before


def test_credential_binding_hidden_in_api_and_evidence(db, web_lab):
    identity = web_lab.identities[0]
    assert (
        "fixture-owned-alpha" not in canonical(safe(identity))
        and "fixture-owned-alpha" not in identity.data
    )
    result = send(
        db,
        web_lab.run,
        WebRequest(url=web_lab.origin + "/token-echo", identity_id=identity.id),
    )
    assert "fixture-owned-alpha" not in canonical(result)
    assert "[REDACTED TARGET CREDENTIAL]" in result["body"]
    assert "fixture-owned-alpha" not in "".join(
        row.data for row in db.query(Document).filter_by(kind="http_observation")
    )


def test_disabled_or_unpinned_identity_never_dispatches(db, web_lab):
    identity = web_lab.identities[0]
    value = identity.value()
    value["enabled"] = False
    identity.data = canonical(value)
    db.commit()
    with pytest.raises(Denied):
        send(
            db,
            web_lab.run,
            WebRequest(
                url=web_lab.origin + "/api/account/alpha", identity_id=identity.id
            ),
        )
    assert not web_lab.calls


def test_pause_and_kill_prevent_target_requests(db, web_lab):
    value = web_lab.run.value()
    value["status"] = "paused"
    web_lab.run.data = canonical(value)
    db.commit()
    with pytest.raises(Denied):
        send(db, web_lab.run, WebRequest(url=web_lab.origin + "/"))
    assert not web_lab.calls


def test_foreign_review_evidence_cannot_confirm_web_finding(db, web_lab, monkeypatch):
    from atlas.workflow import VerificationOutput

    research = check(
        db,
        web_lab.run,
        CheckInput(
            kind="redirect", url=web_lab.origin + "/redirect?next=/", parameter="next"
        ),
    )
    monkeypatch.setattr(
        "atlas.workflow.role",
        lambda *a, **k: VerificationOutput(
            status="confirmed",
            reason="Synthetic incorrect reviewer",
            counterfactual="control",
            evidence_ids=research["proof_ids"],
        ),
    )
    result = verify(
        db,
        web_lab.run,
        SimpleNamespace(payload=canonical({"candidate_id": research["candidate_id"]})),
    )
    assert db.get(Document, result["finding_id"]).value()["status"] == "inconclusive"
