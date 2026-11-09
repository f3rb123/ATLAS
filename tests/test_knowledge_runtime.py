"""Synthetic local corpus/model fixtures; no historical-corpus or live-provider claims."""

import json
import time

import pytest

from atlas.corpus import import_file
from atlas.db import Document, Journal, Knowledge, canonical, document, session
from atlas.gateway import ADAPTERS, Adapter, ModelResponse
from atlas.knowledge import GLOBAL_POLICY, POLICY_VERSION, availability
from atlas.policy import Denied
from atlas.skills import install_references
from atlas.tools import broker
from atlas.workflow import role


def make_run(db, owner="owner", campaign="campaign"):
    run = document(
        db,
        "run",
        owner,
        {
            "campaign_id": campaign,
            "status": "running",
            "deadline": time.time() + 300,
            "max_tool_calls": 50,
            "tool_calls": 0,
        },
    )
    db.commit()
    return run


def seed(db, tmp_path, owner="public"):
    p = tmp_path / (owner + ".md")
    p.write_text(
        "# OAuth authorization research\nOAuth redirect URI and state validation protect tenant isolation. Synthetic research fixture."
    )
    import_file(db, p, "MIT", "atlas:test-fixture", "research_report", owner=owner)
    db.commit()
    return db.query(Knowledge).filter_by(owner=owner).one()


@pytest.mark.parametrize("protocol", ADAPTERS)
@pytest.mark.parametrize("alias", ["reasoning", "coding", "fast", "verifier"])
def test_every_role_protocol_inherits_policy_tools_and_task_retrieval(
    db, tmp_path, monkeypatch, protocol, alias
):
    k = seed(db, tmp_path)
    run = make_run(db)
    p = document(db, "provider", run.owner, {"adapter_type": protocol})
    m = document(
        db,
        "provider_model",
        run.owner,
        {"model_id": "fixture", "max_output_tokens": 1024},
    )
    monkeypatch.setattr("atlas.workflow.model_binding", lambda *_: (p, m))
    captured = []

    def generate(db, p, m, req, run, alias):
        serialized = Adapter(p).serialize(req)
        assert GLOBAL_POLICY in req.messages[0]["content"]
        assert "persistent, model-independent security knowledge base" in canonical(
            serialized
        )
        context = json.loads(req.messages[1]["content"])["context"]["knowledge"]
        assert context["policy_version"] == POLICY_VERSION
        assert "knowledge.search_skills" in context["capabilities"]
        assert context["availability"]["retrieval_mode"] == "lexical_hash_test"
        assert context["task_research"]["results"][0]["record_id"] == k.id
        assert context["task_research"]["results"][0]["source_url"]
        assert len(context["task_research"]["results"]) <= 3
        captured.append(req)
        payload = (
            {
                "status": "inconclusive",
                "reason": "Synthetic fixture",
                "counterfactual": "No current-target evidence",
            }
            if alias == "verifier"
            else {"summary": "Synthetic research observation"}
        )
        return ModelResponse(content=canonical(payload), structured_content=payload)

    monkeypatch.setattr("atlas.workflow.generate_budgeted", generate)
    result = role(
        db, run, "OAUTH_RESEARCH", {"question": "OAuth redirect and state"}, alias
    )
    assert captured and result
    db.commit()
    events = [json.loads(j.payload) for j in db.query(Journal).filter_by(stream=run.id)]
    assert any(e["type"] == "knowledge_search" for e in events)


def test_model_requested_lookup_results_reach_next_reasoning_round(
    db, tmp_path, monkeypatch
):
    k = seed(db, tmp_path)
    run = make_run(db)
    p = document(db, "provider", run.owner, {"adapter_type": "openai_chat_completions"})
    m = document(
        db,
        "provider_model",
        run.owner,
        {"model_id": "fixture", "max_output_tokens": 1024},
    )
    monkeypatch.setattr("atlas.workflow.model_binding", lambda *_: (p, m))
    calls = []

    def generate(db, p, m, req, run, alias):
        calls.append(req)
        if len(calls) == 1:
            payload = {
                "summary": "Need a specific source",
                "tool_requests": [
                    {"name": "knowledge.get_source", "input": {"record_id": k.id}}
                ],
            }
        else:
            context = json.loads(req.messages[1]["content"])["context"]
            source = context["knowledge_tool_results"][0]["result"]
            assert source["record_id"] == k.id and source["source"]["license"] == "MIT"
            payload = {
                "summary": "Cited research, not a confirmed vulnerability",
                "citations": [k.id],
            }
        return ModelResponse(content=canonical(payload), structured_content=payload)

    monkeypatch.setattr("atlas.workflow.generate_budgeted", generate)
    output = role(db, run, "OAUTH_RESEARCH", {"question": "OAuth"})
    assert len(calls) == 2 and output.citations == [k.id] and not output.tool_requests


def test_owner_isolation_report_filter_feedback_and_restart(db, tmp_path):
    private = seed(db, tmp_path, "other-owner")
    public = seed(db, tmp_path)
    run = make_run(db)
    hits = broker(
        db, run, None, "knowledge.search_reports", {"query": "OAuth"}, "research"
    )["result"]
    assert [h["record_id"] for h in hits["results"]] == [public.id]
    for name in (
        "knowledge.retrieve",
        "knowledge.get_source",
        "knowledge.submit_feedback",
    ):
        args = {"record_id": private.id}
        if name.endswith("feedback"):
            args["rating"] = "relevant"
        with pytest.raises(Denied):
            broker(db, run, None, name, args, "research")
    feedback = broker(
        db,
        run,
        None,
        "knowledge.submit_feedback",
        {"record_id": public.id, "rating": "relevant"},
        "research",
    )["result"]
    assert not feedback["promoted"]
    assert (
        db.get(Document, feedback["feedback_id"]).value()["status"] == "pending_review"
    )
    original_hash = public.content_hash
    second = make_run(db, campaign="different-engagement")
    with session() as restarted:
        restored = restarted.get(Document, second.id)
        result = broker(
            restarted,
            restored,
            None,
            "knowledge.search",
            {"query": "OAuth"},
            "new-worker",
        )["result"]
        assert result["results"][0]["hash"] == original_hash
        assert restarted.get(Knowledge, public.id).content_hash == original_hash


def test_missing_and_failed_retrieval_are_explicit_without_stopping_run(
    db, tmp_path, monkeypatch
):
    run = make_run(db)
    assert availability(db, run.owner)["status"] == "empty"
    assert (
        broker(db, run, None, "knowledge.search", {"query": "OAuth"}, "research")[
            "result"
        ]["status"]
        == "empty"
    )
    seed(db, tmp_path)
    monkeypatch.setattr(
        "atlas.corpus.search",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("index unavailable")),
    )
    result = broker(db, run, None, "knowledge.search", {"query": "OAuth"}, "research")[
        "result"
    ]
    assert result["status"] == "unavailable" and result["results"] == []
    assert run.value()["status"] == "running"


def test_references_install_idempotently_and_are_selectively_discoverable(db):
    first = install_references(db, "owner")
    assert install_references(db, "owner") == first and len(first) == 2
    db.commit()
    run = make_run(db)
    found = broker(
        db, run, None, "knowledge.search_skills", {"query": "reporting"}, "specialist"
    )["result"]["results"]
    assert len(found) == 1 and found[0]["reference_only"]
    content = broker(
        db,
        run,
        None,
        "knowledge.retrieve_skill",
        {"record_id": found[0]["record_id"]},
        "specialist",
    )["result"]
    assert (
        content["content"]
        and content["reference_only"]
        and content["source"].startswith("https://github.com/")
    )
    assert db.query(Document).filter_by(kind="skill").count() == 0
    assert all(not db.get(Document, id).value()["enabled"] for id in first)
    db.get(Document, first[0]).data = canonical(
        {**db.get(Document, first[0]).value(), "content_hash": "tampered"}
    )
    with pytest.raises(Denied, match="immutable"):
        install_references(db, "owner")


def test_knowledge_tools_cannot_escape_stop_or_budget_policies(db):
    run = make_run(db)
    for change in ({"status": "cancelled"}, {"deadline": 1}, {"tool_calls": 50}):
        before = run.value()
        run.data = canonical({**before, **change})
        db.commit()
        with pytest.raises(Denied):
            broker(db, run, None, "knowledge.search", {"query": "scope"}, "research")
        run.data = canonical(before)
        db.commit()


def test_owner_feedback_review_preserves_source_and_other_owner_isolation(db, tmp_path):
    from test_auth_api import authenticated

    client, user, _ = authenticated(db)
    k = seed(db, tmp_path)
    run = make_run(db, owner=user.id)
    feedback = broker(
        db,
        run,
        None,
        "knowledge.submit_feedback",
        {
            "record_id": k.id,
            "rating": "relevant",
            "notes": "Synthetic reviewed relevance",
        },
        "research",
    )["result"]
    original_hash = k.content_hash
    response = client.patch(
        "/api/v1/knowledge-feedback/" + feedback["feedback_id"] + "/review",
        json={"decision": "accepted", "reason": "Source relevance checked in fixture"},
    )
    assert response.status_code == 200
    assert not response.json()["trusted_source_modified"]
    db.refresh(k)
    assert k.content_hash == original_hash
    assert client.get("/api/v1/knowledge-feedback").json()[0]["status"] == "accepted"
    assert (
        client.patch(
            "/api/v1/knowledge-feedback/" + feedback["feedback_id"] + "/review",
            json={"decision": "rejected", "reason": "Cannot silently rewrite review"},
        ).status_code
        == 403
    )


@pytest.mark.parametrize("registered", [True, False])
def test_swarm_tool_results_return_to_reasoning_without_shell_escape(
    db, tmp_path, monkeypatch, registered
):
    from test_swarm import prepare

    from atlas.tools import Repository

    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("tenant_boundary = True\n")
    repo = Repository(root)
    run = prepare(db, 1)
    source = document(
        db,
        "repository",
        run.owner,
        {"path": str(root), "snapshot_hash": repo.inventory()["snapshot_hash"]},
    )
    run.data = canonical({**run.value(), "repository_id": source.id})
    p = document(
        db, "provider", run.owner, {"adapter_type": "custom_openai_compatible"}
    )
    m = document(
        db,
        "provider_model",
        run.owner,
        {"model_id": "fixture", "max_output_tokens": 1024},
    )
    db.commit()
    monkeypatch.setattr("atlas.workflow.model_binding", lambda *_: (p, m))
    calls = []

    def generate(db, p, m, req, run, alias):
        context = json.loads(req.messages[1]["content"])["context"]
        assert "read_file_range" in context["tool_capabilities"]
        assert "shell" not in context["tool_capabilities"]
        calls.append(context)
        if len(calls) == 1:
            tool = (
                {"name": "read_file_range", "input": {"path": "app.py"}}
                if registered
                else {"name": "shell", "input": {"command": "unregistered"}}
            )
            payload = {"summary": "Need exact source evidence", "tool_requests": [tool]}
        else:
            result = context["knowledge_tool_results"][0]
            assert (
                result["artifact_id"]
                and "tenant_boundary = True" in result["result"]["text"]
            )
            payload = {
                "summary": "Source read through the policy broker",
                "citations": ["app.py:1"],
            }
        return ModelResponse(content=canonical(payload), structured_content=payload)

    monkeypatch.setattr("atlas.workflow.generate_budgeted", generate)
    if registered:
        result = role(db, run, "SWARM_TASK", {})
        assert result.citations == ["app.py:1"] and len(calls) == 2
    else:
        with pytest.raises(Denied, match="not registered"):
            role(db, run, "SWARM_TASK", {})
        assert len(calls) == 1
