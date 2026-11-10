import time

import pytest
from pydantic import ValidationError

from atlas.db import document
from atlas.gateway import CapacityWait, ModelInput, ModelResponse, ProviderError
from atlas.model_routing import (
    approved_pools,
    circuit_state,
    outcome,
    rank,
    require_dispatchable,
)
from atlas.workflow import role, selected_model_binding


def configured(db):
    campaign = document(db, "campaign", "u", {"mode": "source"})
    provider = document(
        db, "provider", "u", {"enabled": True, "health_status": "tested"}
    )
    models = []
    for name in ("flash", "pro"):
        models.append(
            document(
                db,
                "provider_model",
                "u",
                {
                    **ModelInput(
                        model_id=name, context_window=64000, max_output_tokens=4096
                    ).model_dump(),
                    "provider_id": provider.id,
                    "verified_structured": True,
                },
            )
        )
    pins = {
        alias: {
            "provider_id": provider.id,
            "provider_version": provider.version,
            "model_id": models[index].id,
            "model_version": models[index].version,
        }
        for alias, index in (
            ("reasoning", 0),
            ("fast", 0),
            ("coding", 0),
            ("deep_research", 1),
            ("verifier", 1),
        )
    }
    run = document(
        db,
        "run",
        "u",
        {
            "model_mode": "auto",
            "campaign_id": campaign.id,
            "models": pins,
            "routing_candidates": approved_pools(pins),
        },
    )
    db.commit()
    return provider, models, run


def test_complexity_and_independent_validation_keep_explicit_model(db):
    _, models, run = configured(db)
    simple, _ = rank(
        db, run, "reasoning", "test", {"question": "Summarize headers"}, 1000, 1024
    )
    deep, _ = rank(
        db,
        run,
        "reasoning",
        "test",
        {"question": "Review ambiguous attack chain"},
        1000,
        1024,
    )
    validator, _ = rank(db, run, "verifier", "test", {}, 1000, 1024)
    assert simple[0][1].id == models[0].id and deep[0][1].id == models[1].id
    assert [m.id for _, m, _ in validator] == [models[1].id]
    with pytest.raises(ProviderError, match="approved pinned"):
        selected_model_binding(db, run, "verifier", models[0].id)


def test_context_ownership_and_versions_fail_closed(db):
    _, models, run = configured(db)
    assert not rank(db, run, "fast", "test", {}, 64000, 1024)[0]
    models[0].owner = "different-owner"
    models[1].version += 1
    db.flush()
    assert not rank(db, run, "reasoning", "test", {}, 1000, 1024)[0]


def test_circuit_persists_and_recovers_without_budget_reset(db, monkeypatch):
    provider, _, run = configured(db)
    for _ in range(3):
        outcome(db, provider, False)
        db.commit()
    db.expire_all()
    assert circuit_state(db, provider.id)["open"]
    with pytest.raises(CapacityWait):
        require_dispatchable(db, provider.id)
    candidates, rejected = rank(db, run, "reasoning", "test", {}, 1000, 1024)
    assert not candidates and all(r["reason"] == "circuit_open" for r in rejected)
    current = time.time()
    monkeypatch.setattr("atlas.model_routing.time.time", lambda: current + 400)
    require_dispatchable(db, provider.id)
    outcome(db, provider, True, 20)
    db.commit()
    assert circuit_state(db, provider.id)["failures"] == 0


@pytest.mark.parametrize("ambiguous", [False, True])
def test_fallback_only_before_dispatch(db, monkeypatch, ambiguous):
    _, models, run = configured(db)
    calls = []
    monkeypatch.setattr(
        "atlas.knowledge.prepare_context",
        lambda db, run, stage, context, alias: context,
    )

    def dispatch(db, run, provider, model, req, alias):
        calls.append(model.id)
        if len(calls) == 1:
            raise (
                ProviderError("Ambiguous transport failure")
                if ambiguous
                else CapacityWait("No dispatch capacity")
            )
        return ModelResponse(
            content='{"summary":"Observed only"}',
            structured_content={"summary": "Observed only"},
        )

    monkeypatch.setattr("atlas.workflow.dispatch_role_request", dispatch)
    if ambiguous:
        with pytest.raises(ProviderError, match="Ambiguous"):
            role(db, run, "test", {})
        assert calls == [models[0].id]
    else:
        assert role(db, run, "test", {}).summary == "Observed only"
        assert calls == [models[0].id, models[1].id]


def test_verified_prices_need_evidence():
    with pytest.raises(ValidationError, match="pricing source"):
        ModelInput(model_id="m", pricing_status="verified")
