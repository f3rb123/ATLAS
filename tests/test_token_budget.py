"""Atomic quota and billing tests use synthetic responses and no paid calls."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest

from atlas import gateway, token_budget
from atlas.db import Document, document, session


def test_initial_limits_and_detailed_usage_are_persistent(db):
    initial = token_budget.summarize(db)
    assert initial["cap"] == 50000000 and initial["allocation"] == 2000000
    assert initial["held_for_validation"] == 200000
    id = str(uuid4())
    token_budget.reserve(db, id, 100, "owner", "run", "reasoning", "provider")
    token_budget.settle(
        db,
        id,
        {
            "input_tokens": 30,
            "output_tokens": 20,
            "cached_input_tokens": 10,
            "reasoning_tokens": 5,
            "total_tokens": 50,
        },
    )
    db.commit()
    with session() as restarted:
        result = token_budget.summarize(restarted)
        assert result["used"]["total_tokens"] == 50
        assert result["used"]["input_tokens"] == 30
        assert result["used"]["cached_input_tokens"] == 10
        assert result["used"]["reasoning_tokens"] == 5
        assert result["remaining_allocation"] == 2000000 - 50


def test_concurrent_reservations_preserve_validation_capacity(db):
    token_budget.configure(db, 100, 100, 20)
    db.commit()

    def attempt(index):
        with session() as other:
            try:
                token_budget.reserve(
                    other, str(uuid4()), 15, "owner", "run", "research", "p"
                )
                other.commit()
                return True
            except token_budget.TokenBudgetExhausted:
                other.rollback()
                return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))
    assert sum(results) == 5
    token_budget.reserve(db, str(uuid4()), 20, "owner", "run", "verifier", "p")
    db.commit()
    result = token_budget.summarize(db)
    assert result["reserved_tokens"] == 95 and result["remaining_allocation"] == 5


def test_unknown_billing_holds_quota_and_no_automatic_reset(db):
    token_budget.configure(db, 1000, 500, 100)
    token_budget.reserve(db, "uncertain", 200, "owner", "run", "reasoning", "p")
    token_budget.mark_unknown(db, "uncertain")
    token_budget.settle(
        db, "uncertain", {"input_tokens": 5, "total_tokens": 5, "estimated": True}
    )
    db.commit()
    assert token_budget.summarize(db)["reserved_tokens"] == 200
    assert token_budget.summarize(db)["unknown_billing_reservations"] == 1
    token_budget.configure(db, 1000, 500, 100)
    assert token_budget.summarize(db)["reserved_tokens"] == 200
    token_budget.settle(
        db, "uncertain", {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
    )
    db.commit()
    assert token_budget.summarize(db)["used"]["total_tokens"] == 15


def test_provider_over_reservation_is_recorded_and_freezes_future_calls(db):
    token_budget.reserve(db, "violation", 10, "owner", "run", "reasoning", "p")
    token_budget.settle(
        db, "violation", {"input_tokens": 20, "output_tokens": 2, "total_tokens": 22}
    )
    db.commit()
    assert token_budget.summarize(db)["blocked"]
    assert token_budget.summarize(db)["used"]["total_tokens"] == 22
    with pytest.raises(token_budget.TokenBudgetExhausted):
        token_budget.reserve(db, "next", 5, "owner", "run", "verifier", "p")


def test_allocation_cannot_exceed_authority_or_erase_usage(db):
    with pytest.raises(ValueError):
        token_budget.configure(db, 50000001, 2000000, 200000)
    token_budget.reserve(db, "used", 100, "owner", "run", "reasoning", "p")
    token_budget.settle(db, "used", {"input_tokens": 60, "total_tokens": 60})
    with pytest.raises(ValueError):
        token_budget.configure(db, 100, 50, 0)


def test_invalid_structured_response_still_accounts_provider_usage(db, monkeypatch):
    provider = document(
        db, "provider", "owner", {"adapter_type": "custom_openai_compatible"}
    )
    model = document(
        db,
        "provider_model",
        "owner",
        {
            **gateway.ModelInput(
                model_id="fixture", input_price=1, output_price=1
            ).model_dump(),
            "provider_id": provider.id,
            "verified_structured": True,
        },
    )
    run = document(db, "run", "owner", {"status": "running", "budget_limit": 1})
    request = gateway.ModelRequest(
        model="fixture", messages=[{"role": "user", "content": "fixture"}]
    )
    response = gateway.Adapter(provider).normalize(
        {
            "choices": [
                {"message": {"content": "{truncated"}, "finish_reason": "length"}
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10},
        },
        request,
    )
    assert response.structured_content is None and response.warnings == [
        "invalid_structured_json"
    ]

    class Fixture:
        def generate(self, _):
            return response

    monkeypatch.setattr(gateway, "construct_adapter", lambda _: Fixture())
    with pytest.raises(gateway.ProviderError, match="usage was accounted"):
        gateway.generate_budgeted(db, provider, model, request, run)
    state = token_budget.summarize(db)
    assert state["used"]["total_tokens"] == 30 and state["reserved_tokens"] == 0


def test_unknown_billing_holds_tokens_without_occupying_finished_http_slot(db):
    from atlas.config import settings

    settings().max_provider_concurrency = 1
    first = gateway.reserve(db, "owner", "first", 1, "reasoning", "provider", 100)
    token_budget.mark_unknown(db, first)
    db.commit()
    assert gateway.reserve(db, "owner", "second", 1, "reasoning", "provider", 100)
    assert token_budget.summarize(db)["reserved_tokens"] == 200


def test_exact_json_fence_and_scrub_preserve_structured_protocol(db):
    provider = document(
        db, "provider", "owner", {"adapter_type": "custom_openai_compatible"}
    )
    request = gateway.ModelRequest(model="fixture", messages=[])
    content = (
        '```json\n{"summary":"Read the \\"password\\" field as untrusted data."}\n```'
    )
    response = gateway.Adapter(provider).normalize(
        {
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2},
        },
        request,
    )
    assert response.structured_content["summary"].startswith("Read")
    assert response.warnings == ["exact_json_fence_normalized"]


@pytest.mark.parametrize(
    "protocol,usage,expected",
    [
        (
            "openai_chat_completions",
            {
                "prompt_tokens": 30,
                "completion_tokens": 20,
                "total_tokens": 50,
                "prompt_tokens_details": {"cached_tokens": 10},
                "completion_tokens_details": {"reasoning_tokens": 5},
            },
            (30, 20, 10, 5, 50),
        ),
        (
            "anthropic_messages",
            {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_read_input_tokens": 7,
                "cache_creation_input_tokens": 3,
            },
            (20, 20, 7, 0, 40),
        ),
        (
            "gemini",
            {
                "promptTokenCount": 30,
                "candidatesTokenCount": 10,
                "thoughtsTokenCount": 5,
                "cachedContentTokenCount": 7,
                "totalTokenCount": 45,
            },
            (30, 15, 7, 5, 45),
        ),
    ],
)
def test_protocol_usage_includes_cached_and_reasoning_without_double_count(
    db, protocol, usage, expected
):
    provider = document(db, "provider", "owner", {"adapter_type": protocol})
    if protocol == "anthropic_messages":
        payload = {"content": [{"type": "text", "text": '{"ok":true}'}], "usage": usage}
    elif protocol == "gemini":
        payload = {
            "candidates": [{"content": {"parts": [{"text": '{"ok":true}'}]}}],
            "usageMetadata": usage,
        }
    else:
        payload = {"choices": [{"message": {"content": '{"ok":true}'}}], "usage": usage}
    response = gateway.Adapter(provider).normalize(
        payload, gateway.ModelRequest(model="fixture", messages=[])
    )
    assert (
        response.input_tokens,
        response.output_tokens,
        response.cached_input_tokens,
        response.reasoning_tokens,
        response.total_tokens,
    ) == expected


def fixture_run(db):
    campaign = document(db, "campaign", "owner", {"budget_limit": 100})
    run = document(
        db,
        "run",
        "owner",
        {
            "campaign_id": campaign.id,
            "status": "running",
            "budget_limit": 100,
            "budget_used": 0,
        },
    )
    provider = document(db, "provider", "owner", {})
    model = document(
        db,
        "provider_model",
        "owner",
        {
            "model_id": "fixture",
            "max_output_tokens": 512,
            "context_window": 32000,
            "verified_structured": True,
            "input_price": 1,
            "output_price": 2,
        },
    )
    db.commit()
    return run, provider, model


def test_paid_dispatch_is_blocked_before_call_when_tokens_exhausted(db, monkeypatch):
    token_budget.configure(db, 1000, 1000, 100)
    db.commit()
    run, provider, model = fixture_run(db)
    called = []
    monkeypatch.setattr(
        gateway,
        "construct_adapter",
        lambda _: SimpleNamespace(generate=lambda r: called.append(r)),
    )
    with pytest.raises(token_budget.TokenBudgetExhausted):
        gateway.generate_budgeted(
            db,
            provider,
            model,
            gateway.ModelRequest(
                model="fixture",
                messages=[{"role": "user", "content": "synthetic"}],
                max_tokens=32,
            ),
            run,
        )
    assert called == []


def test_gateway_transport_failure_keeps_both_reservations(db, monkeypatch):
    run, provider, model = fixture_run(db)

    def fail(request):
        raise gateway.ProviderError("Synthetic timeout; dispatch outcome unknown")

    monkeypatch.setattr(
        gateway, "construct_adapter", lambda _: SimpleNamespace(generate=fail)
    )
    with pytest.raises(gateway.ProviderError):
        gateway.generate_budgeted(
            db,
            provider,
            model,
            gateway.ModelRequest(
                model="fixture",
                messages=[{"role": "user", "content": "fixture"}],
                max_tokens=32,
            ),
            run,
        )
    db.expire_all()
    result = token_budget.summarize(db)
    assert result["reserved_tokens"] > 0 and result["unknown_billing_reservations"] == 1
    assert db.get(Document, "budget-global").value()["reserved"]
