"""Explainable routing over explicitly configured, version-pinned model aliases.

Fallback is allowed only before dispatch. Ambiguous transport outcomes retain
their billing reservations and are never automatically replayed on another model.
"""

import time

from .db import Document, append, canonical, digest, document, transaction_lock
from .gateway import CapacityWait, ProviderError


class ProviderCircuitOpen(CapacityWait):
    pass


def circuit_id(provider_id):
    return digest("provider-circuit:" + provider_id)[:36]


def circuit_state(db, provider_id):
    row = db.get(Document, circuit_id(provider_id))
    value = (
        row.value()
        if row
        else {"failures": 0, "unavailable_until": 0, "latency_ms": None}
    )
    return {**value, "open": value.get("unavailable_until", 0) > time.time()}


def require_dispatchable(db, provider_id):
    if circuit_state(db, provider_id)["open"]:
        raise ProviderCircuitOpen(
            "Provider circuit is cooling down; no request dispatched"
        )


def outcome(db, provider, success, latency_ms=None):
    transaction_lock(db, "provider-circuit:" + provider.id)
    row = (
        db.query(Document)
        .filter_by(id=circuit_id(provider.id))
        .with_for_update()
        .first()
    )
    value = (
        row.value()
        if row
        else {"failures": 0, "unavailable_until": 0, "latency_ms": None}
    )
    if success:
        value.update(failures=0, unavailable_until=0)
        if latency_ms is not None:
            previous = value.get("latency_ms")
            value["latency_ms"] = (
                float(latency_ms)
                if previous is None
                else previous * 0.8 + float(latency_ms) * 0.2
            )
    else:
        value["failures"] += 1
        if value["failures"] >= 3:
            value["unavailable_until"] = time.time() + min(
                300, 30 * 2 ** min(value["failures"] - 3, 4)
            )
    value["last_outcome"] = "success" if success else "failure_unknown_billing"
    value["updated_at"] = time.time()
    if row:
        row.data = canonical(value)
    else:
        document(db, "provider_circuit", provider.owner, value, circuit_id(provider.id))


def pin_documents(db, run, pin):
    from .skunk_models import runtime_contract
    provider = db.get(Document, pin["provider_id"])
    model = db.get(Document, pin["model_id"])
    if (
        not provider
        or not model
        or provider.kind != "provider"
        or model.kind != "provider_model"
        or provider.owner != run.owner
        or model.owner != run.owner
        or provider.version != pin["provider_version"]
        or model.version != pin["model_version"]
        or not provider.value().get("enabled")
        or model.value().get("provider_id") != provider.id
        or (provider.value().get("health_status") not in ("tested", "runtime_validated")
            and not runtime_contract(provider, model, run))
        or (not model.value().get("verified_structured")
            and not runtime_contract(provider, model, run))
    ):
        raise ProviderError(
            "Pinned provider/model is unavailable, changed, or unverified"
        )
    return provider, model


def approved_pools(models):
    pools = {}
    for alias in models:
        if alias in ("embedding", "vision"):
            continue
        names = [alias]
        # Verification and deep research retain their explicit assignments.
        if alias in ("reasoning", "fast", "coding"):
            names.extend(["reasoning", "fast", "coding", "deep_research"])
        seen, values = set(), []
        for name in names:
            pin = models.get(name)
            if pin and pin["model_id"] not in seen:
                seen.add(pin["model_id"])
                values.append({**pin, "configured_alias": name})
        pools[alias] = values
    return pools


def complexity(stage, context, alias):
    role = context.get("task", {}).get("role", "")
    if alias in ("verifier", "deep_research") or role in (
        "deep-research",
        "validation-review",
        "proof-validation",
    ):
        return "high"
    question = (
        str(context.get("question", ""))
        + " "
        + str(context.get("task", {}).get("instructions", ""))
    )
    if any(
        word in question.lower()
        for word in ("cryptograph", "race condition", "attack chain", "ambiguous")
    ):
        return "high"
    return "medium" if len(question) > 1500 else "low"


def rank(db, run, alias, stage, context, input_bytes, output_tokens):
    value = run.value()
    pools = value.get("routing_candidates") or approved_pools(value.get("models", {}))
    pins = pools.get(alias, [])
    level = complexity(stage, context, alias)
    ranked, rejected = [], []
    for order, pin in enumerate(pins):
        try:
            provider, model = pin_documents(db, run, pin)
            require_dispatchable(db, provider.id)
            m = model.value()
            if (
                input_bytes + min(output_tokens, m["max_output_tokens"])
                > m["context_window"]
            ):
                raise ProviderError("Conservative context limit exceeded")
            if not m.get("enabled", True):
                raise ProviderError("Model disabled")
            state = circuit_state(db, provider.id)
            preferred_alias = alias
            if alias in ("reasoning", "fast", "coding"):
                preferred_alias = (
                    "deep_research"
                    if level == "high"
                    else ("fast" if level == "low" else alias)
                )
            preferred_id = (
                value.get("models", {})
                .get(preferred_alias, value.get("models", {}).get(alias, {}))
                .get("model_id")
            )
            preferred = pin["model_id"] == preferred_id
            confirmed_price = m.get("pricing_status") == "verified"
            cost = (
                input_bytes * m["input_price"]
                + min(output_tokens, m["max_output_tokens"]) * m["output_price"]
            ) / 1000000
            score = (
                0 if preferred else 1,
                cost if confirmed_price else 0,
                state.get("latency_ms") or 0,
                order,
            )
            ranked.append(
                (
                    score,
                    provider,
                    model,
                    {
                        "complexity": level,
                        "configured_alias": pin.get("configured_alias", alias),
                        "context_bytes": input_bytes,
                        "context_window": m["context_window"],
                        "pricing_confirmed": confirmed_price,
                        "estimated_cost_usd": cost if confirmed_price else None,
                        "provider_circuit_open": False,
                    },
                )
            )
        except ProviderCircuitOpen:
            rejected.append(
                {"model_record_id": pin.get("model_id"), "reason": "circuit_open"}
            )
        except ProviderError:
            rejected.append(
                {
                    "model_record_id": pin.get("model_id"),
                    "reason": "unavailable_unverified_context_or_circuit",
                }
            )
    ranked.sort(key=lambda row: row[0])
    return [(p, m, reason) for _, p, m, reason in ranked], rejected


def route_event(db, run, alias, provider, model, reason, status="selected"):
    append(
        db,
        run.id,
        alias,
        "model_route",
        {
            "task_id": getattr(run, "_swarm_claim", (None, None))[0],
            "status": status,
            "provider_id": provider.id,
            "model_record_id": model.id,
            "model_id": model.value()["model_id"],
            **reason,
            "fallback_policy": "pre_dispatch_only; uncertain_billing_never_replayed",
        },
        run.value().get("campaign_id"),
    )
