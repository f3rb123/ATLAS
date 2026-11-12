"""Persistent global input/output quota, atomic with monetary reservations.

No calendar reset. Unknown billing retains capacity until explicit reconciliation.
Cached input and reasoning are tracked as subsets, not counted twice in totals.
"""

from .config import settings
from .db import Document, canonical, document, now, transaction_lock

AUTHORIZED_MAX = 50000000
VALIDATION_ROLES = {
    "verifier",
    "validation-review",
    "proof-validation",
    "independent-validation",
}
COUNTERS = (
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "cache_creation_input_tokens",
    "reasoning_tokens",
    "total_tokens",
)


class TokenBudgetExhausted(ValueError):
    pass


def ledger(db):
    transaction_lock(db, "budget-global")
    row = (
        db.query(Document).filter_by(id="token-budget-global").with_for_update().first()
    )
    if row is None:
        cfg = settings()
        allocation = min(cfg.token_allocation, cfg.global_token_cap)
        row = document(
            db,
            "token_budget",
            "system",
            {
                "version": 1,
                "cap": cfg.global_token_cap,
                "allocation": allocation,
                "validation_reserve": min(cfg.validation_token_reserve, allocation),
                "used": {k: 0 for k in COUNTERS},
                "validation_used": 0,
                "reserved": {},
                "contract_violation": False,
                "created_at": now(),
                "reset_policy": "never_automatic",
            },
            "token-budget-global",
        )
    return row


def summarize(db):
    value = ledger(db).value()
    reserved = sum(r["ceiling"] for r in value["reserved"].values())
    validation_pending = sum(
        r["ceiling"]
        for r in value["reserved"].values()
        if r["role"] in VALIDATION_ROLES
    )
    protected = max(
        0, value["validation_reserve"] - value["validation_used"] - validation_pending
    )
    used = value["used"]["total_tokens"]
    return {
        "cap": value["cap"],
        "allocation": value["allocation"],
        "used": value["used"],
        "reserved_tokens": reserved,
        "remaining_global": max(0, value["cap"] - used - reserved),
        "remaining_allocation": max(0, value["allocation"] - used - reserved),
        "held_for_validation": protected,
        "validation_used": value["validation_used"],
        "unknown_billing_reservations": sum(
            r.get("state") == "unknown_billing" for r in value["reserved"].values()
        ),
        "pending_reservations": [
            {"id": id, **r} for id, r in value["reserved"].items()
        ],
        "blocked": value["contract_violation"],
        "reset_policy": value["reset_policy"],
    }


def configure(db, cap, allocation, validation_reserve):
    if (
        type(cap) is not int
        or not 1 <= cap <= AUTHORIZED_MAX
        or type(allocation) is not int
        or not 1 <= allocation <= cap
        or type(validation_reserve) is not int
        or not 0 <= validation_reserve <= allocation
    ):
        raise ValueError("Token limits exceed the authorized cap or allocation")
    row = ledger(db)
    value = row.value()
    committed = value["used"]["total_tokens"] + sum(
        r["ceiling"] for r in value["reserved"].values()
    )
    if allocation < committed:
        raise ValueError("Allocation cannot be below consumed and reserved tokens")
    value.update(
        cap=cap,
        allocation=allocation,
        validation_reserve=validation_reserve,
        updated_at=now(),
    )
    row.data = canonical(value)
    return summarize(db)


def ceiling(request):
    # UTF-8 bytes conservatively bound tokenizer input, with framing overhead.
    # Extra output capacity protects providers with separately metered reasoning.
    payload = canonical(request.model_dump()).encode("utf-8")
    return len(payload) + 4096 + request.max_tokens * 4


def reserve(db, id, amount, owner, run_id, role, provider_id):
    if type(amount) is not int or amount <= 0:
        raise ValueError("Token reservation must be a positive integer")
    row = ledger(db)
    value = row.value()
    from .skunk_usage import tracking_only
    track_only = tracking_only(db.get(Document, run_id))
    if not track_only and value["contract_violation"]:
        raise TokenBudgetExhausted(
            "Provider token contract violated; operator review required"
        )
    if id in value["reserved"]:
        raise ValueError("Token reservation identity collision")
    pending = sum(r["ceiling"] for r in value["reserved"].values())
    remaining = (
        min(value["cap"], value["allocation"]) - value["used"]["total_tokens"] - pending
    )
    validation_pending = sum(
        r["ceiling"]
        for r in value["reserved"].values()
        if r["role"] in VALIDATION_ROLES
    )
    protected = max(
        0, value["validation_reserve"] - value["validation_used"] - validation_pending
    )
    if not track_only and (amount > remaining or (
        role not in VALIDATION_ROLES and amount > remaining - protected
    )):
        raise TokenBudgetExhausted(
            "Global token allocation exhausted or reserved for independent validation"
        )
    value["reserved"][id] = {
        "ceiling": amount,
        "owner": owner,
        "run_id": run_id,
        "role": role or "unspecified",
        "provider_id": provider_id,
        "state": "pending",
        "enforcement": "tracking_only" if track_only else "bounded",
        "created_at": now(),
    }
    row.data = canonical(value)


def mark_unknown(db, id):
    row = ledger(db)
    value = row.value()
    if id in value["reserved"]:
        value["reserved"][id]["state"] = "unknown_billing"
        row.data = canonical(value)


def settle(db, id, usage=None, not_dispatched=False):
    row = ledger(db)
    value = row.value()
    reservation = value["reserved"].get(id)
    if reservation is None:
        return
    if not_dispatched:
        value["reserved"].pop(id)
        row.data = canonical(value)
        return
    if usage is None or usage.get("estimated"):
        value["reserved"][id]["state"] = "unknown_billing"
        row.data = canonical(value)
        return
    counters = {k: usage.get(k, 0) for k in COUNTERS}
    if any(type(x) is not int or x < 0 for x in counters.values()):
        raise ValueError("Invalid token usage counters")
    if counters["total_tokens"] < counters["input_tokens"] + counters["output_tokens"]:
        raise ValueError("Total tokens cannot undercount input plus output")
    if (
        counters["cached_input_tokens"] + counters["cache_creation_input_tokens"]
        > counters["input_tokens"]
    ):
        raise ValueError("Cached input cannot exceed total input")
    value["reserved"].pop(id)
    for name, count in counters.items():
        value["used"][name] += count
    if reservation["role"] in VALIDATION_ROLES:
        value["validation_used"] += counters["total_tokens"]
    if counters["total_tokens"] > reservation["ceiling"]:
        # Record reality and stop future calls; never hide a provider violation.
        value["contract_violation"] = True
    row.data = canonical(value)
    document(
        db,
        "token_usage",
        reservation["owner"],
        {
            "reservation_id": id,
            "run_id": reservation["run_id"],
            "role": reservation["role"],
            "provider_id": reservation["provider_id"],
            **counters,
            "confirmed": True,
            "provider_contract_violation": counters["total_tokens"]
            > reservation["ceiling"],
            "recorded_at": now(),
        },
    )
