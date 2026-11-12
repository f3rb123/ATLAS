"""Host-only local token allocation management; also runnable as a standalone helper."""

import argparse
import fcntl
import json
from pathlib import Path


def compact(value):
    pending = list(value.get("reserved", {}).values())
    reserved = sum(item["ceiling"] for item in pending)
    validation_pending = sum(item["ceiling"] for item in pending if item["role"] in {"verifier", "validation-review", "proof-validation", "independent-validation"})
    protected = max(0, value["validation_reserve"] - value["validation_used"] - validation_pending)
    used = value["used"]["total_tokens"]
    remaining = max(0, min(value["cap"], value["allocation"]) - used - reserved)
    return {
        "cap": value["cap"], "allocation": value["allocation"], "used_tokens": used,
        "reserved_tokens": reserved, "remaining_allocation": remaining,
        "held_for_validation": protected, "available_for_research": max(0, remaining - protected),
        "unknown_billing_holds": sum(item.get("state") == "unknown_billing" for item in pending),
        "contract_violation": value.get("contract_violation", False),
    }


def manage(add=None):
    # Absolute imports allow this reviewed module to run with the existing
    # installed interpreter without first replacing the rest of the application.
    from atlas.skunk import prepare_environment
    root = prepare_environment()
    from atlas.config import settings
    from atlas.db import Document, append, session, transaction_lock
    from atlas.token_budget import configure
    from sqlalchemy.engine import make_url

    cfg = settings()
    url = make_url(cfg.database_url)
    if url.drivername.startswith("sqlite") and not Path(url.database).expanduser().is_file():
        return {"error": "existing_skunk_database_not_found", "changed": False}
    lock = None
    if add is not None:
        if type(add) is not int or not 1 <= add <= 50000000:
            return {"error": "add_must_be_between_1_and_50000000", "changed": False}
        lock = (root / "controller.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            return {"error": "exit_skunk_with_ctrl_c_before_changing_allocation", "changed": False}
    try:
        with session() as db:
            if add is not None:
                transaction_lock(db, "budget-global")
            ledger = db.get(Document, "token-budget-global")
            if ledger is None:
                return {"error": "existing_token_ledger_not_found", "changed": False}
            value = ledger.value()
            summary = compact(value)
            if add is None:
                return summary
            if summary["contract_violation"]:
                return {"error": "token_contract_violation_requires_review", "changed": False, "budget": summary}
            new_allocation = min(value["cap"], value["allocation"] + add)
            if new_allocation <= value["allocation"]:
                return {"error": "existing_global_cap_reached", "changed": False, "budget": summary}
            committed = summary["used_tokens"] + summary["reserved_tokens"]
            if new_allocation < committed:
                return {"error": "requested_allocation_still_below_usage_and_holds", "changed": False, "budget": summary}
            configure(db, value["cap"], new_allocation, value["validation_reserve"])
            append(db, "token-budget-global", "skunk-host", "token_allocation_increased", {
                "previous_allocation": value["allocation"], "allocation": new_allocation,
                "cap": value["cap"], "requested_addition": add,
                "used_and_uncertain_reservations": "preserved",
                "authorization": "Host operator explicitly invoked budget --add",
            })
            result = {"changed": True, "previous_allocation": value["allocation"], **compact(ledger.value())}
            db.commit()
            return result
    finally:
        if lock is not None:
            lock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--add", type=int, help="Explicitly add this many local tokens, within the existing cap; usage and holds stay intact")
    args = parser.parse_args(argv)
    from sqlalchemy.exc import SQLAlchemyError
    try:
        result = manage(args.add)
    except (SQLAlchemyError, OSError, ValueError):
        result = {"error": "local_budget_operation_failed", "changed": False}
    print(json.dumps(result, separators=(",", ":")))
    if "error" in result:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
