"""Preserve the owner's prior consumption floor without shipping private state."""

import json
from pathlib import Path
import sys

from atlas.db import Document, append, canonical, document, session, transaction_lock
from atlas.token_budget import COUNTERS

floor = json.loads(Path(sys.argv[1]).read_text())
if set(floor["used"]) != set(COUNTERS) or any(
    type(v) is not int or v < 0 for v in floor["used"].values()
):
    raise SystemExit("Invalid historical token counters")
if (
    floor["used"]["total_tokens"]
    != floor["used"]["input_tokens"] + floor["used"]["output_tokens"]
):
    raise SystemExit("Historical total does not match input/output")
held = sum(item["ceiling"] for item in floor["reserved"].values())
if (
    not 0
    <= floor["used"]["total_tokens"] + held
    <= floor["allocation"]
    <= floor["cap"]
    <= 50000000
):
    raise SystemExit("Invalid budget authority")
with session() as db:
    transaction_lock(db, "budget-global")
    row = (
        db.query(Document).filter_by(id="token-budget-global").with_for_update().first()
    )
    if row:
        # Rerunning an installer must never replace, reset or merge live usage.
        value = row.value()
        if value["used"]["total_tokens"] < floor["used"]["total_tokens"]:
            raise SystemExit(
                "Existing ledger predates this consumption floor; preserve it and perform an explicit state migration"
            )
        print(
            "Existing persistent token ledger preserved; no counters or holds changed."
        )
    else:
        document(db, "token_budget", "system", floor, "token-budget-global")
        append(
            db,
            "token-budget-global",
            "prebuilt-installer",
            "historical_budget_floor_imported",
            {
                "used": floor["used"]["total_tokens"],
                "held": held,
                "private_history_included": False,
            },
        )
        db.commit()
        print(
            "Historical token consumption and uncertain holds retained; no allowance reset."
        )
