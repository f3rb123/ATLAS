import pytest
from atlas.db import document, canonical
from atlas.queueing import admit
from atlas.policy import Denied
from atlas.config import settings
from atlas.workflow import control


def test_capacity_applies_to_new_and_resumed_runs(db):
    settings().max_campaign_runs = 1
    active = document(
        db, "run", "u", {"campaign_id": "c", "status": "queued", "state": "CREATED"}
    )
    paused = document(
        db, "run", "u", {"campaign_id": "c", "status": "paused", "state": "CREATED"}
    )
    db.commit()
    with pytest.raises(Denied, match="concurrency"):
        admit(db, "u", "c")
    with pytest.raises(Denied, match="concurrency"):
        control(db, paused, "resume", "u")
    admit(db, "u", "other-campaign")
    control(db, active, "pause", "u")
    db.commit()
    control(db, paused, "resume", "u")
    db.commit()
    assert paused.value()["status"] == "queued"
