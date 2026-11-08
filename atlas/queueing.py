"""Durable queue admission shared by new runs and resumes."""

from atlas.db import Document, transaction_lock
from atlas.config import settings
from atlas.policy import Denied


def admit(db, owner, campaign_id, exclude=None):
    transaction_lock(db, "queue:" + owner)
    active = [
        r
        for r in db.query(Document).filter_by(kind="run", owner=owner)
        if r.id != exclude and r.value()["status"] in ("queued", "running")
    ]
    if len(active) >= settings().max_queued_runs:
        raise Denied("Owner queue capacity reached; finish or pause existing runs")
    if (
        sum(r.value().get("campaign_id") == campaign_id for r in active)
        >= settings().max_campaign_runs
    ):
        raise Denied("Campaign concurrency limit reached")
