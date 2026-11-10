"""Serialize root-cause deduplication without discarding independent evidence."""

from .db import Document, append, canonical, now, transaction_lock


def matching_findings(db, run, key):
    campaign = run.value()["campaign_id"]
    transaction_lock(db, "finding-root:" + run.owner + ":" + campaign + ":" + key)
    return [
        row
        for row in db.query(Document)
        .filter_by(kind="finding", owner=run.owner)
        .filter(Document.data.contains('"root_cause_key":"' + key + '"'))
        .order_by(Document.created.desc())
        .with_for_update()
        if row.value().get("campaign_id") == campaign
        and row.value().get("root_cause_key") == key
    ]


def record_duplicate(db, run, existing, candidate, fresh, review, actor):
    value = existing.value()
    value.setdefault("independent_review_ids", []).append(review.id)
    value.setdefault("timeline", []).append(
        {
            "at": now(),
            "actor": actor,
            "status": "duplicate_confirmed",
            "run_id": run.id,
            "candidate_id": candidate.id,
            "review_id": review.id,
        }
    )
    existing.data = canonical(value)
    value = candidate.value()
    value.update(
        status="duplicate",
        effective_status="confirmed",
        finding_id=existing.id,
        independent_result=fresh,
        review_id=review.id,
    )
    candidate.data = canonical(value)
    append(
        db,
        run.id,
        actor,
        "finding_duplicate_reviewed",
        {
            "finding_id": existing.id,
            "candidate_id": candidate.id,
            "review_id": review.id,
        },
        run.value()["campaign_id"],
    )
    return {
        "status": "duplicate",
        "finding_id": existing.id,
        "candidate_id": candidate.id,
    }
