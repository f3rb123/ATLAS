"""Expose unverified shared-board leads and explicit coverage limitations."""

from .db import Document


def leads(db, run, limit=60):
    result, seen = [], set()
    rows = db.query(Document).filter(Document.owner == run.owner, Document.kind.in_(("hypothesis", "swarm_event"))).order_by(Document.created.desc())
    for row in rows:
        value = row.value()
        if value.get("run_id") != run.id or (row.kind == "swarm_event" and value.get("kind") != "hypothesis"):
            continue
        claim = value.get("claim") if row.kind == "hypothesis" else value.get("text")
        if not isinstance(claim, str) or not claim.strip():
            continue
        key = " ".join(claim.split())
        if key in seen:
            continue
        seen.add(key)
        result.append({"id": row.id, "claim": claim[:4000], "status": "unverified",
            "research_status": value.get("status", "candidate"), "citations": value.get("citations", [])[:12],
            "source": "shared_board" if row.kind == "swarm_event" else "hypothesis"})
        if len(result) >= limit:
            break
    return result


def coverage_notes(db, run):
    value = run.value()
    policy = db.get(Document, value.get("policy_id", ""))
    scope = policy.value().get("scope", {}) if policy else {}
    notes = []
    if not value.get("target_identities"):
        notes.append("No owned test identities are pinned. Cross-account authorization/IDOR comparisons remain unverified.")
    if "differential" not in scope.get("test_classes", []):
        notes.append("Paired HTTP experiments are unavailable under this frozen policy. Resume preserves that policy.")
    for row in db.query(Document).filter_by(kind="run", owner=run.owner):
        discovery = row.value()
        if discovery.get("campaign_id") == value.get("campaign_id") and discovery.get("execution_mode") == "skunk-discovery":
            status = discovery.get("wildcard_discovery")
            if status:
                notes.append("Wildcard coverage uses public indexes, not a complete asset inventory: " + str(status.get("hostnames", 0)) + " hostnames; " + str(sum(s.get("status") != "ok" for s in status.get("sources", []))) + " unavailable or incomplete sources.")
            else:
                notes.append("This saved campaign used public wildcard indexes without complete per-source coverage records. Discovered hosts do not establish full wildcard coverage.")
    return list(dict.fromkeys(notes))
