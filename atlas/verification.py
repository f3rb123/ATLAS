"""Independent replay and counterfactual evidence gate. No model-only promotion."""

import re
from .db import Document, document, canonical, digest, now, SwarmTask, append
from .vault import redact
from .tools import broker


def successful_test(result):
    r = result.get("result", result)
    return (
        r.get("exit_code") == 0
        and not r.get("timed_out")
        and bool(re.search(r"Ran [1-9][0-9]* tests?", r.get("output", "")))
        and "\nOK" in r.get("output", "")
    )


def verify_candidates(db, run, repo, done):
    from .workflow import role

    executions = [
        d.value()["result"] for d in done if d.value()["state"] == "SAFE_EXECUTION"
    ]
    if not executions or executions[-1].get("no_experiment"):
        return {
            "status": "inconclusive",
            "reason": "No executable evidence was proposed; no finding confirmed",
        }
    original = executions[-1]
    if not successful_test(original["proof"]) or not successful_test(
        original["control"]
    ):
        return {
            "status": "inconclusive",
            "reason": "Research proof/control did not execute non-zero tests successfully",
        }
    e = original["experiment"]
    h = db.get(Document, e["hypothesis_id"])
    if (
        not h
        or h.owner != run.owner
        or h.kind != "hypothesis"
        or h.value()["run_id"] != run.id
    ):
        raise ValueError("Invalid hypothesis provenance")
    proof = broker(
        db,
        run,
        repo,
        "run_local_reproduction",
        {"template": "python_unittest", "test_path": e["test_path"]},
        "independent_verifier",
    )
    control = broker(
        db,
        run,
        repo,
        "run_local_reproduction",
        {"template": "python_unittest", "test_path": e["control_test_path"]},
        "independent_verifier",
    )
    if not successful_test(proof) or not successful_test(control):
        return {"status": "refuted", "reason": "Independent reproduction failed"}
    # Fresh verifier context includes the claim, evidence and secure counterfactual only.
    from .tools import ReadInput

    files, _ = repo.files()
    prefixes = [
        e["test_path"].rstrip("/") + "/",
        e["control_test_path"].rstrip("/") + "/",
    ]
    selected = [f for f in files if any(f.startswith(p) for p in prefixes)][:6]
    selected += [
        c.split(":", 1)[0]
        for c in h.value()["citations"]
        if c.split(":", 1)[0] in files
    ][:4]
    source = [repo.read(ReadInput(path=f, end=200)) for f in dict.fromkeys(selected)]
    response = role(
        db,
        run,
        "INDEPENDENT_VERIFICATION",
        {
            "reproduction_source": source,
            "claim": h.value(),
            "proof": proof,
            "secure_control": control,
            "snapshot": repo.inventory()["snapshot_hash"],
            "expected_evidence_ids": [proof["artifact_id"], control["artifact_id"]],
            "evidence_instruction": "Copy both expected_evidence_ids exactly into evidence_ids if classifying confirmed. Knowledge record IDs and earlier research artifact IDs do not substitute for these fresh independent artifacts.",
        },
        "verifier",
    )
    allowed = {proof["artifact_id"], control["artifact_id"]}
    review = document(db, "verification_review", run.owner, {"run_id": run.id,
        "task_id": getattr(run, "_swarm_claim", (None, None))[0], "hypothesis_id": h.id,
        "model_review": __import__("json").loads(redact(canonical(response.model_dump()))),
        "expected_evidence_ids": sorted(allowed), "finding_confirmed": False})
    if response.status == "confirmed" and (
        set(response.evidence_ids) != allowed or not response.counterfactual
    ):
        append(db, run.id, "independent_verifier", "verification_rejected", {"review_id": review.id, "code": "independent_evidence_binding_failed"}, run.value()["campaign_id"])
        return {"status": "inconclusive", "review_id": review.id, "reason": "Independent review did not bind both fresh proof/control artifacts; no finding confirmed"}
    key = digest(
        canonical(
            {"claim": h.value()["claim"], "snapshot": repo.inventory()["snapshot_hash"]}
        )
    )
    existing = [
        f
        for f in db.query(Document).filter_by(kind="finding", owner=run.owner)
        if f.value()["root_cause_key"] == key
    ]
    if existing:
        return {"status": "duplicate", "finding_id": existing[0].id}
    finding = document(
        db,
        "finding",
        run.owner,
        {
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "title": h.value()["claim"],
            "status": response.status,
            "severity": "unscored",
            "vulnerability_class": "unclassified",
            "asset": None,
            "endpoint": None,
            "parameter_or_component": None,
            "confidence": None,
            "technical_explanation": response.reason,
            "impact": h.value().get("impact"),
            "reproduction_steps": {"test_path": e["test_path"], "secure_control": e["control_test_path"], "snapshot": repo.inventory()["snapshot_hash"]},
            "discovery_agent": (db.get(SwarmTask, h.value()["task_id"]).role if h.value().get("task_id") and db.get(SwarmTask, h.value()["task_id"]) else "research"),
            "validation_agent": "independent_verifier",
            "source_references": h.value().get("citations", []),
            "related_findings": [],
            "timeline": [{"at": now(), "actor": "independent_verifier", "status": response.status}],
            "hypothesis": h.value(),
            "verification": response.model_dump(),
            "evidence_ids": list(allowed),
            "root_cause_key": key,
            "policy_hash": run.value()["policy_hash"],
        },
    )
    return {"status": response.status, "finding_id": finding.id}
