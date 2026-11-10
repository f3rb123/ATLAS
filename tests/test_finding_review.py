import json

from test_auth_api import authenticated

from atlas.db import document
from atlas.reporting import generate_report


def fixture(db, owner, status="confirmed"):
    campaign = document(db, "campaign", owner, {})
    run = document(db, "run", owner, {"campaign_id": campaign.id, "policy_hash": "fixture"})
    finding = document(db, "finding", owner, {"run_id": run.id, "campaign_id": campaign.id,
        "title": "Authored fixture", "status": status, "policy_hash": "fixture", "evidence_ids": ["proof", "control"],
        "hypothesis": {"impact": "Authored cross-owner boundary"}, "verification": {"status": status, "reason": "Fixture review", "counterfactual": "Secure control"}})
    db.commit()
    return run, finding


def test_metadata_review_cannot_change_verification_or_evidence(db):
    client, owner, _ = authenticated(db)
    _, finding = fixture(db, owner.id, "inconclusive")
    response = client.patch(f"/api/v1/findings/{finding.id}/metadata", json={"title": "Reviewed description", "severity": "low", "vulnerability_class": "CWE-639"})
    assert response.status_code == 200
    value = response.json()
    assert value["status"] == "inconclusive" and value["verification"]["status"] == "inconclusive"
    assert value["evidence_ids"] == ["proof", "control"] and value["metadata_reviewed_by"] == owner.id
    assert client.patch(f"/api/v1/findings/{finding.id}/metadata", json={"title": "forged", "status": "confirmed"}).status_code == 422
    assert client.patch(f"/api/v1/findings/{finding.id}", json={"status": "report_ready", "review_notes": "No proof"}).status_code == 403


def test_report_ready_keeps_independently_confirmed_finding_in_exports(db):
    client, owner, _ = authenticated(db)
    run, finding = fixture(db, owner.id)
    response = client.patch(f"/api/v1/findings/{finding.id}", json={"status": "report_ready", "review_notes": "Review complete"})
    assert response.status_code == 200
    db.expire_all()
    report = generate_report(db, run, "json")
    assert json.loads(report.value()["content"])["findings"][0]["status"] == "report_ready"
