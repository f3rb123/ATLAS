"""TEST ONLY host-driven provisioning and evidence for the local Compose validation override."""

import sys, json, time
import httpx
from atlas.db import session, Document, Journal, document, canonical, digest, uid, now
from atlas.gateway import (
    ProviderInput,
    ModelInput,
    ModelRequest,
    create_provider,
    Adapter,
)
from atlas.policy import Scope
from atlas.workflow import ORDER

FIXTURE_OWNER = "deployment-validation"
with session() as db:
    if sys.argv[1] == "create":
        provider = create_provider(
            db,
            FIXTURE_OWNER,
            ProviderInput(
                display_name="Synthetic local deployment fixture",
                base_url="http://fixture-provider:9001/v1",
                api_key="fixture-only-not-real",
            ),
        )
        probe = Adapter(provider).generate(
            ModelRequest(
                model="fixture-json",
                messages=[{"role": "user", "content": "Return JSON"}],
                max_tokens=32,
            )
        )
        assert probe.structured_content == {"ok": True}
        pv = provider.value()
        pv["health_status"] = "tested"
        provider.data = canonical(pv)
        model = document(
            db,
            "provider_model",
            FIXTURE_OWNER,
            {
                **ModelInput(
                    model_id="fixture-json", input_price=1, output_price=1
                ).model_dump(),
                "provider_id": provider.id,
                "verified_structured": True,
            },
        )
        campaign = document(
            db,
            "campaign",
            FIXTURE_OWNER,
            {
                "name": "Synthetic deployment validation",
                "mode": "knowledge",
                "authorization_attested": True,
                "authorization_ref": "Local test-only fixtures",
                "budget_limit": 5,
            },
        )
        scope = Scope().model_dump()
        policy = document(
            db, "policy", FIXTURE_OWNER, {"campaign_id": campaign.id, "scope": scope}
        )
        pins = {
            role: {
                "provider_id": provider.id,
                "model_id": model.id,
                "provider_version": 1,
                "model_version": 1,
            }
            for role in ("reasoning", "verifier")
        }
        run = document(
            db,
            "run",
            FIXTURE_OWNER,
            {
                "campaign_id": campaign.id,
                "policy_id": policy.id,
                "policy_hash": digest(canonical(scope)),
                "state": "CREATED",
                "status": "queued",
                "budget_limit": 1,
                "budget_used": 0,
                "models": pins,
                "deadline": time.time() + 1800,
                "started_at": now(),
                "max_model_calls": 20,
                "max_tool_calls": 10,
            },
        )
        db.commit()
        print(json.dumps({"run_id": run.id}))
    else:
        run = db.get(Document, sys.argv[2])
        assert run and run.owner == FIXTURE_OWNER
        v = run.value()
        result = {
            k: v.get(k) for k in ["state", "status", "budget_used", "blocked_reason"]
        }
        stages = [
            d.value()
            for d in db.query(Document).filter_by(kind="stage_result", owner=run.id)
        ]
        result["completed_stages"] = len(stages)
        result["unique_execution_keys"] = len({d["execution_key"] for d in stages})
        if sys.argv[1] == "verify":
            assert v["status"] == "completed", result
            assert len(stages) == len(ORDER) - 1 == result["unique_execution_keys"]
            previous = "0" * 64
            events = (
                db.query(Journal)
                .filter_by(stream=run.id)
                .order_by(Journal.sequence)
                .all()
            )
            for event in events:
                assert event.previous == previous and event.hash == digest(
                    previous + str(event.sequence) + event.payload
                )
                previous = event.hash
            result["journal_verified"] = len(events)
            assert not [
                d
                for d in db.query(Document).filter_by(
                    kind="finding", owner=FIXTURE_OWNER
                )
                if d.value()["run_id"] == run.id
            ]
            with httpx.Client(trust_env=False, timeout=10) as client:
                result["fixture_provider_calls"] = client.get(
                    "http://fixture-provider:9001/fixture-metrics"
                ).json()
        print(json.dumps(result))
