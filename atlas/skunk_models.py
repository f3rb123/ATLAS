"""Host-configured models validated on their actual work, never by fabricated probes."""

from .db import canonical, document, digest, now
from .skunk_prompts import BASE_URL, MODELS


def runtime_contract(provider, model, run=None):
    p, m = provider.value(), model.value()
    return bool(
        p.get("managed_by") == "skunk-cli"
        and p.get("base_url", "").rstrip("/") == BASE_URL
        and m.get("model_id") in set(MODELS.values())
        and m.get("runtime_schema_validation") is True
        and (run is None or run.value().get("harness") == "skunk/1")
    )


def record_valid_response(db, provider, model, run):
    if not runtime_contract(provider, model, run):
        return
    value = model.value()
    if value.get("verified_structured"):
        return
    value.update(verified_structured=True, capability_status="schema_validated_during_run", last_validated=now())
    model.data = canonical(value)
    value = provider.value()
    value.update(health_status="runtime_validated", last_validated=now())
    provider.data = canonical(value)
    document(db, "runtime_model_validation", run.owner, {
        "run_id": run.id, "model_id": model.id,
        "evidence": "An accounted work response passed the exact role schema",
        "synthetic_probe": False,
    })


def configure(db, owner, key):
    from .gateway import ProviderInput, ModelInput, create_provider, secret_identity
    from .db import Document
    from .vault import open_secret
    import hmac

    provider_id = digest("skunk-provider:" + owner.id + ":" + digest(key))[:36]
    provider = db.get(Document, provider_id)
    if provider is None:
        provider = create_provider(db, owner.id, ProviderInput(
            display_name="HackerAI", adapter_type="custom_openai_compatible",
            base_url=BASE_URL, api_key=key,
        ), id=provider_id)
        value = provider.value()
        value.update(managed_by="skunk-cli", health_status="configured")
        provider.data = canonical(value)
    else:
        value = provider.value()
        if not hmac.compare_digest(open_secret(value["secret"], secret_identity(owner.id, provider.id, value)), key):
            raise ValueError("Managed provider credential identity mismatch")
    rows = {}
    for remote in set(MODELS.values()):
        identity = digest("skunk-model:" + provider_id + ":" + remote)[:36]
        row = db.get(Document, identity)
        if row is None:
            spec = ModelInput(model_id=remote, display_name=remote, context_window=64000,
                              max_output_tokens=4096, capabilities={"structured": True},
                              pricing_status="unverified")
            row = document(db, "provider_model", owner.id, {
                **spec.model_dump(), "provider_id": provider.id,
                "verified_structured": False, "verified_tools": False,
                "runtime_schema_validation": True, "capability_status": "configured_not_probed",
            }, identity)
        rows[remote] = row
    assignments = {**MODELS, "reasoning": MODELS["classifier"], "fast": MODELS["recon"],
                   "coding": MODELS["classifier"], "verifier": MODELS["exploit"],
                   "deep_research": MODELS["orchestrator"]}
    for alias, remote in assignments.items():
        identity = digest("skunk-alias:" + owner.id + ":" + alias)[:36]
        row = db.get(Document, identity) or document(db, "alias", owner.id, {}, identity)
        row.data = canonical({"alias": alias, "provider_id": provider.id, "model_id": rows[remote].id})
    db.commit()
    return provider
