"""Generated Python proof/control harnesses over disposable source copies.

Original snapshots are read-only and never patched. Generated code runs only
inside the existing network-isolated sandbox after explicit offline approval.
"""

import ast
from pathlib import Path
import re
import tempfile

from pydantic import Field, model_validator

from .db import Document, append, canonical, digest, document, now
from .policy import Denied, Strict
from .vault import redact


class Replacement(Strict):
    path: str = Field(max_length=300)
    before: str = Field(min_length=1, max_length=20000)
    after: str = Field(min_length=1, max_length=20000)


class SourceExperiment(Strict):
    claim: str = Field(min_length=10, max_length=500)
    impact: str = Field(min_length=10, max_length=2000)
    proof_code: str = Field(min_length=30, max_length=16000)
    control_code: str = Field(min_length=30, max_length=16000)
    secure_patch: list[Replacement] = Field(min_length=1, max_length=4)
    citations: list[str] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def real_unit_tests(self):
        if len(canonical(self.model_dump())) > 24000:
            raise ValueError(
                "Source experiment must fit a focused 24 KiB review context"
            )
        for code in (self.proof_code, self.control_code):
            try:
                tree = ast.parse(code)
            except SyntaxError:
                raise ValueError("Generated harness is not valid Python") from None
            methods = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
            ]
            if not methods or not any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr.startswith("assert")
                for method in methods
                for node in ast.walk(method)
            ):
                raise ValueError(
                    "Harness requires concrete unittest test methods and assertions"
                )
            if any(
                isinstance(node, ast.Call)
                and (
                    (
                        isinstance(node.func, ast.Name)
                        and node.func.id in ("print", "exit", "quit", "exec", "eval")
                    )
                    or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr
                        in ("exit", "_exit", "skip", "skipIf", "skipUnless")
                    )
                )
                for node in ast.walk(tree)
            ):
                raise ValueError(
                    "Harness cannot forge output, skip tests or terminate the runner"
                )
        return self


def passed(result):
    return (
        result.get("exit_code") == 0
        and not result.get("timed_out")
        and bool(re.search(r"Ran [1-9][0-9]* tests?", result.get("output", "")))
        and "\nOK" in result.get("output", "")
    )


def execute(db, run, repo, spec, record=True):
    from .tools import Repository, ExecutionInput, execute_offline
    from .swarm import check_fence, enqueue

    if not repo or not run.value().get("offline_execution_approved"):
        raise Denied(
            "Generated source experiments require the pinned snapshot and explicit offline approval"
        )
    snapshot = repo.inventory()["snapshot_hash"]
    for patch in spec.secure_patch:
        source = repo.path(patch.path)
        if not source.is_file() or source.stat().st_size > 1024 * 1024:
            raise Denied("Secure-control patch must name a bounded source file")
        if source.read_text().count(patch.before) != 1:
            raise Denied(
                "Secure-control replacement must match one exact source region"
            )
    phases = []
    name = digest(spec.proof_code + spec.control_code)[:12]
    proof_path = "atlas_generated_proof_" + name
    control_path = "atlas_generated_control_" + name
    if (repo.root / proof_path).exists() or (repo.root / control_path).exists():
        raise Denied("Reserved harness path already exists in the source")
    with tempfile.TemporaryDirectory(prefix="atlas-source-experiment-") as temporary:
        root = Path(temporary) / "source"
        root.mkdir()
        files, _ = repo.files()
        for filename in files:
            target = root / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(repo.path(filename).read_bytes())
        for directory, code in (
            (proof_path, spec.proof_code),
            (control_path, spec.control_code),
        ):
            target = root / directory
            target.mkdir()
            (target / "test_generated.py").write_text(code)
        scratch = Repository(root)
        for phase, path in [
            ("original_proof", proof_path),
            ("original_control", control_path),
            ("patched_proof", proof_path),
            ("patched_control", control_path),
        ]:
            if phase == "patched_proof":
                for patch in spec.secure_patch:
                    target = scratch.path(patch.path)
                    target.write_text(
                        target.read_text().replace(patch.before, patch.after, 1)
                    )
            check_fence(db, run)
            import time

            remaining = run.value()["deadline"] - time.time()
            if remaining <= 0:
                raise Denied("Run deadline exhausted before source reproduction")
            result = execute_offline(
                scratch,
                ExecutionInput(template="python_unittest", test_path=path),
                timeout=min(30, remaining),
            )
            check_fence(db, run)
            artifact = document(
                db,
                "artifact",
                run.owner,
                {
                    "run_id": run.id,
                    "campaign_id": run.value()["campaign_id"],
                    "task_id": getattr(run, "_swarm_claim", (None, None))[0],
                    "tool_name": "source.experiment." + phase,
                    "tool_version": "1",
                    "sha256": digest(canonical(result)),
                    "media_type": "application/json",
                    "payload": result,
                    "sensitivity": "campaign_private",
                },
            )
            phases.append(
                {"phase": phase, "artifact_id": artifact.id, "result": result}
            )
            db.commit()
    if repo.inventory()["snapshot_hash"] != snapshot:
        raise Denied("Original snapshot changed; no experiment result can be promoted")
    by_phase = {p["phase"]: p["result"] for p in phases}
    failed_proof = by_phase["patched_proof"]
    contrast = (
        failed_proof.get("exit_code") not in (0, None)
        and not failed_proof.get("timed_out")
        and bool(
            re.search(
                r"FAILED \(failures=[1-9][0-9]*\)", failed_proof.get("output", "")
            )
        )
    )
    candidate = (
        passed(by_phase["original_proof"])
        and passed(by_phase["original_control"])
        and contrast
        and passed(by_phase["patched_control"])
    )
    result = {
        "candidate": bool(candidate),
        "snapshot": snapshot,
        "proof_ids": [p["artifact_id"] for p in phases[:2]],
        "control_ids": [p["artifact_id"] for p in phases[2:]],
        "phases": phases,
        "proof_code_sha256": digest(spec.proof_code),
        "control_code_sha256": digest(spec.control_code),
        "secure_patch_sha256": digest(
            canonical([p.model_dump() for p in spec.secure_patch])
        ),
    }
    if candidate and record:
        id = digest("source-experiment:" + run.id + canonical(spec.model_dump()))[:36]
        if not db.get(Document, id):
            row = document(
                db,
                "source_candidate",
                run.owner,
                {
                    "run_id": run.id,
                    "campaign_id": run.value()["campaign_id"],
                    "specification": spec.model_dump(),
                    "research_result": result,
                    "status": "candidate",
                    "created_at": now(),
                },
                id,
            )
            enqueue(
                db,
                run,
                "source-verification",
                {
                    "candidate_id": row.id,
                    "reason": "Fresh independent source harness and secure-patch replay",
                },
                digest("source-verify:" + id),
            )
            from .swarm import Discovery, publish_current

            publish_current(
                db,
                run,
                Discovery(
                    kind="hypothesis",
                    topic="general",
                    title=spec.claim[:200],
                    text=(
                        spec.claim
                        + "; source experiment requires independent validation"
                    )[:2000],
                    citations=result["proof_ids"] + result["control_ids"],
                    confidence=0.8,
                ),
            )
        result["candidate_id"] = id
    return result


def verify(db, run, repo, task):
    import json
    from .workflow import role, VerificationOutput

    row = db.get(Document, json.loads(task.payload)["candidate_id"])
    if (
        not row
        or row.kind != "source_candidate"
        or row.owner != run.owner
        or row.value()["run_id"] != run.id
    ):
        raise Denied("Invalid source candidate provenance")
    spec = SourceExperiment.model_validate(row.value()["specification"])
    fresh = execute(db, run, repo, spec, record=False)
    if not fresh["candidate"]:
        value = row.value()
        value.update(status="refuted", independent_result=fresh)
        row.data = canonical(value)
        return {
            "status": "refuted",
            "candidate_id": row.id,
            "reason": "Fresh source proof/control contrast failed",
        }
    evidence = fresh["proof_ids"] + fresh["control_ids"]
    source = []
    for patch in spec.secure_patch:
        text = repo.path(patch.path).read_text()
        offset = text.index(patch.before)
        source.append(
            {
                "path": patch.path,
                "verified_original_region": patch.before,
                "surrounding_source": redact(
                    text[
                        max(0, offset - 500) : offset
                        + min(len(patch.before), 1500)
                        + 500
                    ]
                ),
            }
        )
    review_evidence = {
        **fresh,
        "phases": [
            {
                **phase,
                "result": {
                    **phase["result"],
                    "output": phase["result"].get("output", "")[:1500],
                },
            }
            for phase in fresh["phases"]
        ],
    }
    response = role(
        db,
        run,
        "INDEPENDENT_SOURCE_EXPERIMENT",
        {
            "claim": spec.claim,
            "impact": spec.impact,
            "original_source": source,
            "generated_proof": spec.proof_code,
            "functional_control": spec.control_code,
            "secure_patch": [p.model_dump() for p in spec.secure_patch],
            "fresh_evidence": review_evidence,
            "expected_evidence_ids": evidence,
            "instruction": "Challenge whether tests demonstrate the claimed security invariant rather than assertions manufactured to pass. The vulnerable assertion must pass originally, fail by assertion on the secure patch, and legitimate functionality must pass both. Confirm only with exact fresh artifact IDs and a justified secure counterfactual.",
        },
        "verifier",
        response_schema=VerificationOutput,
    )
    status = response.status
    if status == "confirmed" and (
        set(response.evidence_ids) != set(evidence) or not response.counterfactual
    ):
        status = "inconclusive"
    key = digest(
        canonical(
            {
                "campaign": run.value()["campaign_id"],
                "snapshot": fresh["snapshot"],
                "claim": spec.claim,
            }
        )
    )
    review = document(
        db,
        "verification_review",
        run.owner,
        {
            "run_id": run.id,
            "candidate_id": row.id,
            "model_review": response.model_dump(),
            "expected_evidence_ids": evidence,
            "effective_status": status,
            "finding_confirmed": status == "confirmed",
        },
    )
    from .finding_reviews import matching_findings, record_duplicate

    prior = matching_findings(db, run, key)
    old = next((f for f in prior if f.value().get("status") == "confirmed"), None)
    if status == "confirmed" and old:
        return record_duplicate(
            db, run, old, row, fresh, review, "independent-source-verifier"
        )
    finding = document(
        db,
        "finding",
        run.owner,
        {
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "title": spec.claim,
            "status": status,
            "severity": "unscored",
            "vulnerability_class": "source_invariant",
            "asset": "source:" + fresh["snapshot"],
            "endpoint": None,
            "parameter_or_component": ",".join(p.path for p in spec.secure_patch),
            "technical_explanation": response.reason,
            "impact": spec.impact,
            "hypothesis": {
                "claim": spec.claim,
                "impact": spec.impact,
                "preconditions": ["Pinned source and approved offline execution"],
                "citations": spec.citations,
            },
            "reproduction_steps": {
                "capability": "source.experiment",
                "input": spec.model_dump(),
            },
            "verification": {**response.model_dump(), "status": status},
            "evidence_ids": evidence,
            "source_references": spec.citations,
            "discovery_agent": "source-research",
            "validation_agent": "independent-source-verifier",
            "related_findings": [f.id for f in prior],
            "independent_review_ids": [review.id],
            "timeline": [
                {"at": now(), "actor": "independent-source-verifier", "status": status}
            ],
            "root_cause_key": key,
            "policy_hash": run.value()["policy_hash"],
        },
    )
    value = row.value()
    value.update(
        status=status,
        finding_id=finding.id,
        independent_result=fresh,
        review_id=review.id,
    )
    row.data = canonical(value)
    append(
        db,
        run.id,
        "independent-source-verifier",
        "source_experiment_reviewed",
        {"finding_id": finding.id, "review_id": review.id, "status": status},
        run.value()["campaign_id"],
    )
    return {"status": status, "finding_id": finding.id}
