"""Attributed research notes and explicit unverified attack-chain relationships."""

from typing import Literal

from pydantic import Field

from .db import Document, append, canonical, digest, document, now
from .policy import Denied, Strict
from .vault import redact


class ResearchNote(Strict):
    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=12000)
    status: Literal["proposed", "refuted"] = "proposed"
    citations: list[str] = Field(default_factory=list, max_length=20)
    competing_explanations: list[str] = Field(default_factory=list, max_length=8)
    missing_information: list[str] = Field(default_factory=list, max_length=12)
    next_steps: list[str] = Field(default_factory=list, max_length=8)


class ChainLink(Strict):
    source_id: str = Field(max_length=36)
    target_id: str = Field(max_length=36)
    relationship: Literal["enables", "depends_on", "shares_root_cause", "contradicts"]
    rationale: str = Field(min_length=1, max_length=4000)
    citations: list[str] = Field(default_factory=list, max_length=20)
    preconditions: list[str] = Field(default_factory=list, max_length=12)


def store_note(db, run, note, actor):
    content = __import__("json").loads(redact(canonical(note.model_dump())))
    row = document(
        db,
        "research_note",
        run.owner,
        {
            **content,
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "task_id": getattr(run, "_swarm_claim", (None, None))[0],
            "created_at": now(),
            "source": "attributed_unverified_research",
            "author": actor,
            "finding_confirmed": False,
        },
    )
    append(
        db,
        run.id,
        actor,
        "research_note_created",
        {"note_id": row.id, "citations": content["citations"]},
        run.value()["campaign_id"],
    )
    return {"note_id": row.id, "status": note.status, "finding_confirmed": False}


def link_chain(db, run, link, actor):
    if link.source_id == link.target_id:
        raise Denied("Attack-chain endpoints must differ")
    for id in (link.source_id, link.target_id):
        row = db.get(Document, id)
        if (
            not row
            or row.owner != run.owner
            or row.kind not in ("finding", "hypothesis")
            or row.value().get("run_id") != run.id
        ):
            raise Denied(
                "Attack-chain endpoints must be owned hypotheses/findings in this run"
            )
    id = digest(
        "chain:" + run.id + link.source_id + link.relationship + link.target_id
    )[:36]
    row = db.get(Document, id)
    if not row:
        row = document(
            db,
            "attack_chain",
            run.owner,
            {
                **__import__("json").loads(redact(canonical(link.model_dump()))),
                "run_id": run.id,
                "campaign_id": run.value()["campaign_id"],
                "author": actor,
                "task_id": getattr(run, "_swarm_claim", (None, None))[0],
                "created_at": now(),
                "status": "unverified_relationship",
                "finding_confirmed": False,
                "validation_requirement": "Individual findings and the combined preconditions require independent evidence",
            },
            id,
        )
        append(
            db,
            run.id,
            actor,
            "attack_chain_linked",
            {
                "relationship_id": id,
                "source_id": link.source_id,
                "target_id": link.target_id,
            },
            run.value()["campaign_id"],
        )
    return {
        "relationship_id": row.id,
        "status": row.value()["status"],
        "finding_confirmed": False,
    }
