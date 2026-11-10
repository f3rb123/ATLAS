"""Durable operator conversation and execution preferences, without inferred scope."""

from typing import Literal
import re

from pydantic import Field

from .db import Document, append, canonical, document, now
from .policy import Denied, Scope, Strict, match, normalize
from .vault import redact
from .web_research import WebPlan


class EngagementInput(Strict):
    name: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=1, max_length=4096)
    authorization_ref: str = Field(min_length=1, max_length=2000)
    authorization_attested: bool
    instructions: str = Field(min_length=1, max_length=4000)
    scope: Scope
    assessment_profile: Literal["standard", "smoke_readonly"] = "standard"
    budget_limit: float = Field(default=1, gt=0, le=100)


class Preferences(Strict):
    agent_count: int = Field(default=8, ge=1, le=16)
    model_mode: Literal["single", "capability", "auto"] = "capability"
    max_seconds: int = Field(default=1800, ge=30, le=86400)
    max_model_calls: int = Field(default=30, ge=1, le=100)
    max_tool_calls: int = Field(default=50, ge=1, le=500)
    repository_id: str | None = None
    offline_execution_approved: bool = False
    web: WebPlan = Field(default_factory=lambda: WebPlan(enabled=True))


class Message(Strict):
    text: str = Field(min_length=1, max_length=4000)


def validate_target(body):
    normalized, hostname, port, path, scheme = normalize(body.target_url)
    if any(
        match(r, hostname, port, path, scheme, "HEAD") for r in body.scope.deny
    ) or not any(
        match(r, hostname, port, path, scheme, "HEAD") for r in body.scope.allow
    ):
        raise Denied(
            "The exact target must match the explicit scope before creating an engagement"
        )
    return normalized


def messages(db, campaign):
    return [
        row
        for row in db.query(Document)
        .filter_by(kind="engagement_message", owner=campaign.owner)
        .filter(Document.data.contains('"campaign_id":"' + campaign.id + '"'))
        .order_by(Document.created)
        .limit(100)
        if row.value().get("campaign_id") == campaign.id
    ]


def save_message(db, campaign, text, actor):
    from .db import transaction_lock

    transaction_lock(db, "engagement:" + campaign.id)
    if not campaign.value().get("engagement"):
        raise Denied("Conversation requires an engagement")
    if len(messages(db, campaign)) >= 100:
        raise Denied(
            "Conversation is limited to 100 messages; use a new engagement for a new research objective"
        )
    row = document(
        db,
        "engagement_message",
        campaign.owner,
        {
            "campaign_id": campaign.id,
            "role": "operator",
            "author": actor,
            "text": redact(text),
            "created_at": now(),
            "scope_authority": False,
            "execution": "Saved for the next run; active runs retain their original instructions",
        },
    )
    append(db, campaign.id, actor, "engagement_message_saved", {"message_id": row.id})
    return row


def run_instructions(db, campaign):
    # A bounded, visible snapshot. Chat messages cannot modify policy or budgets.
    parts = [row.value()["text"] for row in messages(db, campaign)]
    return "\n\n".join(parts)[-4000:]


def source_only_instructions(text):
    return bool(
        re.search(
            r"(?i)\b(?:no live (?:target )?(?:requests|traffic)|source[- ]only|offline[- ]only)\b",
            text,
        )
    )


def save_preferences(db, campaign, preferences, actor):
    value = campaign.value()
    if not value.get("engagement"):
        raise Denied("Execution preferences require an engagement")
    if preferences.repository_id:
        repo = db.get(Document, preferences.repository_id)
        if (
            not repo
            or repo.kind != "repository"
            or repo.owner != campaign.owner
            or repo.value().get("campaign_id") != campaign.id
        ):
            raise Denied("Source snapshot must belong to this engagement")
    value["execution_preferences"] = preferences.model_dump()
    campaign.data = canonical(value)
    append(
        db, campaign.id, actor, "engagement_preferences_saved", preferences.model_dump()
    )
    return preferences.model_dump()
