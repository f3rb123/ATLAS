"""Strict versioned research artifacts, not authorization policy."""

from pydantic import Field
from .policy import Strict


class ThreatModel(Strict):
    protected_assets: list[str] = []
    attacker_model: str
    entry_points: list[str] = []
    trust_boundaries: list[str] = []
    identities: list[str] = []
    security_invariants: list[str] = []
    assumptions: list[str] = []
    prohibited_actions: list[str] = []
    unknowns: list[str] = []
    citations: list[str] = []


class ResearchSlice(Strict):
    title: str
    description: str
    paths_or_endpoints: list[str]
    boundary: str
    invariant: str
    reason: str
    priority: int = Field(ge=1, le=10)
    evidence: list[str] = []
    expected_effort: str = "unknown"
    risk_class: str = "read_only"
