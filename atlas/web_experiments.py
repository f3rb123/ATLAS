"""Typed HTTP proof/control experiments; no executable model code or shell."""

from typing import Literal
from pydantic import Field, model_validator

from .db import Document, canonical, digest, document, now
from .policy import Denied, Strict, authorize
from .web_research import WebRequest, scope_for, send


class Assertion(Strict):
    kind: Literal[
        "status", "body_contains", "body_absent", "header_equals", "header_absent"
    ]
    value: str | int
    header: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def bounded(self):
        if self.kind == "status":
            if type(self.value) is not int or not 100 <= self.value <= 599:
                raise ValueError("Status assertion requires a valid status code")
        elif not isinstance(self.value, str) or not 1 <= len(self.value) <= 300:
            raise ValueError("Evidence assertions require a bounded nonempty value")
        if self.kind.startswith("header") and (
            not self.header
            or self.header.lower() in ("set-cookie", "cookie", "authorization")
        ):
            raise ValueError("Header assertion requires a non-secret header")
        return self


class ExpectedRequest(Strict):
    request: WebRequest
    assertions: list[Assertion] = Field(min_length=1, max_length=5)


class HTTPExperiment(Strict):
    claim: str = Field(min_length=10, max_length=500)
    impact: str = Field(min_length=10, max_length=1500)
    vulnerability_class: Literal[
        "authorization",
        "redirect",
        "information_disclosure",
        "input_handling",
        "cache_policy",
    ]
    proof: list[ExpectedRequest] = Field(min_length=1, max_length=3)
    control: list[ExpectedRequest] = Field(min_length=1, max_length=3)
    contrast: Literal["status_differs", "body_differs", "header_differs"]
    contrast_header: str | None = Field(default=None, max_length=100)
    reasoning: str = Field(min_length=20, max_length=2000)


def matches(response, assertion):
    if assertion.kind == "status":
        return response["status"] == assertion.value
    if assertion.kind == "body_contains":
        return assertion.value in response["body"]
    if assertion.kind == "body_absent":
        return assertion.value not in response["body"]
    if assertion.kind == "header_equals":
        return response["headers"].get(assertion.header.lower()) == assertion.value
    if assertion.kind == "header_absent":
        return assertion.header.lower() not in response["headers"]
    return False


def execute(db, run, experiment, record=True):
    scope = scope_for(db, run)
    if (
        "differential" not in scope.test_classes
        or run.value().get("assessment_profile") == "smoke_readonly"
    ):
        raise Denied("Differential experiments are outside the frozen campaign policy")
    signatures = [
        canonical(item.request.model_dump())
        for item in experiment.proof + experiment.control
    ]
    if set(signatures[: len(experiment.proof)]) & set(
        signatures[len(experiment.proof) :]
    ):
        raise Denied(
            "Secure controls must use independently specified distinct requests"
        )
    for item in experiment.proof + experiment.control:
        authorize(scope, item.request.url, item.request.method)
    observations = [
        send(db, run, item.request, "web-experiment")
        for item in experiment.proof + experiment.control
    ]
    passed = all(
        all(matches(response, assertion) for assertion in expected.assertions)
        for response, expected in zip(
            observations, experiment.proof + experiment.control
        )
    )
    proof = observations[: len(experiment.proof)]
    control = observations[len(experiment.proof) :]
    if experiment.contrast == "status_differs":
        contrast = proof[0]["status"] != control[0]["status"]
    elif experiment.contrast == "body_differs":
        contrast = proof[0]["body_sha256"] != control[0]["body_sha256"]
    else:
        if not experiment.contrast_header:
            raise Denied("A specific non-secret contrast header is required")
        header = experiment.contrast_header.lower()
        if header in ("authorization", "cookie", "set-cookie"):
            raise Denied("Credentials cannot be evidence assertions")
        contrast = proof[0]["headers"].get(header) != control[0]["headers"].get(header)
    result = {
        "kind": "differential",
        "candidate": bool(passed and contrast),
        "claim": experiment.claim,
        "impact": experiment.impact,
        "vulnerability_class": experiment.vulnerability_class,
        "url": experiment.proof[0].request.url,
        "proof_ids": [p["observation_id"] for p in proof],
        "control_ids": [c["observation_id"] for c in control],
        "assertions_passed": passed,
        "contrast_passed": contrast,
        "reasoning": experiment.reasoning,
        "responses": [
            {
                "id": o["observation_id"],
                "status": o["status"],
                "body_sha256": o["body_sha256"],
            }
            for o in observations
        ],
    }
    if result["candidate"] and record:
        from .swarm import enqueue

        spec = experiment.model_dump()
        id = digest("http-experiment:" + run.id + canonical(spec))[:36]
        if not db.get(Document, id):
            row = document(
                db,
                "web_candidate",
                run.owner,
                {
                    "run_id": run.id,
                    "campaign_id": run.value()["campaign_id"],
                    "check": {"kind": "differential", "input": spec},
                    "research_result": result,
                    "status": "candidate",
                    "created_at": now(),
                },
                id,
            )
            enqueue(
                db,
                run,
                "web-verification",
                {
                    "candidate_id": row.id,
                    "reason": "Independent HTTP proof/control and claim challenge",
                },
                digest("web-verify:" + id),
            )
        result["candidate_id"] = id
    return result
