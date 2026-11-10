"""Owner-reviewed fixed HTTP templates, compiled into a narrow Nuclei subset."""

from typing import Literal
import re
import yaml
from pydantic import Field, model_validator

from .db import Document, append, canonical, digest, document
from .policy import Denied, Strict


class Matcher(Strict):
    type: Literal["word", "status"]
    part: Literal["body", "header"] = "body"
    words: list[str] = Field(default=[], max_length=10)
    status: list[int] = Field(default=[], max_length=10)
    condition: Literal["and", "or"] = "and"

    @model_validator(mode="after")
    def bounded(self):
        if any("{{" in word or "}}" in word for word in self.words):
            raise ValueError(
                "Word matchers cannot contain executable template expressions"
            )
        if self.type == "word" and (
            not self.words or any(not w or len(w) > 500 for w in self.words)
        ):
            raise ValueError("Word matchers require bounded nonempty terms")
        if self.type == "status" and (
            not self.status
            or any(type(s) is not int or not 100 <= s <= 599 for s in self.status)
        ):
            raise ValueError("Status matcher requires valid HTTP codes")
        return self


class TemplateInput(Strict):
    template_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,99}$")
    version: str = Field(default="1.0.0", max_length=30)
    name: str = Field(min_length=1, max_length=200)
    source_url: str = Field(min_length=1, max_length=1000)
    license: str = Field(min_length=1, max_length=100)
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    paths: list[str] = Field(min_length=1, max_length=5)
    matchers: list[Matcher] = Field(min_length=1, max_length=5)
    readonly_contract_attested: bool

    @model_validator(mode="after")
    def fixed_requests(self):
        if not self.readonly_contract_attested:
            raise ValueError("A fixed read-only template contract is required")
        for path in self.paths:
            suffix = path.removeprefix("{{BaseURL}}")
            if (
                not path.startswith("{{BaseURL}}")
                or (suffix and not suffix.startswith(("/", "?")))
                or len(path) > 1000
                or "{{" in suffix
                or "}}" in suffix
                or any(ord(c) < 33 for c in path)
            ):
                raise ValueError(
                    "Templates support fixed BaseURL paths only; no raw requests, payload engines, code, out-of-band callbacks or shell"
                )
        return self


def compile_template(spec):
    data = {
        "id": spec.template_id,
        "info": {
            "name": spec.name,
            "author": "ATLAS-reviewed-owner-template",
            "severity": "info",
            "reference": [spec.source_url],
            "description": "Unverified research observation; independent proof/control required.",
        },
        "http": [
            {
                "method": spec.method,
                "path": spec.paths,
                "matchers-condition": "and",
                "matchers": [
                    {
                        "type": m.type,
                        **(
                            {"part": m.part, "words": m.words, "condition": m.condition}
                            if m.type == "word"
                            else {"status": m.status}
                        ),
                    }
                    for m in spec.matchers
                ],
            }
        ],
    }
    return yaml.safe_dump(data, sort_keys=False)


def create(db, owner, spec):
    if (
        sum(
            bool(row.value().get("enabled"))
            for row in db.query(Document).filter_by(
                kind="scanner_template", owner=owner
            )
        )
        >= 20
    ):
        raise Denied(
            "Disable a template before adding more than twenty active templates"
        )
    text = compile_template(spec)
    id = digest(
        "scanner-template:" + owner + ":" + spec.template_id + ":" + spec.version
    )[:36]
    if db.get(Document, id):
        raise Denied("Template version already exists; create a new immutable version")
    row = document(
        db,
        "scanner_template",
        owner,
        {
            "template_id": spec.template_id,
            "version": spec.version,
            "name": spec.name,
            "source_url": spec.source_url,
            "license": spec.license,
            "enabled": True,
            "specification": spec.model_dump(),
            "yaml": text,
            "sha256": digest(text),
        },
        id,
    )
    append(
        db,
        owner,
        owner,
        "scanner_template_registered",
        {
            "id": id,
            "template_id": spec.template_id,
            "version": spec.version,
            "sha256": digest(text),
        },
    )
    return row


def pins(db, owner):
    return [
        {"id": row.id, "version": row.version, "sha256": row.value()["sha256"]}
        for row in db.query(Document).filter_by(kind="scanner_template", owner=owner)
        if row.value().get("enabled")
    ][:20]


def pinned(db, run):
    result = []
    for pin in run.value().get("scanner_template_pins", []):
        row = db.get(Document, pin["id"], populate_existing=True)
        if (
            not row
            or row.owner != run.owner
            or row.kind != "scanner_template"
            or row.version != pin["version"]
            or not row.value().get("enabled")
            or row.value()["sha256"] != pin["sha256"]
            or digest(row.value()["yaml"]) != pin["sha256"]
        ):
            raise Denied("Pinned scanner template was disabled or changed")
        result.append(row)
    return result
