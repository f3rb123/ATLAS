"""Evidence-preserving deterministic report renderers; never render untrusted HTML."""

import json, html
from .db import Document, document, canonical, now
from . import __version__


def render(findings, format):
    if format == "json":
        return canonical(
            {
                "schema": "atlas-finding-report",
                "version": "1.0",
                "generated_at": now(),
                "findings": findings,
            }
        )
    if format == "sarif":
        return canonical(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "SKUNK", "version": __version__}},
                        "results": [
                            {
                                "ruleId": "ATLAS.evidence-confirmed",
                                "message": {"text": f["title"]},
                                "level": "warning",
                                "properties": {
                                    "verification": f["verification"],
                                    "evidence_ids": f["evidence_ids"],
                                },
                            }
                            for f in findings
                        ],
                    }
                ],
            }
        )
    lines = [
        "# SKUNK evidence report",
        "Generated " + now(),
        "Only confirmed findings are included. Severity is unscored unless reviewed.",
    ]
    for f in findings:
        lines += [
            "\n## " + f["title"],
            "Status: " + f["status"],
            "Policy: " + f["policy_hash"],
            "\nClaimed impact: " + f["hypothesis"]["impact"],
            "\nVerification: " + f["verification"]["reason"],
            "\nSecure counterfactual: " + f["verification"]["counterfactual"],
            "Evidence: " + ", ".join(f["evidence_ids"]),
            "\nReproduction and preconditions:\n"
            + json.dumps(f["hypothesis"], indent=2),
        ]
    text = "\n\n".join(lines)
    if format == "html":
        return (
            '<!doctype html><html><meta charset="utf-8"><title>SKUNK report</title><body><pre>'
            + html.escape(text)
            + "</pre></body></html>"
        )
    if format == "pdf":
        import io, base64
        from reportlab.platypus import SimpleDocTemplate, Preformatted
        from reportlab.lib.styles import getSampleStyleSheet
        from xml.sax.saxutils import escape

        output = io.BytesIO()
        SimpleDocTemplate(output).build(
            [
                Preformatted(
                    escape(text), getSampleStyleSheet()["Code"], maxLineLength=90
                )
            ]
        )
        return base64.b64encode(output.getvalue()).decode()
    if format != "markdown":
        raise ValueError("Unsupported report format")
    return text


def generate_report(db, run, format):
    findings = [
        f.value()
        for f in db.query(Document).filter_by(kind="finding", owner=run.owner)
        if f.value()["run_id"] == run.id
        and f.value()["status"]
        in ("confirmed", "report_ready", "reported", "fixed", "closed")
        and f.value().get("verification", {}).get("status") == "confirmed"
    ]
    coverage = {
        "partial": bool(run.value().get("partial")),
        "task_errors": run.value().get("task_errors", 0),
        "tool_warnings": run.value().get("tool_warnings", []),
        "http_and_network_requests": run.value().get("http_requests", 0),
        "policy_hash": run.value().get("policy_hash", "unavailable"),
        "note": "A completed run is bounded research over the captured surface, not proof that every vulnerability was found.",
    }
    unverified = []
    if run.value().get("harness") == "skunk/1":
        from .skunk_evidence import leads, coverage_notes
        unverified = leads(db, run)
        coverage["limitations"] = coverage_notes(db, run)
        coverage["unverified_lead_count_in_report"] = len(unverified)
        coverage["resume_cycle"] = run.value().get("resume_cycle", 0)
        coverage["partial"] |= bool(coverage["limitations"])
    content = render(findings, format)
    details = "# Run coverage\n\n" + json.dumps(coverage, indent=2)
    if unverified:
        details += "\n\n# Unverified leads\n\nThese are research hypotheses, not confirmed vulnerabilities. Independent proof and a secure control are still required.\n\n"
        details += "\n\n".join("\n".join("    " + line for line in json.dumps(lead, ensure_ascii=False, indent=2).splitlines()) for lead in unverified)
    if format == "markdown":
        content = details + "\n\n" + content
    if format == "html":
        content = content.replace("<body>", "<body><pre>" + html.escape(details) + "</pre>", 1)
    if format == "json":
        parsed = json.loads(content)
        parsed["coverage"] = coverage
        parsed["unverified_leads"] = unverified
        content = canonical(parsed)
    return document(
        db,
        "report",
        run.owner,
        {
            "run_id": run.id,
            "format": format,
            "content": content,
            "coverage": coverage,
            "unverified_lead_count": len(unverified),
            "confirmed_count": len(findings),
        },
    )
