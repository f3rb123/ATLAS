"""Policy-reviewed acquisition, canonical conversion, durable ingest and citation retrieval."""

import csv, hashlib, io, json, math, re, tarfile, time, zipfile, urllib.request
from pathlib import Path
from collections import Counter
import numpy as np
from sqlalchemy import func
from .db import (
    Knowledge,
    Alias,
    Chunk,
    Document,
    session,
    document,
    canonical,
    digest,
    uid,
    now,
)
from .records import Record, Source
from .config import settings
from .vault import redact


class WithdrawnRecord(ValueError):
    def __init__(self, record_id):
        self.record_id = record_id
        super().__init__("Source withdrew this record")


SOURCES = {
    "ghsa": {
        "name": "GitHub Advisory Database",
        "url": "https://github.com/github/advisory-database",
        "terms": "https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md",
        "license": "CC-BY-4.0",
        "policy": "allowed",
        "bulk": "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main",
    },
    "cve": {
        "name": "CVE Program",
        "url": "https://github.com/CVEProject/cvelistV5",
        "terms": "https://www.cve.org/Legal/TermsOfUse",
        "license": "LicenseRef-CVE-Terms",
        "policy": "allowed",
        "bulk": "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main",
    },
    "nvd": {
        "name": "NVD",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "terms": "https://www.nist.gov/copyrights-disclaimers",
        "license": "LicenseRef-NIST-PublicInformation",
        "policy": "allowed",
    },
    "osv": {
        "name": "OSV",
        "url": "https://api.osv.dev/v1/vulns",
        "terms": "https://osv.dev/docs/",
        "license": "upstream-dependent",
        "policy": "unknown_or_restricted",
    },
    "kev": {
        "name": "CISA KEV",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "terms": "https://github.com/cisagov/kev-data#licensing",
        "license": "CC0-1.0",
        "policy": "allowed",
        "official_mirror": "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    },
}

from .embeddings import embed, embed_many, embedding_version, split_text, dimension


def source_config(source):
    cfg = dict(SOURCES[source])
    with session() as db:
        for d in (
            db.query(Document)
            .filter_by(kind="source_policy")
            .order_by(Document.created)
        ):
            v = d.value()
            if v.get("native_source") == source:
                cfg.update(
                    license=v["license"],
                    terms=v["terms_url"],
                    policy="allowed"
                    if v.get("enabled") and v.get("owner_reviewed")
                    else "unknown_or_restricted",
                    operator_disabled=not v.get("enabled"),
                )
    return cfg


def source_record(source, item, raw, url=None):
    cfg = source_config(source)
    if (
        source == "osv"
        and item.get("id", "").startswith("GHSA-")
        and not cfg.get("operator_disabled")
    ):
        cfg.update(
            license=SOURCES["ghsa"]["license"],
            terms=SOURCES["ghsa"]["terms"],
            policy="allowed",
        )
    aliases = []
    title = ""
    summary = ""
    kind = "security_advisory"
    published = None
    target = {}
    classification = {}
    research = {}
    if source in ("ghsa", "osv"):
        native = item["id"]
        aliases = list(set([native] + item.get("aliases", [])))
        title = item.get("summary") or native
        summary = item.get("details", "")
        published = item.get("published")
        kind = "ghsa" if source == "ghsa" else "osv"
        affected = item.get("affected", [])
        if affected:
            a = affected[0]
            pkg = a.get("package", {})
            target = {
                "ecosystem": pkg.get("ecosystem"),
                "package": pkg.get("name"),
                "affected_versions": a.get("versions", []),
                "fixed_versions": [
                    e["fixed"]
                    for r in a.get("ranges", [])
                    for e in r.get("events", [])
                    if "fixed" in e
                ],
            }
        classification["cwe"] = item.get("database_specific", {}).get("cwe_ids", [])
        classification["severity_label"] = item.get("database_specific", {}).get(
            "severity"
        )
        refs = [r["url"] for r in item.get("references", []) if r.get("type") == "FIX"]
        research["patch_references"] = refs
        if item.get("withdrawn"):
            raise WithdrawnRecord(native)
    elif source == "cve":
        meta = item["cveMetadata"]
        native = meta["cveId"]
        if meta.get("state") != "PUBLISHED":
            raise ValueError("CVE not published")
        aliases = [native]
        cna = item["containers"]["cna"]
        title = cna.get("title") or native
        summary = "\n".join(
            d["value"]
            for d in cna.get("descriptions", [])
            if d.get("lang", "").startswith("en")
        )
        published = meta.get("datePublished")
        kind = "cve"
        a = next(iter(cna.get("affected", [])), {})
        target = {
            "vendor": a.get("vendor"),
            "product": a.get("product"),
            "affected_versions": a.get("versions", []),
        }
        classification["cwe"] = [
            d["cweId"]
            for p in cna.get("problemTypes", [])
            for d in p.get("descriptions", [])
            if d.get("cweId")
        ]
    elif source == "nvd":
        c = item.get("cve", item)
        native = c["id"]
        aliases = [native]
        title = native
        summary = "\n".join(
            d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"
        )
        published = c.get("published")
        kind = "cve"
    elif source == "kev":
        native = item["cveID"]
        aliases = [native]
        title = item["vulnerabilityName"]
        summary = item["shortDescription"]
        research["remediation"] = item.get("requiredAction")
        target = {"vendor": item.get("vendorProject"), "product": item.get("product")}
    else:
        raise ValueError("Unknown structured adapter")
    classification.update(
        cve=[a for a in aliases if a.startswith("CVE-")],
        ghsa=[a for a in aliases if a.startswith("GHSA-")],
        osv=[a for a in aliases if not a.startswith(("CVE-", "GHSA-"))],
    )
    key = next(iter(sorted(classification["cve"])), native)
    url = url or (
        f"https://github.com/advisories/{native}"
        if source == "ghsa"
        else cfg["url"] + "/" + native
    )
    published_date = None
    if published:
        from datetime import datetime, timezone

        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
            published_date = published
            published = None
        else:
            date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if date.tzinfo is None:
                date = date.replace(
                    tzinfo=timezone.utc
                )  # official native adapters define UTC timestamps
            published = date.astimezone(timezone.utc).isoformat()
    r = Record(
        canonical_key=key,
        record_type=kind,
        title=title,
        summary=redact(summary),
        source=Source(
            source_id=source,
            source_name=cfg["name"],
            source_url=url,
            source_record_id=native,
            published_at=published,
            published_date=published_date,
            date_precision="timestamp"
            if published
            else "date"
            if published_date
            else "unknown",
            terms_url=cfg["terms"],
            license=cfg["license"],
            full_text_policy=cfg["policy"],
            content_hash_sha256=digest(raw),
            parser_name=source + "-v1",
        ),
        target=target,
        classification=classification,
        research=research,
        deduplication={"source_aliases": aliases},
    )
    if r.summary != summary:
        r.content.redaction_status = "redacted"
    return r


def store_raw(raw):
    h = digest(raw)
    p = Path(settings().data_dir) / "corpus_raw" / h[:2] / h
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not p.exists():
        p.write_bytes(raw)
        p.chmod(0o600)
    return str(p)


def category(r):
    return (
        "full_text_research_reports"
        if r.record_type in ("research_report", "bug_bounty_disclosure")
        else "patch_and_commit_records"
        if r.record_type == "patch_analysis"
        else "training_and_reference_resources"
        if r.record_type == "training_reference"
        else "structured_vulnerability_advisories"
    )


def ingest(db, r, raw):
    # Raw artifact retained only under explicit permission, before publication.
    if r.source.full_text_policy not in ("allowed", "derived_only"):
        raise ValueError("Full-text permission requires review")
    aliases = set(r.deduplication.source_aliases + [r.canonical_key])
    matches = db.query(Alias).filter(Alias.alias.in_(aliases)).all()
    roots = sorted({a.record_id for a in matches})
    existing = (
        db.get(Knowledge, roots[0])
        if roots
        else db.query(Knowledge)
        .filter_by(content_hash=r.source.content_hash_sha256, owner=r.access_owner)
        .first()
    )
    # Official alias bridges collapse identity groups, preserving every source version.
    for id in roots[1:]:
        old = db.get(Knowledge, id)
        if old.owner != r.access_owner:
            raise ValueError("Cross-owner alias collision")
        document(
            db,
            "corpus_provenance",
            existing.id,
            {
                "record": json.loads(old.record),
                "duplicate_of": existing.id,
                "reason": "official_alias_bridge",
            },
        )
        db.query(Alias).filter_by(record_id=id).update({"record_id": existing.id})
        db.query(Chunk).filter_by(record_id=id).delete()
        db.delete(old)
        db.flush()
    if existing:
        for a in aliases:
            if not db.get(Alias, a):
                db.add(Alias(alias=a, record_id=existing.id))
        # Preserve all source versions/provenance as linked artifacts, not independent records.
        link_id = digest(r.source.source_id + ":" + r.source.content_hash_sha256)[:36]
        if not db.get(Document, link_id):
            document(
                db,
                "corpus_provenance",
                existing.id,
                {"source": r.source.model_dump(), "raw": store_raw(raw)},
                link_id,
            )
        old_record = Record.model_validate_json(existing.record)
        if (
            old_record.source.source_id == r.source.source_id
            and old_record.source.source_record_id == r.source.source_record_id
            and old_record.source.content_hash_sha256 != r.source.content_hash_sha256
        ):
            document(
                db,
                "corpus_provenance",
                existing.id,
                {
                    "record": old_record.model_dump(by_alias=True),
                    "reason": "source_revision",
                },
            )
            r.record_id = existing.id
            r.canonical_key = existing.canonical_key
            r.created_at = old_record.created_at
            r.updated_at = now()
            r.content.raw_artifact_ref = store_raw(raw)
            r.deduplication.source_aliases = sorted(
                {a.alias for a in db.query(Alias).filter_by(record_id=existing.id)}
            )
            existing.record = canonical(r.model_dump(by_alias=True))
            existing.title = r.title
            existing.content_hash = r.source.content_hash_sha256
            reindex_record(db, existing)
            db.flush()
            return "updated"
        db.flush()
        return "duplicate"
    r.content.raw_artifact_ref = store_raw(raw)
    text = redact(r.title + "\n" + r.summary)
    page_parts = [c for c in r.content.chunks if "text" in c]
    pieces = []
    metadata = []
    for part in page_parts or [{"text": text, "page": None}]:
        t = redact(part["text"])
        for piece in split_text(t):
            pieces.append(piece)
            metadata.append(
                {
                    "index": len(pieces) - 1,
                    "page": part.get("page"),
                    "section": r.title,
                    "hash": digest(pieces[-1]),
                    "embedding_version": embedding_version(),
                    "text": pieces[-1],
                }
            )
    if len(pieces) > 2000:
        raise ValueError("Document exceeds chunk quota")
    r.content.chunks = metadata
    record = r.model_dump(by_alias=True)
    Record.model_validate(record)
    db.add(
        Knowledge(
            id=r.record_id,
            owner=r.access_owner,
            canonical_key=r.canonical_key,
            category=category(r),
            source=r.source.source_id,
            title=r.title,
            content_hash=r.source.content_hash_sha256,
            record=canonical(record),
        )
    )
    db.flush()
    for a in aliases:
        db.add(Alias(alias=a, record_id=r.record_id))
    vectors = embed_many(pieces)
    for i, p in enumerate(pieces):
        db.add(
            Chunk(
                record_id=r.record_id,
                position=i,
                text=p,
                embedding=canonical(vectors[i]),
                embedding_model=embedding_version(),
            )
        )
    db.flush()
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import text

        for c in db.query(Chunk).filter_by(record_id=r.record_id):
            db.execute(
                text(
                    "UPDATE knowledge_chunks SET embedding_vector=CAST(:v AS vector) WHERE id=:id"
                ),
                {"v": c.embedding, "id": c.id},
            )
    return "ingested"


def stats(db, owner=None):
    visible = db.query(Knowledge).filter(
        Knowledge.owner.in_(["public", owner] if owner else ["public"])
    )
    unique = visible.filter(Knowledge.record.contains('"duplicate_of":null'))
    cats = dict(
        unique.with_entities(Knowledge.category, func.count())
        .group_by(Knowledge.category)
        .all()
    )
    sources = dict(
        unique.with_entities(Knowledge.source, func.count())
        .group_by(Knowledge.source)
        .all()
    )
    for c in [
        "full_text_research_reports",
        "structured_vulnerability_advisories",
        "patch_and_commit_records",
        "training_and_reference_resources",
    ]:
        cats.setdefault(c, 0)
    errors = db.query(Document).filter_by(kind="import_error").all()
    reviewed = {
        r.value()["original_error_id"]
        for r in db.query(Document).filter_by(kind="corpus_exclusion_review")
        if r.value()["reason"] == "upstream_withdrawal"
    }
    parser_errors = sum(
        e.value().get("reason") not in ("ValueError", "WithdrawnRecord")
        for e in errors
        if e.id not in reviewed
    )
    unclassified = sum(
        e.id not in reviewed and e.value().get("reason") == "ValueError" for e in errors
    )
    return {
        "unique_normalized_records": sum(cats.values()),
        "categories": cats,
        "by_source": sources,
        "aliases": db.query(Alias)
        .join(Knowledge, Knowledge.id == Alias.record_id)
        .filter(Knowledge.owner.in_(["public", owner] if owner else ["public"]))
        .count(),
        "chunks": db.query(Chunk)
        .join(Knowledge, Knowledge.id == Chunk.record_id)
        .filter(Knowledge.owner.in_(["public", owner] if owner else ["public"]))
        .count(),
        "active_embedding_chunks": db.query(Chunk)
        .join(Knowledge, Knowledge.id == Chunk.record_id)
        .filter(
            Knowledge.owner.in_(["public", owner] if owner else ["public"]),
            Chunk.embedding_model == embedding_version(),
        )
        .count(),
        "embedding": embedding_version(),
        "quarantined_items": len(errors),
        "reviewed_withdrawn_exclusions": len(reviewed),
        "unclassified_import_errors": unclassified,
        "parser_errors": parser_errors,
        "jobs": [
            {"id": j.id, **j.value()}
            for j in db.query(Document).filter_by(kind="corpus_job")
        ],
        "scale_target": 20000,
        "scale_status": "passed" if sum(cats.values()) >= 20000 else "partial",
        "full_text_report_count": cats["full_text_research_reports"],
    }


def search(db, query, source=None, limit=5, owner="public", filters=None):
    limit = min(max(limit, 1), 20)
    tokens = list(set(re.findall(r"[a-z0-9_+-]+", query.lower())))[:20]
    if not tokens:
        return []
    # Hybrid identity/title matching and neural cosine; SQLite bounds lexical candidates.
    from sqlalchemy import or_, case

    q = (
        db.query(Chunk, Knowledge)
        .join(Knowledge, Knowledge.id == Chunk.record_id)
        .filter(Chunk.embedding_model == embedding_version())
        .filter(Knowledge.owner.in_(["public", owner]))
    )
    if (
        db.bind.dialect.name != "postgresql"
        or embedding_version() == "signed-token-hash-v1-128"
    ):
        terms = [Chunk.text.ilike("%" + t + "%") for t in tokens]
        q = q.filter(or_(*terms)).order_by(
            case((func.lower(Knowledge.title) == query.lower(), 1), else_=0).desc(),
            sum(case((term, 1), else_=0) for term in terms).desc(),
        )
    identifiers = re.findall(
        r"(?i)(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", query
    )
    exact_ids = (
        {
            a.record_id
            for a in db.query(Alias).filter(
                Alias.alias.in_(
                    [
                        i.upper()
                        if i.upper().startswith("CVE-")
                        else "GHSA-" + i[5:].lower()
                        for i in identifiers
                    ]
                )
            )
        }
        if identifiers
        else set()
    )
    if source:
        q = q.filter(Knowledge.source == source)
    filters = filters or {}
    q = q.filter(~Knowledge.record.contains('"curation_status":"deprecated"'))
    for key in ("package", "ecosystem", "record_type", "language", "trust_boundary"):
        if filters.get(key):
            q = q.filter(
                Knowledge.record.contains(canonical({key: filters[key]})[1:-1])
            )
    for key in ("cwe", "cve", "ghsa"):
        if filters.get(key):
            q = q.filter(Knowledge.record.contains(canonical(filters[key])))
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import text

        q = q.order_by(
            case((Knowledge.id.in_(exact_ids), 0), else_=1),
            case((func.lower(Knowledge.title) == query.lower(), 0), else_=1),
            text(
                "knowledge_chunks.embedding_vector <=> CAST(:query_embedding AS vector)"
            ),
        ).params(query_embedding=canonical(embed(query)))
    v = np.array(embed(query))
    results = []
    for c, k in q.limit(2000):
        score = float(np.dot(v, np.array(json.loads(c.embedding))))
        score += (
            1.0 if k.id in exact_ids or k.title.casefold() == query.casefold() else 0.0
        )
        r = json.loads(k.record)
        results.append(
            {
                "record_id": k.id,
                "title": k.title,
                "text": c.text,
                "score": score,
                "source_url": r["source"]["source_url"],
                "license": r["source"]["license"],
                "hash": k.content_hash,
                "chunk_index": c.position,
                "page": next(
                    (
                        m.get("page")
                        for m in r["content"]["chunks"]
                        if m.get("index") == c.position
                    ),
                    None,
                ),
                "section": r["title"],
                "chunk_sha256": digest(c.text),
                "embedding_model": c.embedding_model,
                "curation_status": r.get("curation_status", "proposed"),
                "validation_status": r["evidence"]["validation_status"],
                "published_at": r["source"]["published_at"],
                "retrieved_at": r["source"]["fetched_at"],
            }
        )
    results.sort(key=lambda x: x["score"], reverse=True)
    unique = []
    seen = set()
    for result in results:
        if result["record_id"] not in seen:
            unique.append(result)
            seen.add(result["record_id"])
        if len(unique) == limit:
            break
    return unique


def import_parts(path, max_size=20 * 1024 * 1024):
    p = Path(path)
    if p.stat().st_size > max_size:
        raise ValueError("Input too large")
    data = p.read_bytes()
    ext = p.suffix.lower()
    if ext == ".zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if (
                len(z.infolist()) > 1000
                or sum(i.file_size for i in z.infolist()) > max_size
            ):
                raise ValueError("Archive exceeds quota")
            for info in z.infolist():
                if info.is_dir():
                    continue
                if (
                    info.filename.startswith("/")
                    or ".." in Path(info.filename).parts
                    or (info.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise ValueError("Unsafe archive member")
                import tempfile

                with tempfile.TemporaryDirectory() as td:
                    f = Path(td) / Path(info.filename).name
                    f.write_bytes(z.read(info))
                    yield from import_parts(f, max_size)
    elif ext == ".pdf":
        from pypdf import PdfReader

        for n, page in enumerate(PdfReader(io.BytesIO(data)).pages):
            yield {
                "title": p.name + f" page {n + 1}",
                "text": page.extract_text() or "",
                "page": n + 1,
                "raw": data,
            }
    elif ext == ".docx":
        from docx import Document as Docx

        yield {
            "title": p.name,
            "text": "\n".join(p.text for p in Docx(io.BytesIO(data)).paragraphs),
            "raw": data,
        }
    elif ext in (".json", ".jsonl", ".csv"):
        text = data.decode("utf-8")
        items = (
            list(csv.DictReader(io.StringIO(text)))
            if ext == ".csv"
            else [json.loads(l) for l in text.splitlines() if l.strip()]
            if ext == ".jsonl"
            else json.loads(text)
        )
        if not isinstance(items, list):
            items = [items]
        for index, item in enumerate(items):
            yield {
                "title": item.get("title", p.name + f" row {index + 1}"),
                "text": canonical(item),
                "structured": item,
                "raw": canonical(item).encode(),
                "wire_raw": data,
                "json_pointer": "/" + str(index),
            }
    elif ext in (".md", ".txt", ".html", ".htm"):
        text = data.decode("utf-8")
        if ext in (".html", ".htm"):
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style", "iframe"]):
                tag.decompose()
            text = soup.get_text("\n")
        yield {"title": p.name, "text": text, "raw": data}
    else:
        raise ValueError("Unsupported input format")


def import_file(
    db, path, license, source_url, record_type="research_report", owner="public"
):
    if license == "unknown":
        raise ValueError("Confirm source permission before import")
    counts = Counter()
    inputs = list(import_parts(path))
    if len(inputs) > 1000:
        raise ValueError("Import exceeds 1000-part quota; split the library")
    grouped = {}
    parts = []
    for part in inputs:
        if part.get("page") is not None:
            grouped.setdefault(digest(part["raw"]), []).append(part)
        else:
            parts.append(part)
    for pages in grouped.values():
        parts.append(
            {
                "title": pages[0]["title"].rsplit(" page ", 1)[0],
                "text": "\n".join(x["text"] for x in pages),
                "raw": pages[0]["raw"],
                "pages": pages,
            }
        )
    for part in parts:
        if not part["text"].strip():
            raise ValueError("No extractable text; OCR is not enabled")
        r = Record(
            canonical_key=digest(
                (source_url + part["title"] + digest(part["raw"])).encode()
            ),
            record_type=record_type,
            title=part["title"],
            summary=redact(part["text"]),
            source=Source(
                source_id="owner",
                source_name="Owner import",
                source_url=source_url,
                license=license,
                full_text_policy="allowed",
                content_hash_sha256=digest(part["raw"]),
                parser_name="owner-" + Path(path).suffix,
            ),
        )
        native = part.get("structured")
        if isinstance(native, dict):
            if native.get("schema") == "atlas-research-record":
                imported = Record.model_validate(native)
                imported.record_id = uid()
                imported.source.source_id = "owner"
                imported.source.source_name = "Owner-supplied ATLAS-RR"
                imported.source.source_url = source_url
                imported.source.license = license
                imported.source.full_text_policy = "allowed"
                imported.source.content_hash_sha256 = digest(part["raw"])
                imported.content.raw_artifact_ref = None
                imported.evidence.independently_reproduced = False
                imported.evidence.validation_status = "source_reported"
                imported.curation_status = "proposed"
                imported.deduplication.duplicate_of = None
                imported.deduplication.duplicate_group_id = None
                r = imported
            else:
                adapter = (
                    "cve"
                    if "cveMetadata" in native
                    else "nvd"
                    if isinstance(native.get("cve"), dict) and native["cve"].get("id")
                    else "ghsa"
                    if str(native.get("id", "")).startswith("GHSA-")
                    else "osv"
                    if native.get("id") and "affected" in native
                    else None
                )
                if adapter:
                    r = source_record(adapter, native, part["raw"], source_url)
                    r.source.source_id = "owner"
                    r.source.source_name = "Owner-supplied native advisory"
                    r.source.license = license
                    r.source.full_text_policy = "allowed"
        if owner != "public":
            identities = (
                r.classification.cve + r.classification.ghsa + r.classification.osv
            )
            public_alias = (
                db.query(Alias)
                .join(Knowledge, Knowledge.id == Alias.record_id)
                .filter(Knowledge.owner == "public", Alias.alias.in_(identities))
                .first()
                if identities
                else None
            )
            if public_alias:
                r.deduplication.duplicate_of = public_alias.record_id
                r.deduplication.duplicate_group_id = public_alias.record_id
        if part.get("wire_raw") is not None:
            r.source.acquisition_artifact_ref = store_raw(part["wire_raw"])
            r.source.acquisition_hash_sha256 = digest(part["wire_raw"])
            r.source.json_pointer = part["json_pointer"]
        if part.get("pages"):
            r.content.chunks = [
                {"page": p["page"], "text": p["text"]} for p in part["pages"]
            ]
        r.access_owner = owner
        if owner != "public":
            r.canonical_key = owner + ":" + r.canonical_key
            r.deduplication.source_aliases = [r.canonical_key]
        counts[ingest(db, r, part["raw"])] += 1
    db.commit()
    return dict(counts)


class ReadStream:
    def __init__(self, response):
        self.response = response

    def read(self, n):
        return self.response.read(n)


def sync_bulk(source="ghsa", limit=21000, job_id=None):
    if source not in ("ghsa", "cve"):
        raise ValueError("No official bulk connector for source")
    cfg = source_config(source)
    if cfg["policy"] != "allowed":
        raise ValueError("Source terms/permission review required")
    with session() as db:
        job = (
            db.get(Document, job_id)
            if job_id
            else document(
                db,
                "corpus_job",
                "system",
                {
                    "source": source,
                    "cursor": 0,
                    "counts": {},
                    "status": "running",
                    "started": now(),
                },
            )
        )
        if not job or job.kind != "corpus_job" or job.value()["source"] != source:
            raise ValueError("Invalid resume job")
        state = job.value()
        counts = Counter(state["counts"])
        cursor = state["cursor"]
        job_id = job.id
        if counts["ingested"] + counts["duplicate"] + counts["updated"] >= limit:
            return {"job_id": job_id, **state}
        state["status"] = "running"
        job.data = canonical(state)
        db.commit()
    if not state.get("snapshot_sha"):
        import subprocess

        remote = subprocess.run(
            ["git", "ls-remote", cfg["url"] + ".git", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.split()
        if not remote or not re.fullmatch(r"[0-9a-f]{40}", remote[0]):
            raise ValueError("Unable to pin source snapshot")
        state["snapshot_sha"] = remote[0]
        with session() as db:
            job = db.get(Document, job_id)
            job.data = canonical(state)
            db.commit()
    bulk_url = cfg["bulk"].replace("refs/heads/main", state["snapshot_sha"])
    req = urllib.request.Request(
        bulk_url,
        headers={
            "User-Agent": "ATLAS/0.1 lawful advisory import",
            "Accept-Encoding": "identity",
        },
    )
    try:
        with (
            urllib.request.urlopen(req, timeout=120) as response,
            tarfile.open(fileobj=ReadStream(response), mode="r|gz") as tar,
        ):
            index = 0
            for member in tar:
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                if (
                    source == "ghsa"
                    and "/advisories/github-reviewed/" not in member.name
                ):
                    continue
                if source == "cve" and "/cves/" not in member.name:
                    continue
                index += 1
                if index <= cursor:
                    continue
                if member.size > 2 * 1024 * 1024:
                    continue
                raw = tar.extractfile(member).read()
                with session() as db:
                    try:
                        r = source_record(
                            source,
                            json.loads(raw),
                            raw,
                            cfg["url"]
                            + "/blob/"
                            + state["snapshot_sha"]
                            + "/"
                            + member.name.split("/", 1)[1],
                        )
                        counts[ingest(db, r, raw)] += 1
                    except WithdrawnRecord as e:
                        db.rollback()
                        counts["withdrawn"] += 1
                        alias = db.get(Alias, e.record_id)
                        if alias:
                            remove_record(db, alias.record_id, "upstream_withdrawal")
                        document(
                            db,
                            "corpus_exclusion",
                            "system",
                            {
                                "source": source,
                                "source_record_id": e.record_id,
                                "reason": "upstream_withdrawal",
                                "job_id": job_id,
                            },
                        )
                    except Exception as e:
                        db.rollback()
                        counts["errors"] += 1
                        document(
                            db,
                            "import_error",
                            "system",
                            {
                                "source": source,
                                "path": member.name,
                                "reason": type(e).__name__,
                                "job_id": job_id,
                            },
                        )
                    job = db.get(Document, job_id)
                    state.update(
                        cursor=index,
                        counts=dict(counts),
                        updated=now(),
                        status="running",
                    )
                    job.data = canonical(state)
                    db.commit()
                if index % 500 == 0:
                    print(canonical({"job_id": job_id, **state}), flush=True)
                if counts["ingested"] + counts["duplicate"] + counts[
                    "updated"
                ] >= limit or index >= max(limit * 2, limit + 1000):
                    break
        with session() as db:
            job = db.get(Document, job_id)
            state["status"] = "completed"
            job.data = canonical(state)
            db.commit()
        return {"job_id": job_id, **state}
    except Exception as e:
        with session() as db:
            job = db.get(Document, job_id)
            state.update(status="blocked", error=type(e).__name__)
            job.data = canonical(state)
            db.commit()
        raise


# API connectors retain source cursors and conditional-fetch metadata independently.
def fetch_json(source, url, etag=None, capture=None):
    import urllib.error
    from urllib.parse import urlsplit

    allowed_hosts = {
        "api.github.com",
        "raw.githubusercontent.com",
        "services.nvd.nist.gov",
        "api.osv.dev",
        "www.cisa.gov",
    }
    parsed_url = urlsplit(url)
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname not in allowed_hosts
        or parsed_url.username
        or parsed_url.password
    ):
        raise ValueError("Official connector URL is not approved")
    headers = {
        "User-Agent": "ATLAS/0.1 (+local-owner-controlled-advisory-ingest)",
        "Accept": "application/json",
    }
    if etag:
        headers["If-None-Match"] = etag
    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=30
            ) as r:
                data = r.read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ValueError("Source response exceeds quota")
                parsed = json.loads(data)
                if capture is not None:
                    capture.update(
                        acquisition_url=url,
                        acquisition_artifact_ref=store_raw(data),
                        acquisition_hash_sha256=digest(data),
                        acquisition_fetched_at=now(),
                    )
                return parsed, r.headers.get("ETag")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None, etag
            if e.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            value = e.headers.get("Retry-After", "6")
            try:
                delay = float(value)
            except ValueError:
                from email.utils import parsedate_to_datetime
                from datetime import datetime, timezone

                delay = (
                    parsedate_to_datetime(value) - datetime.now(timezone.utc)
                ).total_seconds()
            delay = max(1, delay)
            if not math.isfinite(delay) or delay > 60:
                raise ValueError(
                    "Source requires extended Retry-After; resume later without violating backoff"
                )
            time.sleep(delay)
    raise ValueError("Fetch exhausted")


def sync_api(source, limit=10, ids=None, job_id=None):
    if source not in ("nvd", "osv", "kev"):
        raise ValueError("Unsupported API source")
    with session() as db:
        job = (
            db.get(Document, job_id)
            if job_id
            else document(
                db,
                "corpus_job",
                "system",
                {
                    "source": source,
                    "cursor": 0,
                    "counts": {},
                    "status": "running",
                    "started": now(),
                    "etag": None,
                },
            )
        )
        if not job or job.value()["source"] != source:
            raise ValueError("Resume source mismatch")
        state = job.value()
        job_id = job.id
        db.commit()
        if source == "osv" and not ids:
            ids = [
                r.alias
                for r in db.query(Alias).filter(Alias.alias.like("GHSA-%")).limit(limit)
            ]
    counts = Counter(state.get("counts", {}))
    if source == "osv":
        with session() as db:
            if state.get("ids_manifest_id"):
                manifest_doc = db.get(Document, state["ids_manifest_id"])
                ids = manifest_doc.value()["ids"]
            elif state["cursor"] > 0 and state["cursor"] < limit:
                raise ValueError(
                    "Legacy OSV cursor has no immutable ID manifest; start a new incremental job"
                )
            elif state["cursor"] == 0:
                manifest_doc = document(
                    db, "source_id_manifest", "system", {"ids": ids or []}
                )
                state["ids_manifest_id"] = manifest_doc.id
                db.get(Document, job_id).data = canonical(state)
                db.commit()
    try:
        if source != "osv" and source_config(source)["policy"] != "allowed":
            raise ValueError("Source terms/permission review required")
        while state["cursor"] < limit:
            cursor = state["cursor"]
            if source == "nvd":
                url = (
                    SOURCES[source]["url"]
                    + f"?startIndex={cursor}&resultsPerPage={min(100, limit - cursor)}"
                )
            elif source == "osv":
                if cursor >= len(ids):
                    break
                url = SOURCES[source]["url"] + "/" + ids[cursor]
            else:
                url = SOURCES[source]["url"]
            fetch_meta = {}
            try:
                payload, etag = fetch_json(
                    source,
                    url,
                    state.get("etag") if source == "kev" else None,
                    capture=fetch_meta,
                )
            except Exception as primary_error:
                if (
                    (
                        isinstance(
                            primary_error,
                            __import__(
                                "urllib.error", fromlist=["HTTPError"]
                            ).HTTPError,
                        )
                        and primary_error.code == 429
                    )
                    or source != "kev"
                    or not SOURCES["kev"].get("official_mirror")
                ):
                    raise
                import subprocess

                sha = subprocess.run(
                    [
                        "git",
                        "ls-remote",
                        "https://github.com/cisagov/kev-data.git",
                        "HEAD",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                ).stdout.split()[0]
                if not re.fullmatch("[0-9a-f]{40}", sha):
                    raise ValueError("Invalid KEV source revision")
                url = SOURCES["kev"]["official_mirror"].replace(
                    "/main/", "/" + sha + "/"
                )
                state.update(
                    primary_status="unavailable",
                    mirror_reason=type(primary_error).__name__,
                    snapshot_sha=sha,
                    acquisition_url=url,
                )
                payload, etag = fetch_json(source, url, capture=fetch_meta)
            if payload is None:
                break
            items = (
                payload.get("vulnerabilities", [])
                if source in ("nvd", "kev")
                else [payload]
            )
            if not items:
                break
            state["source_native_items_in_response"] = len(items)
            start = state["cursor"] if source == "kev" else 0
            selected = (
                items[start:limit]
                if source == "kev"
                else items[: limit - state["cursor"]]
            )
            for position, item in enumerate(selected, start=start):
                raw = canonical(item).encode()
                with session() as db:
                    try:
                        record = source_record(source, item, raw, url)
                        for name, value in fetch_meta.items():
                            setattr(record.source, name, value)
                        record.source.json_pointer = (
                            ("/vulnerabilities/" + str(position))
                            if source in ("nvd", "kev")
                            else "/"
                        )
                        counts[ingest(db, record, raw)] += 1
                    except Exception as e:
                        db.rollback()
                        counts["errors"] += 1
                        document(
                            db,
                            "import_error",
                            "system",
                            {
                                "source": source,
                                "reason": type(e).__name__,
                                "job_id": job_id,
                            },
                        )
                    state.update(
                        cursor=state["cursor"] + 1,
                        counts=dict(counts),
                        updated=now(),
                        status="running",
                        etag=etag,
                    )
                    job = db.get(Document, job_id)
                    job.data = canonical(state)
                    db.commit()
            if source == "kev":
                break
            time.sleep(6 if source == "nvd" else 1)
        state["status"] = "completed"
    except Exception as e:
        state.update(status="blocked", error=type(e).__name__)
    with session() as db:
        job = db.get(Document, job_id)
        job.data = canonical(state)
        db.commit()
    return {"job_id": job_id, **state}


def remove_record(db, record_id, reason):
    k = db.get(Knowledge, record_id)
    if not k:
        raise ValueError("Record not found")
    raw_paths = [json.loads(k.record)["content"]["raw_artifact_ref"]]
    for d in (
        db.query(Document).filter_by(kind="corpus_provenance", owner=record_id).all()
    ):
        v = d.value()
        raw_paths.append(v.get("raw"))
        if v.get("record"):
            raw_paths.append(v["record"].get("content", {}).get("raw_artifact_ref"))
        db.delete(d)
    db.query(Chunk).filter_by(record_id=record_id).delete()
    db.query(Alias).filter_by(record_id=record_id).delete()
    document(
        db,
        "corpus_tombstone",
        "system",
        {
            "record_id": record_id,
            "hash": k.content_hash,
            "reason": reason,
            "deleted_at": now(),
        },
    )
    db.delete(k)
    db.flush()
    root = (Path(settings().data_dir) / "corpus_raw").resolve()
    for raw in set(p for p in raw_paths if p):
        p = Path(raw).resolve()
        if (
            p.is_relative_to(root)
            and re.fullmatch("[0-9a-f]{64}", p.name)
            and not db.query(Knowledge).filter_by(content_hash=p.name).first()
        ):
            p.unlink(missing_ok=True)
    db.commit()


def near_duplicates(db, threshold=0.92):
    groups = {}
    candidates = []
    for k in db.query(Knowledge).yield_per(200):
        r = json.loads(k.record)
        tokens = re.findall(r"\w+", r["summary"].lower())
        if len(tokens) < 20:
            continue
        signature = digest(" ".join(tokens[:12]))[:16]
        shingles = set(tuple(tokens[i : i + 3]) for i in range(len(tokens) - 2))
        for previous, other in groups.get(signature, [])[:20]:
            score = len(shingles & other) / max(1, len(shingles | other))
            if score >= threshold:
                candidates.append(
                    {
                        "left": previous,
                        "right": k.id,
                        "score": score,
                        "status": "needs_review",
                    }
                )
        groups.setdefault(signature, []).append((k.id, shingles))
    return candidates


def reindex_records(db, records):
    prepared = []
    all_text = []
    for k in records:
        r = Record.model_validate_json(k.record)
        page_groups = {}
        for item in r.content.chunks:
            if item.get("page") is not None and "text" in item:
                page_groups.setdefault(item["page"], []).append(item["text"])
        parts = []
        for page, texts in sorted(page_groups.items()):
            merged = ""
            for text in texts:
                overlap = next(
                    (
                        n
                        for n in range(min(len(merged), len(text), 1600), 0, -1)
                        if merged.endswith(text[:n])
                    ),
                    0,
                )
                merged += text[overlap:]
            parts.append({"text": merged, "page": page})
        if not parts:
            parts = [
                {
                    "text": " ".join(
                        [r.title, r.canonical_key, *r.deduplication.source_aliases]
                    )
                    + "\n"
                    + r.summary,
                    "page": None,
                }
            ]
        chunks = []
        for part in parts:
            for piece in split_text(redact(part["text"])):
                chunks.append(
                    {
                        "index": len(chunks),
                        "text": piece,
                        "page": part.get("page"),
                        "section": r.title,
                        "hash": digest(piece),
                        "embedding_version": embedding_version(),
                    }
                )
        if len(chunks) > 2000:
            raise ValueError("Document exceeds chunk quota")
        prepared.append((k, r, chunks))
        all_text.extend(c["text"] for c in chunks)
    vectors = iter(embed_many(all_text))
    ids = [k.id for k in records]
    if ids:
        db.query(Chunk).filter(Chunk.record_id.in_(ids)).delete(
            synchronize_session=False
        )
    vector_updates = []
    for k, r, chunks in prepared:
        for metadata in chunks:
            vector = next(vectors)
            c = Chunk(
                id=uid(),
                record_id=k.id,
                position=metadata["index"],
                text=metadata["text"],
                embedding=canonical(vector),
                embedding_model=embedding_version(),
            )
            db.add(c)
            vector_updates.append({"v": c.embedding, "id": c.id})
        r.content.chunks = chunks
        r.updated_at = now()
        k.record = canonical(r.model_dump(by_alias=True))
    db.flush()
    if db.bind.dialect.name == "postgresql" and vector_updates:
        from sqlalchemy import text

        db.execute(
            text(
                "UPDATE knowledge_chunks SET embedding_vector=CAST(:v AS vector) WHERE id=:id"
            ),
            vector_updates,
        )


def reindex_record(db, k):
    reindex_records(db, [k])


def reindex_job(id):
    with session() as db:
        job = db.get(Document, id)
        v = job.value()
        owner = job.owner
    total = v.get("processed", 0)
    while total < v.get("limit", 100000):
        with session() as db:
            records = (
                db.query(Knowledge)
                .filter(
                    Knowledge.owner.in_(["public", owner]),
                    Knowledge.id > v.get("cursor", ""),
                )
                .order_by(Knowledge.id)
                .limit(100)
                .all()
            )
            if not records:
                break
            reindex_records(db, records)
            total += len(records)
            v["cursor"] = records[-1].id
            v.update(processed=total, lease_until=time.time() + 600)
            job = db.get(Document, id)
            job.data = canonical(v)
            db.commit()
    with session() as db:
        job = db.get(Document, id)
        v.update(status="completed", processed=total)
        job.data = canonical(v)
        db.commit()
    return v
