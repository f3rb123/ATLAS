"""Recheck early generic GHSA exclusions against a new pinned official source snapshot.
Original error events and original job counts are preserved; no records are added.
"""

import json, subprocess, urllib.request, tarfile, re
from atlas.db import session, Document, document, canonical, digest, now
from atlas.corpus import store_raw, ReadStream

sha = subprocess.run(
    ["git", "ls-remote", "https://github.com/github/advisory-database.git", "HEAD"],
    capture_output=True,
    text=True,
    check=True,
    timeout=30,
).stdout.split()[0]
if not re.fullmatch("[0-9a-f]{40}", sha):
    raise SystemExit("Invalid official snapshot")
with session() as db:
    errors = {
        d.value()["path"].split("/advisories/", 1)[-1]: d.id
        for d in db.query(Document).filter_by(kind="import_error")
        if d.value().get("source") == "ghsa" and d.value().get("reason") == "ValueError"
    }
url = f"https://codeload.github.com/github/advisory-database/tar.gz/{sha}"
counts = {"withdrawn": 0, "needs_review": 0}
with (
    urllib.request.urlopen(
        urllib.request.Request(
            url, headers={"User-Agent": "ATLAS/0.1 lawful source audit"}
        ),
        timeout=120,
    ) as response,
    tarfile.open(fileobj=ReadStream(response), mode="r|gz") as archive,
):
    for member in archive:
        suffix = member.name.split("/advisories/", 1)[-1]
        if suffix not in errors or not member.isfile() or member.size > 2 * 1024 * 1024:
            continue
        raw = archive.extractfile(member).read()
        item = json.loads(raw)
        reason = "upstream_withdrawal" if item.get("withdrawn") else "needs_review"
        counts["withdrawn" if item.get("withdrawn") else "needs_review"] += 1
        with session() as db:
            id = digest("exclusion-review:" + errors[suffix])[:36]
            if not db.get(Document, id):
                document(
                    db,
                    "corpus_exclusion_review",
                    "system",
                    {
                        "original_error_id": errors[suffix],
                        "reason": reason,
                        "source_record_id": item["id"],
                        "source_snapshot": sha,
                        "acquisition_url": url,
                        "content_hash": digest(raw),
                        "raw_artifact_ref": store_raw(raw),
                        "reviewed_at": now(),
                        "basis": "New pinned official source confirms withdrawn status; original parser excluded withdrawn advisories",
                    },
                    id,
                )
                db.commit()
        del errors[suffix]
print(json.dumps({"snapshot": sha, "counts": counts, "unresolved": len(errors)}))
