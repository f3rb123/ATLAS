"""Reset only the explicitly isolated generated e2e.db owner, preserving public corpus/audit."""

from pathlib import Path
import json
from sqlalchemy.engine import make_url
from atlas.config import settings
from atlas.db import session, User, Session, Document
from atlas.auth import bootstrap_token

p = Path(make_url(settings().database_url).database).resolve()
if p != Path(".runtime/e2e.db").resolve():
    raise SystemExit("Refusing to reset a non-E2E database")
with session() as db:
    users = db.query(User).all()
    if any(u.email != "build-test@example.invalid" for u in users):
        raise SystemExit("Unexpected non-fixture account; refusing reset")
    for u in users:
        db.query(Session).filter_by(user_id=u.id).delete()
        db.query(Document).filter_by(owner=u.id).delete()
        db.delete(u)
    marker = db.get(Document, "owner-bootstrap-complete")
    if marker:
        db.delete(marker)
    db.query(Document).filter_by(kind="throttle").delete()
    db.commit()
    token = bootstrap_token(db)
p = Path(".runtime/e2e-bootstrap.json")
v = json.loads(p.read_text())
v["token"] = token
p.write_text(json.dumps(v))
p.chmod(0o600)
print("Isolated test owner reset; corpus and immutable audit retained.")
