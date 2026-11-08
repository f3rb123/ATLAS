"""Create an isolated copy of PUBLIC corpus only; never reset the application database."""

import os, json, secrets
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as SQLSession
from atlas.db import Base, Knowledge, Alias, Chunk, Document, session
from atlas.auth import bootstrap_token

root = Path(".runtime/e2e-data")
root.mkdir(mode=0o700, parents=True, exist_ok=True)
p = Path(".runtime/e2e.db")
if p.exists():
    raise SystemExit(
        "Use a new test database or explicitly archive the previous generated e2e.db"
    )
engine = create_engine("sqlite:///" + str(p))
Base.metadata.create_all(engine)
with session() as source, SQLSession(engine) as target:
    public = {k.id for k in source.query(Knowledge).filter_by(owner="public")}
    for cls in [Knowledge, Alias, Chunk]:
        q = source.query(cls)
        for obj in q.yield_per(200):
            if (obj.id if cls == Knowledge else obj.record_id) not in public:
                continue
            target.add(
                cls(**{c.name: getattr(obj, c.name) for c in cls.__table__.columns})
            )
        target.commit()
    token = bootstrap_token(target)
fd = os.open(
    ".runtime/e2e-bootstrap.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
)
with os.fdopen(fd, "w") as f:
    json.dump(
        {
            "token": token,
            "email": "build-test@example.invalid",
            "password": secrets.token_urlsafe(32),
        },
        f,
    )
import zipfile

with zipfile.ZipFile(".runtime/e2e-repo.zip", "w") as z:
    z.writestr("app.py", "def owned(actor,owner):\n    return actor == owner\n")
    z.writestr(
        "tests/test_owned.py",
        "import unittest\nclass Owned(unittest.TestCase):\n def test_benign(self):self.assertTrue(True)\n",
    )
print(
    "Isolated public corpus fixture and one-time bootstrap prepared; secret values not printed."
)
