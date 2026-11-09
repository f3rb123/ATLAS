from fastapi.testclient import TestClient

from atlas.api import app
from atlas.auth import bootstrap_token
from atlas.config import settings
from atlas.db import Session


def test_password_only_operator_csrf_change_rotation_and_logout(db):
    password = "local fixture unique passphrase 73420"
    new = "different fixture passphrase 89273"
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "token": bootstrap_token(db),
                "email": "owner@example.invalid",
                "password": password,
            },
        )
        assert r.status_code == 200
        assert client.get("/api/v1/campaigns").status_code == 200
        me = client.get("/api/v1/users/me").json()
        assert me["operator_access"] and not me["mfa_required"]
        headers = {"Origin": settings().external_url, "X-CSRF-Token": me["csrf_token"]}
        assert (
            client.post("/api/v1/campaigns", json={"name": "forged"}).status_code == 403
        )
        body = {"current_password": "wrong fixture password", "new_password": new}
        assert (
            client.post("/api/v1/auth/password", json=body, headers=headers).status_code
            == 400
        )
        original = client.cookies.get("atlas_dev")
        body["current_password"] = password
        changed = client.post("/api/v1/auth/password", json=body, headers=headers)
        assert (
            changed.status_code == 200 and client.cookies.get("atlas_dev") != original
        )
        db.expire_all()
        assert db.query(Session).count() == 1
        other = TestClient(app)
        other.cookies.set("atlas_dev", original)
        assert other.get("/api/v1/campaigns").status_code == 401
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": me["email"], "password": password}
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": me["email"], "password": new}
            ).status_code
            == 200
        )
        current = client.get("/api/v1/users/me").json()
        headers["X-CSRF-Token"] = current["csrf_token"]
        assert (
            client.post("/api/v1/auth/logout", json={}, headers=headers).status_code
            == 200
        )
        assert client.get("/api/v1/campaigns").status_code == 401
