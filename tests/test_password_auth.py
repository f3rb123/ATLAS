from fastapi.testclient import TestClient

from atlas.api import app
from atlas.auth import bootstrap_token
from atlas.config import settings
from atlas.db import Session


def test_password_only_sensitive_cli_token_preserves_actual_factor_level(db):
    with TestClient(app) as client:
        assert client.post("/api/v1/auth/bootstrap", json={"token": bootstrap_token(db), "email": "owner@example.invalid",
            "password": "fixture CLI unique passphrase 93473"}).status_code == 200
        me = client.get("/api/v1/users/me").json()
        headers = {"Origin": settings().external_url, "X-CSRF-Token": me["csrf_token"]}
        response = client.post("/api/v1/auth/cli-tokens", headers=headers, json={"scopes": ["read", "tool"]})
        assert response.status_code == 200
        token = response.json()["token"]
        # A scoped password token does not pretend MFA happened, and the
        # optional-factor policy matches browser operator behavior.
        from atlas.db import digest
        db.expire_all()
        issued = db.query(Session).filter_by(token_hash=digest(token)).one()
        assert issued.mfa == 0
        configured = client.post("/api/v1/tools/integrations", headers={"Authorization": "Bearer " + token},
            json={"name": "Unconnected fixture", "adapter": "mcp_resources", "base_url": "https://fixture.example.invalid/mcp", "readonly_contract_attested": True})
        assert configured.status_code == 200 and not configured.json()["enabled"]


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
        scoped = client.post(
            "/api/v1/campaigns",
            headers=headers,
            json={
                "name": "Password-only authorized lab configuration",
                "mode": "lab",
                "authorization_ref": "Isolated fixture; no live requests",
                "authorization_attested": True,
                "scope": {
                    "allow": [{"host": "example.invalid"}],
                    "lab_networks": ["127.0.0.0/8"],
                },
            },
        )
        assert scoped.status_code == 200
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
