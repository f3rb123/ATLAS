import time, json
from fastapi.testclient import TestClient
from atlas.api import app
from atlas.db import *
from atlas.auth import *


def test_bootstrap_password_session_and_csrf(db, monkeypatch):
    from atlas.config import settings

    monkeypatch.setenv("ATLAS_REQUIRE_MFA", "true")
    settings.cache_clear()
    token = bootstrap_token(db)
    with TestClient(app) as c:
        assert c.get("/api/v1/campaigns").status_code == 401
        assert (
            c.post(
                "/api/v1/auth/bootstrap",
                json={
                    "token": token,
                    "email": "owner@example.invalid",
                    "password": "short",
                },
            ).status_code
            == 400
        )
        r = c.post(
            "/api/v1/auth/bootstrap",
            json={
                "token": token,
                "email": "owner@example.invalid",
                "password": "a long generated test passphrase 73420",
            },
        )
        assert r.status_code == 200
        assert (
            "HttpOnly" in r.headers["set-cookie"]
            and "SameSite=strict" in r.headers["set-cookie"]
        )
        assert (
            c.post(
                "/api/v1/auth/bootstrap",
                json={
                    "token": token,
                    "email": "other@example.invalid",
                    "password": "another long test passphrase",
                },
            ).status_code
            == 400
        )
        assert c.get("/api/v1/campaigns").status_code == 403
        assert c.post("/api/v1/auth/totp/setup").status_code == 403
        csrf = r.json()["csrf_token"]
        h = {"Origin": "http://localhost:8000", "X-CSRF-Token": csrf}
        r = c.post("/api/v1/auth/totp/setup", headers=h)
        assert r.status_code == 200
        assert "otpauth://" in r.json()["provisioning_uri"]
        db.expire_all()
        u = db.query(User).one()
        assert "argon2id" in u.password
        assert db.query(Session).one().token_hash not in c.cookies.values()


def authenticated(db):
    u = User(
        id=uid(),
        email="admin@example.invalid",
        password=ph.hash("a long fixture-only password 9824"),
    )
    db.add(u)
    db.flush()
    document(
        db,
        "passkey",
        u.id,
        {
            "credential_id": "fixture-only",
            "public_key": "not-a-real-key",
            "sign_count": 0,
        },
    )
    s, t, csrf = issue(db, u, True)
    s.stepup = time.time()
    db.commit()
    c = TestClient(app)
    c.cookies.set("atlas_dev", t)
    c.headers.update({"Origin": "http://localhost:8000", "X-CSRF-Token": csrf})
    return c, u, s


def test_campaign_ownership_idempotency_and_kill(db):
    c, u, s = authenticated(db)
    r = c.post(
        "/api/v1/campaigns",
        json={
            "name": "Lab",
            "authorization_ref": "local lab",
            "authorization_attested": True,
        },
    )
    assert r.status_code == 200
    r = r.json()
    headers = {"Idempotency-Key": "run-1"}
    a = c.post("/api/v1/campaigns/" + r["id"] + "/runs", json={}, headers=headers)
    b = c.post("/api/v1/campaigns/" + r["id"] + "/runs", json={}, headers=headers)
    assert a.status_code == 200 and a.json()["id"] == b.json()["id"]
    db.expire_all()
    other = document(db, "campaign", "another-user", {"name": "private"})
    db.commit()
    assert c.get("/api/v1/campaigns/" + other.id).status_code == 404
    assert c.post("/api/v1/admin/kill-switch").status_code == 200
    assert c.post("/api/v1/campaigns/" + r["id"] + "/runs", json={}).status_code == 403
    assert c.get("/api/v1/runs/" + a.json()["id"]).json()["status"] == "cancelled"


def test_passkey_bad_challenge_no_replay(db):
    c, u, s = authenticated(db)
    r = c.post("/api/v1/auth/webauthn/authentication/options")
    assert r.status_code == 200
    assert (
        c.post(
            "/api/v1/auth/webauthn/authentication/verify",
            json={"credential": {"id": "invalid"}},
        ).status_code
        == 400
    )
    db.expire_all()
    assert db.query(Document).filter_by(kind="challenge").count() == 0


def test_recovery_single_use_and_totp_replay(db):
    c, u, s = authenticated(db)
    codes = recovery_codes(db, u)
    db.commit()
    recovery_consume(db, u, s, codes[0])
    db.commit()
    with __import__("pytest").raises(ValueError):
        recovery_consume(db, u, s, codes[0])
    assert all(
        codes[1] not in d.data for d in db.query(Document).filter_by(kind="recovery")
    )
    uri = totp_setup(db, u, s)
    db.commit()
    seed = __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(
        __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(uri).query
    )["secret"][0]
    code = __import__("pyotp").TOTP(seed).now()
    totp_verify(db, u, s, code, True)
    db.commit()
    with __import__("pytest").raises(ValueError):
        totp_verify(db, u, s, code)


def test_validation_errors_do_not_echo_passwords_or_keys(db):
    with TestClient(app) as c:
        r = c.post(
            "/api/v1/auth/login",
            json={"email": "x" * 300, "password": "fixture-secret-do-not-echo"},
        )
        assert r.status_code == 422 and "fixture-secret-do-not-echo" not in r.text


def test_production_cookie_and_enrollment_gate(db, monkeypatch):
    from atlas.config import settings

    monkeypatch.setenv("ATLAS_ENV", "production")
    monkeypatch.setenv("ATLAS_REQUIRE_MFA", "true")
    monkeypatch.setenv("ATLAS_EXTERNAL_URL", "https://atlas.example.invalid")
    settings.cache_clear()
    token = bootstrap_token(db)
    with TestClient(app, base_url="https://atlas.example.invalid") as c:
        assert c.get("/health/ready").status_code == 503
        r = c.post(
            "/api/v1/auth/bootstrap",
            json={
                "token": token,
                "email": "owner@example.invalid",
                "password": "A generated fixture passphrase 82490",
            },
        )
        assert r.status_code == 200
        cookie = r.headers["set-cookie"]
        assert (
            "__Host-atlas=" in cookie
            and "Secure" in cookie
            and "HttpOnly" in cookie
            and "SameSite=strict" in cookie
            and "Domain=" not in cookie
        )
        assert c.get("/api/v1/campaigns").status_code == 403
        assert (
            c.get("/api/v1/users/me", headers={"Host": "attacker.invalid"}).status_code
            == 400
        )
    settings.cache_clear()


def test_long_unicode_passphrases_and_common_blocklist():
    import pytest

    assert password_ok("  αληθινή μακριά φράση 7342  ") is None
    for p in ["short", "passwordpassword", "aaaaaaaaaaaaaaa", "12345678901234567890"]:
        with pytest.raises(ValueError):
            password_ok(p)


def test_specific_auth_and_capability_routes_not_shadowed(db):
    c, u, s = authenticated(db)
    assert c.get("/api/v1/auth/passkeys").status_code == 200
    assert c.get("/api/v1/auth/audit").status_code == 200
    assert c.get("/api/v1/capabilities").status_code == 200
    assert c.get("/api/v1/corpus/sources/reviewed").status_code == 200


def test_unknown_billing_reconciliation_requires_stepup_and_stopped_owner_run(db):
    from atlas.gateway import reserve

    c, u, s = authenticated(db)
    run = document(
        db,
        "run",
        u.id,
        {"campaign_id": "c", "status": "blocked", "budget_limit": 1, "budget_used": 0},
    )
    db.commit()
    reservation = reserve(db, u.id, run.id, 0.5, "reasoning")
    body = {"actual_cost": 0.1, "billing_reference": "Provider invoice fixture-123"}
    response = c.post(
        "/api/v1/budgets/reservations/" + reservation + "/reconcile", json=body
    )
    assert response.status_code == 200, response.text
    db.expire_all()
    assert db.get(Document, run.id).value()["budget_used"] == 0.1
    assert (
        c.post(
            "/api/v1/budgets/reservations/" + reservation + "/reconcile", json=body
        ).status_code
        == 404
    )


def test_chunked_request_limit_counts_bytes_without_content_length(db):
    from atlas.config import settings

    settings().max_request_bytes = 1024
    with TestClient(app) as c:

        def chunks():
            yield b" " * 800
            yield b" " * 800

        response = c.post(
            "/api/v1/auth/login",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413, response.text
        assert "limit" in response.text
