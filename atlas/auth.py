"""Owner bootstrap, Argon2id, opaque sessions, passkeys, TOTP and recovery."""

import secrets, time, hmac, json
from urllib.parse import urlsplit
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
import pyotp
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from .db import (
    User,
    Session,
    Document,
    document,
    digest,
    canonical,
    uid,
    append,
    transaction_lock,
)
from sqlalchemy import update, delete
from .config import settings
from .vault import seal, open_secret

COMMON_PASSWORDS = {
    p.casefold()
    for p in (
        __import__("pathlib").Path(__file__).parent / "data" / "common_passwords.txt"
    )
    .read_text()
    .splitlines()
    if p and not p.startswith("#")
}
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY = ph.hash(secrets.token_urlsafe(32))
COOKIE = "__Host-atlas"


def password_ok(p):
    if (
        len(p) < 15
        or len(p) > 1024
        or p.casefold().strip() in COMMON_PASSWORDS
        or len(set(p.strip())) < 3
    ):
        raise ValueError("Use a unique passphrase of 15–1024 characters")


def throttle(db, key, limit=8, seconds=300):
    key = digest(key)[:36]
    transaction_lock(db, "throttle:" + key)
    d = db.get(Document, key)
    t = time.time()
    v = d.value() if d else {"start": t, "count": 0}
    if t - v["start"] > seconds:
        v = {"start": t, "count": 0}
    if v["count"] >= limit:
        raise ValueError("Too many attempts; retry later")
    v["count"] += 1
    if d:
        d.data = canonical(v)
    else:
        document(db, "throttle", "system", v, key)
    db.commit()


def bootstrap_token(db):
    if db.query(User).first():
        raise ValueError("Bootstrap disabled")
    db.query(Document).filter_by(kind="bootstrap").delete()
    token = secrets.token_urlsafe(48)
    document(
        db,
        "bootstrap",
        "system",
        {"verifier": digest(token), "expires": time.time() + 600},
    )
    db.commit()
    return token


def bootstrap(db, token, email, password):
    password_ok(password)
    if db.query(User).first():
        raise ValueError("Bootstrap disabled")
    d = db.query(Document).filter_by(kind="bootstrap").with_for_update().first()
    if (
        not d
        or d.value()["expires"] < time.time()
        or not hmac.compare_digest(d.value()["verifier"], digest(token))
    ):
        raise ValueError("Invalid bootstrap")
    u = User(id=uid(), email=email.strip().lower(), password=ph.hash(password))
    db.add(u)
    db.delete(d)
    db.flush()
    append(db, u.id, u.id, "owner_bootstrapped", {})
    return u


def issue(db, u, mfa=False, scopes="browser", seconds=43200):
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    t = time.time()
    s = Session(
        user_id=u.id,
        token_hash=digest(token),
        csrf_hash=digest(csrf),
        created=t,
        used=t,
        expires=t + seconds,
        mfa=int(mfa),
        stepup=0,
        scopes=scopes,
    )
    db.add(s)
    db.flush()
    return s, token, csrf


def identify(db, token):
    s = db.query(Session).filter_by(token_hash=digest(token)).with_for_update().first()
    t = time.time()
    if not s or s.expires < t or (s.scopes == "browser" and t - s.used > 1800):
        raise ValueError("Authentication required")
    u = db.get(User, s.user_id)
    if not u:
        raise ValueError("Authentication required")
    s.used = t
    return u, s


def login(db, email, password):
    u = db.query(User).filter_by(email=email.strip().lower()).first()
    try:
        ok = ph.verify(u.password if u else DUMMY, password)
    except (VerificationError, InvalidHashError):
        ok = False
    if not u or not ok:
        raise ValueError("Invalid credentials")
    return issue(db, u)


def change_password(db, user, old_password, new_password, mfa=False):
    password_ok(new_password)
    try:
        valid = ph.verify(user.password, old_password)
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid:
        raise ValueError("Current passphrase is incorrect")
    user.password = ph.hash(new_password)
    db.query(Session).filter_by(user_id=user.id).delete()
    append(db, user.id, user.id, "password_changed", {"sessions_revoked": True})
    return issue(db, user, mfa=mfa)


def rp():
    return urlsplit(settings().external_url).hostname


def challenge(db, u, s, kind):
    creds = db.query(Document).filter_by(kind="passkey", owner=u.id).all()
    if kind == "registration":
        if not creds and s.created < time.time() - 300:
            raise ValueError("Recent sign-in required for initial enrollment")
        if creds and s.stepup < time.time() - 300:
            raise ValueError("Passkey step-up required")
        opt = generate_registration_options(
            rp_id=rp(),
            rp_name="ATLAS",
            user_id=u.id.encode(),
            user_name=u.email,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(d.value()["credential_id"])
                )
                for d in creds
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED,
                resident_key=ResidentKeyRequirement.PREFERRED,
            ),
        )
    else:
        opt = generate_authentication_options(
            rp_id=rp(),
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(d.value()["credential_id"])
                )
                for d in creds
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
    db.query(Document).filter_by(kind="challenge", owner=s.id).delete()
    o = json.loads(options_to_json(opt))
    document(
        db,
        "challenge",
        s.id,
        {"challenge": o["challenge"], "kind": kind, "expires": time.time() + 120},
    )
    return o


def verify_passkey(db, u, s, credential, kind):
    d = (
        db.query(Document)
        .filter_by(kind="challenge", owner=s.id)
        .with_for_update()
        .first()
    )
    if not d:
        raise ValueError("Challenge missing")
    v = d.value()
    db.delete(d)
    db.flush()
    # Consume even on failed verification; caller commits challenge consumption.
    if v["kind"] != kind or v["expires"] < time.time():
        raise ValueError("Expired challenge")
    kwargs = dict(
        credential=credential,
        expected_challenge=base64url_to_bytes(v["challenge"]),
        expected_rp_id=rp(),
        expected_origin=settings().external_url,
        require_user_verification=True,
    )
    if kind == "registration":
        r = verify_registration_response(**kwargs)
        existing = db.query(Document).filter_by(kind="passkey").all()
        cid = bytes_to_base64url(r.credential_id)
        if any(c.value()["credential_id"] == cid for c in existing):
            raise ValueError("Credential already registered")
        document(
            db,
            "passkey",
            u.id,
            {
                "credential_id": cid,
                "public_key": bytes_to_base64url(r.credential_public_key),
                "sign_count": r.sign_count,
                "backed_up": r.credential_backed_up,
            },
        )
        append(
            db,
            u.id,
            u.id,
            "passkey_enrolled",
            {"credential_fingerprint": digest(cid)[:12]},
        )
    else:
        c = next(
            (
                c
                for c in db.query(Document).filter_by(kind="passkey", owner=u.id)
                if c.value()["credential_id"] == credential.get("id")
            ),
            None,
        )
        if not c:
            raise ValueError("Unknown credential")
        cv = c.value()
        response = credential.get("response", {})
        if (
            response.get("userHandle")
            and base64url_to_bytes(response["userHandle"]) != u.id.encode()
        ):
            raise ValueError("Invalid credential owner")
        r = verify_authentication_response(
            **kwargs,
            credential_public_key=base64url_to_bytes(cv["public_key"]),
            credential_current_sign_count=cv["sign_count"],
        )
        cv["sign_count"] = r.new_sign_count
        cv["backed_up"] = r.credential_backed_up
        c.data = canonical(cv)
        s.mfa = 1
        s.stepup = time.time()
        append(db, u.id, u.id, "passkey_verified", {})
    return True


def totp_setup(db, u, s):
    if (
        u.totp or db.query(Document).filter_by(kind="passkey", owner=u.id).first()
    ) and s.stepup < time.time() - 300:
        raise ValueError("Passkey step-up required")
    seed = pyotp.random_base32()
    document(
        db,
        "totp_pending",
        s.id,
        {"secret": seal(seed, f"totp:{u.id}"), "expires": time.time() + 300},
    )
    return pyotp.TOTP(seed).provisioning_uri(u.email, issuer_name="ATLAS")


def totp_verify(db, u, s, code, enroll=False):
    if enroll:
        d = (
            db.query(Document)
            .filter_by(kind="totp_pending", owner=s.id)
            .order_by(Document.created.desc())
            .first()
        )
        if not d or d.value()["expires"] < time.time():
            raise ValueError("Setup expired")
        blob = d.value()["secret"]
    else:
        blob = u.totp
    if not blob:
        raise ValueError("Invalid factor")
    otp = pyotp.TOTP(open_secret(blob, f"totp:{u.id}"))
    counter = int(time.time()) // 30
    if counter <= u.totp_counter or not otp.verify(code, valid_window=0):
        raise ValueError("Invalid factor")
    changed = db.execute(
        update(User)
        .where(User.id == u.id, User.totp_counter < counter)
        .values(totp_counter=counter)
    ).rowcount
    if changed != 1:
        raise ValueError("Invalid factor")
    u.totp_counter = counter
    if enroll:
        u.totp = blob
        db.delete(d)
        u.mfa = 1
    else:
        if settings().require_mfa and not db.query(Document).filter_by(kind="passkey", owner=u.id).first():
            raise ValueError("Passkey enrollment required")
        s.mfa = 1
    append(db, u.id, u.id, "totp_enrolled" if enroll else "totp_verified", {})


def recovery_codes(db, u):
    db.query(Document).filter_by(kind="recovery", owner=u.id).delete()
    codes = [secrets.token_urlsafe(24) for _ in range(10)]
    for c in codes:
        document(db, "recovery", u.id, {"hash": ph.hash(c)})
    append(db, u.id, u.id, "recovery_codes_regenerated", {})
    return codes


def recovery_consume(db, u, s, code):
    for d in (
        db.query(Document).filter_by(kind="recovery", owner=u.id).with_for_update()
    ):
        try:
            valid = ph.verify(d.value()["hash"], code)
        except VerificationError:
            valid = False
        if valid:
            consumed = db.execute(
                delete(Document).where(
                    Document.id == d.id,
                    Document.kind == "recovery",
                    Document.owner == u.id,
                )
            ).rowcount
            if consumed != 1:
                raise ValueError("Invalid recovery code")
            s.mfa = 1
            append(db, u.id, u.id, "recovery_consumed", {})
            return
    raise ValueError("Invalid recovery code")
