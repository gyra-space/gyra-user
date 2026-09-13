"""End-to-end coverage of the local login / JWT lifecycle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def test_register_then_login(client):
    resp = client.post(
        "/api/v1/auth/local/register",
        json={
            "username": "bob",
            "password": "hunter2hunter2",
            "email": "bob@example.com",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["name"] == "bob"
    assert body["access_token"] and body["refresh_token"]

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["name"] == "bob"
    assert me.json()["role"] == "normal"


def test_login_accepts_base64_password(client, registered_user):
    client.post("/api/v1/auth/logout")
    payload = {
        "username": "alice",
        "password": base64.b64encode(b"secret123").decode(),
    }
    resp = client.post("/api/v1/auth/local/login", json=payload)
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["name"] == "alice"


def test_login_accepts_plain_password(client, registered_user):
    client.post("/api/v1/auth/logout")
    resp = client.post(
        "/api/v1/auth/local/login", json={"username": "alice", "password": "secret123"}
    )
    assert resp.status_code == 200


def test_wrong_password_is_rejected(client, registered_user):
    client.post("/api/v1/auth/logout")
    resp = client.post(
        "/api/v1/auth/local/login", json={"username": "alice", "password": "wrongpass"}
    )
    assert resp.status_code == 401


def test_duplicate_registration_rejected(client, registered_user):
    resp = client.post(
        "/api/v1/auth/local/register",
        json={"username": "alice", "password": "secret123"},
    )
    assert resp.status_code == 400


def test_me_requires_auth(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_refresh_rotates_and_reuse_is_rejected(client, registered_user):
    first_refresh = registered_user["refresh_token"]

    refreshed = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first_refresh}
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["access_token"]

    # Old token was rotated away — replaying it must fail and kill the family.
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert replay.status_code == 401

    # The whole family is revoked, so the freshly issued token dies too.
    second = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refreshed.json()["refresh_token"]},
    )
    assert second.status_code == 401


def test_password_grant_token_endpoint(client, registered_user):
    client.post("/api/v1/auth/logout")
    resp = client.post(
        "/api/v1/auth/token",
        json={
            "grant_type": "password",
            "username": "alice",
            "password": base64.b64encode(b"secret123").decode(),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


def test_introspect(client, registered_user):
    token = registered_user["access_token"]
    ok = client.post(f"/api/v1/auth/introspect?token={token}")
    assert ok.status_code == 200 and ok.json()["active"] is True
    assert ok.json()["username"] == "alice"

    bad = client.post("/api/v1/auth/introspect?token=not-a-token")
    assert bad.json()["active"] is False


def test_access_token_claims(client, registered_user, settings):
    payload = jwt.decode(
        registered_user["access_token"], settings.jwt_secret, algorithms=["HS256"]
    )
    assert payload["typ"] == "access"
    assert payload["name"] == "alice"
    assert payload["iss"] == settings.jwt_issuer
    assert payload["jti"]


def test_refresh_token_is_not_accepted_as_access(client, registered_user):
    """A refresh token must not work as a Bearer access token (RFC 6749 §5.1)."""
    client.cookies.clear()  # otherwise the session cookie silently refreshes
    resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {registered_user['refresh_token']}"},
    )
    assert resp.status_code == 401


def test_logout_revokes_refresh(client, registered_user):
    refresh = registered_user["refresh_token"]
    client.post("/api/v1/auth/logout")
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


def test_oauth_status_lists_local_provider(client):
    body = client.get("/api/v1/auth/oauth/status").json()
    assert body["enabled"] is True
    assert any(p["id"] == "local" for p in body["providers"])


def test_legacy_gyra_session_token_is_accepted(client, settings, registered_user):
    """A token minted by gyra_app.auth.session must still authenticate."""
    settings.legacy_session_secret = "legacy-secret"
    user = registered_user["user"]
    payload = {"user": user, "exp": int(time.time()) + 3600, "iat": int(time.time())}
    payload_b64 = _b64(json.dumps(payload, sort_keys=True))
    sig = hmac.new(b"legacy-secret", payload_b64.encode(), hashlib.sha256).hexdigest()
    legacy_token = f"{payload_b64}.{sig}"

    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {legacy_token}"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["name"] == "alice"


def test_disabled_user_cannot_login(client, registered_user):
    admin = client  # alice is the only user; promote via service below
    from gyra_user.db import session_scope
    from gyra_user.models import User

    with session_scope() as session:
        user = session.query(User).filter(User.name == "alice").one()
        user.role = "admin"
        session.flush()

    user_id = registered_user["user"]["id"]
    resp = admin.patch(f"/api/v1/admin/users/{user_id}", json={"is_active": False})
    assert resp.status_code == 200, resp.text

    client.post("/api/v1/auth/logout")
    resp = client.post(
        "/api/v1/auth/local/login", json={"username": "alice", "password": "secret123"}
    )
    assert resp.status_code == 403


def test_admin_endpoints_require_admin_role(client, registered_user):
    resp = client.get("/api/v1/admin/users")
    assert resp.status_code == 403


def test_admin_can_list_and_revoke(client, registered_user):
    from gyra_user.db import session_scope
    from gyra_user.models import User

    with session_scope() as session:
        session.query(User).filter(User.name == "alice").one().role = "admin"
        session.flush()

    listing = client.get("/api/v1/admin/users")
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    user_id = registered_user["user"]["id"]
    revoked = client.post(f"/api/v1/admin/users/{user_id}/revoke-sessions")
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] >= 1

    events = client.get("/api/v1/admin/login-events")
    assert events.status_code == 200
    assert any(e["action"] in ("login", "register") for e in events.json())
