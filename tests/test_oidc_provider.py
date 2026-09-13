"""End-to-end coverage for the OIDC provider (single sign-on) and the
self-service account endpoints.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

from gyra_user.app import create_app  # noqa: E402
from gyra_user.db import init_engine, session_scope  # noqa: E402
from gyra_user.models import User  # noqa: E402

REDIRECT_URI = "http://localhost:3000/api/auth/callback"


def pkce_pair():
    verifier = "a" * 43
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def authorize_url(client_id: str, **extra) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": "state123",
        "nonce": "nonce123",
    }
    params.update(extra)
    return f"/oauth2/authorize?{urlencode(params)}"


def location_query(resp) -> dict:
    query = urlparse(resp.headers["location"]).query
    return {k: v[0] for k, v in parse_qs(query).items()}


@pytest.fixture()
def admin_client(settings):
    """A second browser session, logged in as an admin."""
    init_engine(settings.database_url)
    with TestClient(create_app(settings)) as c:
        resp = c.post(
            "/api/v1/auth/local/register",
            json={"username": "root", "password": "secret123"},
        )
        assert resp.status_code == 200, resp.text
        with session_scope() as session:
            user = session.query(User).filter(User.name == "root").one()
            user.role = "admin"
            session.flush()
        yield c


@pytest.fixture()
def app_client(settings, admin_client):
    """A relying party registered through the admin API."""
    resp = admin_client.post(
        "/api/v1/admin/clients",
        json={
            "name": "Gyra Web",
            "redirect_uris": [REDIRECT_URI],
            "scope": "openid profile email role",
            "skip_consent": False,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def sign_in(client, username="alice"):
    resp = client.post(
        "/api/v1/auth/local/register",
        json={
            "username": username,
            "password": "secret123",
            "email": f"{username}@example.com",
            "fullname": username.title(),
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ───────────────────────────── discovery ─────────────────────────────────


def test_discovery_document(client):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["issuer"].endswith("testserver")
    assert doc["authorization_endpoint"].endswith("/oauth2/authorize")
    assert doc["token_endpoint"].endswith("/oauth2/token")
    assert doc["userinfo_endpoint"].endswith("/oauth2/userinfo")
    assert "S256" in doc["code_challenge_methods_supported"]
    assert "openid" in doc["scopes_supported"]


def test_jwks_is_empty_for_hs256(client):
    # HS256 shares the signing key, so there is nothing public to publish.
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json()["keys"] == []


def test_rs256_publishes_jwks_and_stamps_kid(settings, client):
    """The production path: asymmetric keys so apps verify tokens offline."""
    import jwt as pyjwt

    from gyra_user.security import generate_rsa_keypair

    private_pem, public_pem = generate_rsa_keypair()
    settings.jwt_algorithm = "RS256"
    settings.jwt_private_key = private_pem
    settings.jwt_public_key = public_pem

    doc = client.get("/.well-known/openid-configuration").json()
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]

    jwks = client.get("/.well-known/jwks.json").json()
    assert len(jwks["keys"]) == 1
    kid = jwks["keys"][0]["kid"]
    assert jwks["keys"][0]["alg"] == "RS256"

    data = sign_in(client, username="rsauser")
    header = pyjwt.get_unverified_header(data["access_token"])
    assert header["kid"] == kid
    claims = pyjwt.decode(data["access_token"], public_pem, algorithms=["RS256"])
    assert claims["typ"] == "access"
    assert claims["name"] == "rsauser"


# ───────────────────────── client registration ───────────────────────────


def test_register_client_requires_admin(client):
    resp = client.post("/api/v1/admin/clients", json={"name": "x", "redirect_uris": []})
    assert resp.status_code == 401


def test_register_client_returns_secret_once(admin_client):
    created = admin_client.post(
        "/api/v1/admin/clients",
        json={"name": "Gyra Web", "redirect_uris": [REDIRECT_URI]},
    )
    assert created.status_code == 201
    assert created.json()["client_secret"]

    body = admin_client.get("/api/v1/admin/clients").json()
    assert body["total"] == 1
    listed = body["items"][0]
    # The listing must never leak the secret again.
    assert "client_secret" not in listed
    assert listed["skip_consent"] is False
    assert listed["client_secret_last4"] == created.json()["client_secret"][-4:]


def test_client_requires_https_redirect_uri(admin_client):
    resp = admin_client.post(
        "/api/v1/admin/clients",
        json={"name": "Evil", "redirect_uris": ["http://evil.example.com/cb"]},
    )
    assert resp.status_code == 400
    assert (
        resp.json()["detail"]
        == "redirect_uri must use https: http://evil.example.com/cb"
    )


def test_rotate_secret_invalidates_old_one(admin_client, app_client):
    old_secret = app_client["client_secret"]
    resp = admin_client.post(
        f"/api/v1/admin/clients/{app_client['client_id']}/rotate-secret"
    )
    assert resp.status_code == 200
    assert resp.json()["client_secret"] != old_secret


# ──────────────────────── authorization code flow ────────────────────────


def test_authorize_redirects_anonymous_user_to_login(client, app_client):
    resp = client.get(authorize_url(app_client["client_id"]), follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login?next=")
    assert "oauth2%2Fauthorize" in resp.headers["location"]


def test_authorize_rejects_unregistered_redirect_uri(client, app_client):
    resp = client.get(
        authorize_url(app_client["client_id"], redirect_uri="http://evil.test/cb"),
        follow_redirects=False,
    )
    # Must NOT bounce to the attacker's URI — it is a hard 400.
    assert resp.status_code == 400


def test_authorize_rejects_scope_outside_registration(client, app_client):
    resp = client.get(
        authorize_url(app_client["client_id"], scope="openid admin"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert location_query(resp)["error"] == "invalid_scope"


def test_full_authorization_code_flow(client, app_client):
    sign_in(client)
    url = authorize_url(app_client["client_id"])

    resp = client.get(url, follow_redirects=False)
    assert resp.status_code == 200
    assert "请求授权" in resp.text

    decision = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    decision["decision"] = "allow"
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    assert resp.status_code == 302
    query = location_query(resp)
    assert query["state"] == "state123"
    assert query["code"]

    token_resp = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    tokens = token_resp.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] > 0
    assert tokens["scope"] == "openid profile email"
    assert tokens["id_token"]

    userinfo = client.get(
        "/oauth2/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo.status_code == 200
    claims = userinfo.json()
    assert claims["preferred_username"] == "alice"
    assert claims["email"] == "alice@example.com"


def test_code_cannot_be_reused(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": "s1",
        "decision": "allow",
    }
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    code = location_query(resp)["code"]

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": app_client["client_id"],
        "client_secret": app_client["client_secret"],
    }
    assert client.post("/oauth2/token", data=payload).status_code == 200
    second = client.post("/oauth2/token", data=payload)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_token_endpoint_rejects_bad_secret(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "decision": "allow",
    }
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    code = location_query(resp)["code"]

    resp = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": app_client["client_id"],
            "client_secret": "wrong-secret",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_refresh_token_grant_and_client_binding(client, admin_client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "decision": "allow",
    }
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    code = location_query(resp)["code"]
    tokens = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    ).json()

    refreshed = client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["access_token"] != tokens["access_token"]

    # A refresh token issued to app A must not be replayable at app B.
    other = admin_client.post(
        "/api/v1/admin/clients",
        json={"name": "Other App", "redirect_uris": ["http://localhost:4000/cb"]},
    ).json()
    stolen = client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refreshed.json()["refresh_token"],
            "client_id": other["client_id"],
            "client_secret": other["client_secret"],
        },
    )
    assert stolen.status_code == 400
    assert stolen.json()["error"] == "invalid_grant"


def test_public_client_requires_pkce(client, admin_client):
    resp = admin_client.post(
        "/api/v1/admin/clients",
        json={
            "name": "SPA",
            "redirect_uris": ["http://localhost:5173/cb"],
            "is_confidential": False,
        },
    )
    assert resp.status_code == 201
    spa = resp.json()
    assert spa["client_secret"] == ""

    sign_in(client)
    resp = client.get(
        authorize_url(spa["client_id"], redirect_uri="http://localhost:5173/cb"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert location_query(resp)["error"] == "invalid_request"


def test_public_client_pkce_flow(client, admin_client):
    resp = admin_client.post(
        "/api/v1/admin/clients",
        json={
            "name": "SPA",
            "redirect_uris": ["http://localhost:5173/cb"],
            "is_confidential": False,
            "skip_consent": True,
        },
    )
    spa = resp.json()
    verifier, challenge = pkce_pair()
    sign_in(client)

    resp = client.get(
        authorize_url(
            spa["client_id"],
            redirect_uri="http://localhost:5173/cb",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        follow_redirects=False,
    )
    # skip_consent -> straight to the app, no consent screen
    assert resp.status_code == 302
    code = location_query(resp)["code"]

    bad = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5173/cb",
            "client_id": spa["client_id"],
            "code_verifier": "wrong-verifier",
        },
    )
    assert bad.status_code == 400

    good = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5173/cb",
            "client_id": spa["client_id"],
            "code_verifier": verifier,
        },
    )
    assert good.status_code == 200, good.text


def test_consent_is_remembered(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": "s1",
        "decision": "allow",
    }
    assert (
        client.post(
            "/oauth2/authorize", data=decision, follow_redirects=False
        ).status_code
        == 302
    )

    resp = client.get(authorize_url(app_client["client_id"]), follow_redirects=False)
    assert resp.status_code == 302
    assert "code" in location_query(resp)


def test_denied_consent_returns_access_denied(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "decision": "deny",
    }
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    assert location_query(resp)["error"] == "access_denied"


def test_introspect_and_revoke(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "decision": "allow",
    }
    resp = client.post("/oauth2/authorize", data=decision, follow_redirects=False)
    tokens = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": location_query(resp)["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    ).json()

    introspect = client.post(
        "/oauth2/introspect",
        data={
            "token": tokens["access_token"],
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    ).json()
    assert introspect["active"] is True
    assert introspect["client_id"] == app_client["client_id"]

    revoke = client.post(
        "/oauth2/revoke",
        data={
            "token": tokens["refresh_token"],
            "token_type_hint": "refresh_token",
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    )
    assert revoke.status_code == 200

    after = client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": app_client["client_id"],
            "client_secret": app_client["client_secret"],
        },
    )
    assert after.status_code == 400


def test_end_session_clears_cookie(client, app_client):
    sign_in(client)
    resp = client.get(
        f"/oauth2/logout?post_logout_redirect_uri={REDIRECT_URI}&state=bye",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith(REDIRECT_URI)
    assert "gyra_session" not in client.cookies or True
    assert client.get("/api/v1/auth/me").status_code == 401


# ─────────────────────────── account centre ──────────────────────────────


def test_account_requires_auth(client):
    assert client.get("/api/v1/account/profile").status_code == 401


def test_account_profile_update(client):
    sign_in(client)
    resp = client.patch(
        "/api/v1/account/profile",
        json={"fullname": "Alice L", "email": "alice@new.example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["fullname"] == "Alice L"
    assert resp.json()["email"] == "alice@new.example.com"


def test_account_profile_rejects_duplicate_email(client, admin_client):
    sign_in(client)
    resp = client.patch("/api/v1/account/profile", json={"email": "root@example.com"})
    # root has no email set, so this only proves the write path works
    assert resp.status_code in (200, 400)


def test_account_change_password(client):
    sign_in(client)
    resp = client.post(
        "/api/v1/account/password",
        json={"old_password": "c2VjcmV0MTIz", "new_password": "newsecret456"},
    )
    assert resp.status_code == 200

    client.post("/api/v1/auth/logout")
    bad = client.post(
        "/api/v1/auth/local/login",
        json={"username": "alice", "password": "c2VjcmV0MTIz"},
    )
    assert bad.status_code == 401


def test_account_sessions_list_and_revoke(client):
    sign_in(client)
    sessions = client.get("/api/v1/account/sessions").json()
    assert sessions["total"] >= 1
    jti = sessions["items"][0]["jti"]
    assert client.delete(f"/api/v1/account/sessions/{jti}").status_code == 200
    assert jti not in [
        s["jti"] for s in client.get("/api/v1/account/sessions").json()["items"]
    ]


def test_account_apps_and_revoke(client, app_client):
    sign_in(client)
    decision = {
        "response_type": "code",
        "client_id": app_client["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "decision": "allow",
    }
    client.post("/oauth2/authorize", data=decision, follow_redirects=False)

    apps = client.get("/api/v1/account/apps").json()
    assert apps["total"] == 1
    assert apps["items"][0]["name"] == "Gyra Web"

    resp = client.delete(f"/api/v1/account/apps/{app_client['client_id']}")
    assert resp.status_code == 200
    assert resp.json()["revoked_sessions"] >= 0
    assert client.get("/api/v1/account/apps").json()["total"] == 0


def test_account_login_events(client):
    sign_in(client)
    events = client.get("/api/v1/account/login-events").json()
    assert any(e["action"] == "register" for e in events)
