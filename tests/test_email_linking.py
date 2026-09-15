"""Email as an identity anchor — but only when both sides proved they own it.

Regression cover for a real account-takeover path: an attacker registers the
victim's address locally, the victim later signs in with an OAuth provider
that *has* verified that same address, and the old code merged the two
identities, handing the attacker the victim's account.

The rule these tests pin down: an address merges two identities only when the
provider asserts it is verified **and** the existing account's address is
verified too. Anything weaker is a claim, not proof.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from gyra_user.app import create_app
from gyra_user.config import ProviderConfig, Settings
from gyra_user.db import session_scope
from gyra_user.models import LoginEvent, OAuthAccount, User
from gyra_user.providers.base import _as_bool
from gyra_user.providers.github import GitHubProvider


class _FakeResponse:
    def __init__(self, data: Any):
        self._data = data

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._data


class FakeAsyncClient:
    """Stands in for ``httpx.AsyncClient``; routes by URL substring."""

    routes: Dict[str, Any] = {}

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def request(self, method, url, params=None, data=None, headers=None):
        for key, payload in FakeAsyncClient.routes.items():
            if key in url:
                return _FakeResponse(payload)
        raise AssertionError(f"unexpected request: {method} {url}")


@pytest.fixture()
def fake_http(monkeypatch):
    FakeAsyncClient.routes = {}
    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    yield FakeAsyncClient


SSO = ProviderConfig(
    id="sso",
    type="oidc",
    label="Fake SSO",
    client_id="cid",
    client_secret="csecret",
    scope="openid profile email",
    authorization_url="https://sso.test/authorize",
    token_url="https://sso.test/token",
    userinfo_url="https://sso.test/userinfo",
    id_path="sub",
    username_path="preferred_username",
    name_path="name",
    email_path="email",
    avatar_path="picture",
)


def _make_client(tmp_path, **overrides) -> TestClient:
    settings = Settings(
        jwt_secret="email-linking-secret-0123456789abcdef",
        data_dir=str(tmp_path),
        database_url=f"sqlite:///{tmp_path / 'linking.db'}",
        cookie_secure=False,
        providers=[SSO],
        **overrides,
    )
    return TestClient(create_app(settings))


def _route_sso(email: Any, email_verified: Any, subject: str = "sso-1") -> None:
    FakeAsyncClient.routes = {
        "sso.test/token": {"access_token": "at-1", "expires_in": 3600},
        "sso.test/userinfo": {
            "sub": subject,
            "preferred_username": "dana",
            "name": "Dana Scully",
            "email": email,
            "email_verified": email_verified,
            "picture": "https://cdn.test/dana.png",
        },
    }


def _register(client, username: str, email: str) -> int:
    resp = client.post(
        "/api/v1/auth/local/register",
        json={"username": username, "password": "secret123", "email": email},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["user"]["id"]


def _mark_verified(user_id: int) -> None:
    """Simulate a completed email-verification step on an existing account."""
    with session_scope() as session:
        user = session.get(User, user_id)
        assert user is not None
        user.email_verified = True


def _users() -> List[Dict[str, Any]]:
    with session_scope() as session:
        rows = session.query(User).order_by(User.id).all()
        return [
            {
                "id": row.id,
                "name": row.name,
                "email": row.email or "",
                "verified": bool(row.email_verified),
            }
            for row in rows
        ]


def _events(action: str) -> List[Dict[str, Any]]:
    with session_scope() as session:
        rows = (
            session.query(LoginEvent)
            .filter(LoginEvent.action == action)
            .order_by(LoginEvent.id)
            .all()
        )
        return [{"user_id": row.user_id, "detail": row.detail or ""} for row in rows]


def _oauth_login(client, provider: str = "sso", subject: str = "sso-1"):
    """Walk the full authorization-code flow against the mocked provider."""
    start = client.get(
        f"/api/v1/auth/oauth/login?provider={provider}", follow_redirects=False
    )
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return client.get(
        f"/api/v1/auth/oauth/callback?code=code-abc&state={state}",
        follow_redirects=False,
    )


# ── the takeover path ──────────────────────────────────────────────────────


def test_verified_provider_email_reclaims_from_squatter(tmp_path, fake_http):
    """The attack: squat the victim's address, then wait for their login."""
    client = _make_client(tmp_path)
    squatter_id = _register(client, "squatter", "victim@example.com")
    _route_sso("victim@example.com", True)

    assert _oauth_login(client).status_code == 302

    rows = _users()
    # Two accounts: the squatter and the real owner. No merge happened.
    assert len(rows) == 2, rows
    assert rows[0]["id"] == squatter_id

    squatter, owner = rows
    assert squatter["email"] == ""  # claimed but never proven
    assert squatter["verified"] is False
    assert owner["email"] == "victim@example.com"
    assert owner["verified"] is True

    # The squatter did not get the provider binding, and the hand-off is audited.
    with session_scope() as session:
        binding = session.query(OAuthAccount).one()
        assert binding.user_id == owner["id"]
    reclaimed = _events("email_reclaimed")
    assert len(reclaimed) == 1
    assert reclaimed[0]["user_id"] == squatter_id


def test_unverified_provider_email_never_merges(tmp_path, fake_http):
    """A provider that did not verify the address has proved nothing."""
    client = _make_client(tmp_path)
    local_id = _register(client, "bob", "bob@example.com")
    _mark_verified(local_id)
    _route_sso("bob@example.com", False)

    assert _oauth_login(client, subject="sso-2").status_code == 302

    rows = _users()
    assert len(rows) == 2, rows
    local, oauth_user = rows
    # The verified local account keeps its address untouched...
    assert (local["email"], local["verified"]) == ("bob@example.com", True)
    # ...and the unproven claim does not get to sit on it either.
    assert (oauth_user["email"], oauth_user["verified"]) == ("", False)

    refused = _events("link_refused")
    assert len(refused) == 1
    assert refused[0]["user_id"] == local_id
    assert "did not verify" in refused[0]["detail"]


def test_verified_on_both_sides_still_merges(tmp_path, fake_http):
    """The normal case must keep working — this is not a merge removal."""
    client = _make_client(tmp_path)
    local_id = _register(client, "carol", "carol@example.com")
    _mark_verified(local_id)
    _route_sso("carol@example.com", True)

    assert _oauth_login(client, subject="sso-3").status_code == 302

    rows = _users()
    assert len(rows) == 1, rows
    assert rows[0]["id"] == local_id
    with session_scope() as session:
        binding = session.query(OAuthAccount).one()
        assert binding.user_id == local_id


def test_reclaim_disabled_leaves_address_with_nobody(tmp_path, fake_http):
    """With reclaiming off, neither side ends up holding the address."""
    client = _make_client(tmp_path, reclaim_unverified_email=False)
    squatter_id = _register(client, "dave", "dave@example.com")
    _route_sso("dave@example.com", True)

    assert _oauth_login(client, subject="sso-4").status_code == 302

    rows = _users()
    assert len(rows) == 2, rows
    assert rows[0]["id"] == squatter_id
    assert (rows[0]["email"], rows[0]["verified"]) == ("dave@example.com", False)
    assert (rows[1]["email"], rows[1]["verified"]) == ("", False)
    assert _events("email_reclaimed") == []
    assert len(_events("link_refused")) == 1


def test_link_by_email_off_never_merges(tmp_path, fake_http):
    client = _make_client(tmp_path, link_by_email=False)
    local_id = _register(client, "eve", "eve@example.com")
    _mark_verified(local_id)
    _route_sso("eve@example.com", True)

    assert _oauth_login(client, subject="sso-5").status_code == 302

    rows = _users()
    assert len(rows) == 2, rows
    assert rows[0]["id"] == local_id
    with session_scope() as session:
        binding = session.query(OAuthAccount).one()
        assert binding.user_id == rows[1]["id"]


def test_legacy_mode_restores_old_linking(tmp_path, fake_http):
    """``link_by_email_requires_verified=False`` is the escape hatch."""
    client = _make_client(tmp_path, link_by_email_requires_verified=False)
    local_id = _register(client, "frank", "frank@example.com")
    _route_sso("frank@example.com", False)

    assert _oauth_login(client, subject="sso-6").status_code == 302

    rows = _users()
    assert len(rows) == 1, rows
    assert rows[0]["id"] == local_id


# ── local registration must never mint a verified address ──────────────────


def test_local_registration_leaves_email_unverified(tmp_path):
    client = _make_client(tmp_path)
    _register(client, "gina", "gina@example.com")
    rows = _users()
    assert (rows[0]["email"], rows[0]["verified"]) == ("gina@example.com", False)


def test_changing_email_clears_verification(tmp_path):
    """A new address is a fresh claim, even for an already-verified account."""
    client = _make_client(tmp_path)
    user_id = _register(client, "hank", "hank@example.com")
    _mark_verified(user_id)

    resp = client.patch("/api/v1/account/profile", json={"email": "other@x.com"})
    assert resp.status_code in (200, 204), resp.text

    rows = _users()
    assert (rows[0]["email"], rows[0]["verified"]) == ("other@x.com", False)


# ── provider claims ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "claim,expected",
    [
        (True, True),
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        (1, True),
        (False, False),
        ("false", False),
        (0, False),
        ("", False),
        (None, False),
        ("maybe", False),
    ],
)
def test_email_verified_claim_parsing(claim, expected):
    assert _as_bool(claim) is expected


class _StubClient:
    def __init__(self, routes: Dict[str, Any]):
        self.routes = routes

    async def request(self, method, url, params=None, data=None, headers=None):
        for key, payload in self.routes.items():
            if key in url:
                return _FakeResponse(payload)
        raise AssertionError(f"unexpected request: {method} {url}")


def _github(routes: Dict[str, Any]) -> GitHubProvider:
    config = ProviderConfig(
        id="github", type="github", client_id="ghid", client_secret="ghsecret"
    )
    return GitHubProvider(config, _StubClient(routes))


async def test_github_ignores_unverified_addresses():
    """GitHub keeps unverified addresses on file; they are not proof."""
    provider = _github(
        {
            "/user/emails": [
                {"email": "made-up@example.com", "primary": True, "verified": False}
            ]
        }
    )
    assert await provider._primary_email("tok") == ("", False)


async def test_github_prefers_verified_primary_address():
    provider = _github(
        {
            "/user/emails": [
                {"email": "alt@example.com", "primary": False, "verified": True},
                {"email": "main@example.com", "primary": True, "verified": True},
            ]
        }
    )
    assert await provider._primary_email("tok") == ("main@example.com", True)


async def test_github_login_with_only_unverified_address_creates_unverified_user():
    """End to end: a public-but-unverified profile address stays unverified."""
    provider = _github(
        {
            "/user/emails": [
                {"email": "public@example.com", "primary": True, "verified": False}
            ],
            "api.github.com/user": {
                "id": 99,
                "login": "octo",
                "name": "Octo",
                "email": "public@example.com",
                "avatar_url": "https://avatars.test/o.png",
            },
        }
    )
    from gyra_user.providers.base import TokenResponse

    profile = await provider.fetch_profile(TokenResponse(access_token="tok"))
    assert profile.email == "public@example.com"
    assert profile.email_verified is False
