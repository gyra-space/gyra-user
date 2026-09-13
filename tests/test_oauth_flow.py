"""Full OAuth2 authorization-code flow against a mocked provider.

Covers the parts we cannot hit with real credentials: state validation,
code exchange, first-login provisioning, WeChat's ``errcode`` failures.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from gyra_user.app import create_app
from gyra_user.config import ProviderConfig, Settings


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
    calls: List[Dict[str, Any]] = []

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def request(self, method, url, params=None, data=None, headers=None):
        FakeAsyncClient.calls.append(
            {"method": method, "url": url, "params": params, "data": data}
        )
        for key, payload in FakeAsyncClient.routes.items():
            if key in url:
                if callable(payload):
                    payload = payload(params or data or {})
                return _FakeResponse(payload)
        raise AssertionError(f"unexpected request: {method} {url}")


@pytest.fixture()
def fake_http(monkeypatch):
    FakeAsyncClient.routes = {}
    FakeAsyncClient.calls = []
    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    yield FakeAsyncClient


OIDC_PROVIDER = ProviderConfig(
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

WECHAT_PROVIDER = ProviderConfig(
    id="wechat",
    type="wechat_open",
    label="微信",
    client_id="wxappid",
    client_secret="wxsecret",
    scope="snsapi_login",
)


def _make_client(tmp_path, providers) -> TestClient:
    settings = Settings(
        jwt_secret="oauth-test-secret-key-0123456789abcdef",
        data_dir=str(tmp_path),
        database_url=f"sqlite:///{tmp_path / 'oauth.db'}",
        cookie_secure=False,
        providers=providers,
    )
    return TestClient(create_app(settings))


def test_authorize_redirect_and_state(tmp_path, fake_http):
    client = _make_client(tmp_path, [OIDC_PROVIDER])
    resp = client.get("/api/v1/auth/oauth/login?provider=sso", follow_redirects=False)
    assert resp.status_code in (302, 307), resp.text
    location = resp.headers["location"]
    assert location.startswith("https://sso.test/authorize?")

    query = parse_qs(urlparse(location).query)
    assert query["client_id"] == ["cid"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid profile email"]
    # PKCE is on for OIDC providers
    assert query["code_challenge_method"] == ["S256"]
    assert "state" in query


def test_full_callback_creates_user(tmp_path, fake_http):
    fake_http.routes = {
        "sso.test/token": {
            "access_token": "at-123",
            "refresh_token": "rt-123",
            "expires_in": 7200,
        },
        "sso.test/userinfo": {
            "sub": "user-42",
            "preferred_username": "dana",
            "name": "Dana Scully",
            "email": "dana@example.com",
            "picture": "https://cdn.test/dana.png",
        },
    }
    client = _make_client(tmp_path, [OIDC_PROVIDER])

    start = client.get("/api/v1/auth/oauth/login?provider=sso", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

    cb = client.get(
        f"/api/v1/auth/oauth/callback?code=code-abc&state={state}",
        follow_redirects=False,
    )
    assert cb.status_code == 302
    assert "/auth/callback/#token=" in cb.headers["location"]
    assert "gyra_session" in cb.cookies

    me = client.get("/api/v1/auth/me").json()
    assert me["user"]["name"] == "dana"
    assert me["user"]["email"] == "dana@example.com"
    assert me["user"]["oauth_provider"] == "sso"
    assert me["user"]["avatar"] == "https://cdn.test/dana.png"

    bindings = client.get("/api/v1/auth/bindings").json()
    assert bindings[0]["provider"] == "sso"
    assert bindings[0]["provider_uid"] == "user-42"

    # Second login must reuse the same account, not create a new one.
    start2 = client.get("/api/v1/auth/oauth/login?provider=sso", follow_redirects=False)
    state2 = parse_qs(urlparse(start2.headers["location"]).query)["state"][0]
    client.get(
        f"/api/v1/auth/oauth/callback?code=code-abc&state={state2}",
        follow_redirects=False,
    )
    from gyra_user.db import session_scope
    from gyra_user.models import User

    with session_scope() as session:
        assert session.query(User).count() == 1


def test_invalid_state_is_rejected(tmp_path, fake_http):
    client = _make_client(tmp_path, [OIDC_PROVIDER])
    resp = client.get(
        "/api/v1/auth/oauth/callback?code=abc&state=tampered",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "error=invalid_state" in resp.headers["location"]


def test_wechat_login_builds_qrconnect_and_creates_user(tmp_path, fake_http):
    fake_http.routes = {
        "api.weixin.qq.com/sns/oauth2/access_token": {
            "access_token": "wx-at",
            "expires_in": 7200,
            "refresh_token": "wx-rt",
            "openid": "oOPEN123",
            "unionid": "union-xyz",
            "scope": "snsapi_login",
        },
        "api.weixin.qq.com/sns/userinfo": {
            "openid": "oOPEN123",
            "unionid": "union-xyz",
            "nickname": "微信用户",
            "headimgurl": "https://wx.qlogo.cn/abc",
        },
    }
    client = _make_client(tmp_path, [WECHAT_PROVIDER])

    start = client.get(
        "/api/v1/auth/oauth/login?provider=wechat", follow_redirects=False
    )
    location = start.headers["location"]
    assert location.startswith("https://open.weixin.qq.com/connect/qrconnect?")
    assert location.endswith("#wechat_redirect")
    query = parse_qs(urlparse(location.split("#")[0]).query)
    assert query["appid"] == ["wxappid"]  # WeChat uses appid, not client_id

    state = query["state"][0]
    cb = client.get(
        f"/api/v1/auth/oauth/callback?code=wxcode&state={state}",
        follow_redirects=False,
    )
    assert "/auth/callback/#token=" in cb.headers["location"]

    me = client.get("/api/v1/auth/me").json()
    assert me["user"]["oauth_provider"] == "wechat"
    assert me["user"]["oauth_id"] == "oOPEN123"
    assert me["user"]["avatar"] == "https://wx.qlogo.cn/abc"
    # WeChat never returns an email, so the account stays email-less.
    assert me["user"]["email"] == ""


def test_wechat_error_response_redirects_to_login(tmp_path, fake_http):
    fake_http.routes = {
        "api.weixin.qq.com/sns/oauth2/access_token": {
            "errcode": 40029,
            "errmsg": "invalid code",
        }
    }
    client = _make_client(tmp_path, [WECHAT_PROVIDER])
    start = client.get(
        "/api/v1/auth/oauth/login?provider=wechat", follow_redirects=False
    )
    state = parse_qs(urlparse(start.headers["location"].split("#")[0]).query)["state"][
        0
    ]

    cb = client.get(
        f"/api/v1/auth/oauth/callback?code=bad&state={state}", follow_redirects=False
    )
    assert "error=token_exchange_failed" in cb.headers["location"]


def test_qr_page_renders_iframe(tmp_path, fake_http):
    client = _make_client(tmp_path, [WECHAT_PROVIDER])
    resp = client.get("/api/v1/auth/oauth/qr/wechat")
    assert resp.status_code == 200
    assert "open.weixin.qq.com/connect/qrconnect" in resp.text
    # the iframe must hand the code back to our own qr/done landing page
    assert "auth%2Foauth%2Fqr%2Fdone" in resp.text


def test_unknown_provider_returns_400(tmp_path, fake_http):
    client = _make_client(tmp_path, [OIDC_PROVIDER])
    resp = client.get("/api/v1/auth/oauth/login?provider=nope", follow_redirects=False)
    assert resp.status_code == 400


def test_open_redirect_is_not_possible(tmp_path, fake_http):
    """``redirect_after`` must be sanitised to a same-site relative path."""
    from gyra_user.router import _safe_next

    assert _safe_next("https://evil.test") == ""
    assert _safe_next("//evil.test") == ""
    assert _safe_next("/login?x=1") == ""
    assert _safe_next("/workspace") == "/workspace"
