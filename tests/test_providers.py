"""Provider-level tests: URL building, WeChat error handling, identity linking."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from gyra_user.config import ProviderConfig
from gyra_user.providers import create_provider
from gyra_user.providers.base import OAuthError, OAuthProfile
from gyra_user.providers.wechat import WeChatOpenProvider


def test_github_authorize_url():
    provider = create_provider(
        ProviderConfig(id="github", type="github", client_id="cid", scope="read:user")
    )
    url = provider.build_authorize_url("http://localhost/api/cb", "state123")
    parsed = urlparse(url)
    assert parsed.netloc == "github.com"
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["cid"]
    assert query["state"] == ["state123"]
    assert query["response_type"] == ["code"]
    assert not provider.supports_pkce  # GitHub does not implement PKCE


def test_wechat_qrconnect_url_shape():
    provider = create_provider(
        ProviderConfig(
            id="wechat", type="wechat_open", client_id="wxappid", scope="snsapi_login"
        )
    )
    assert isinstance(provider, WeChatOpenProvider)
    url = provider.build_authorize_url("https://example.com/api/cb", "st")
    assert url.startswith("https://open.weixin.qq.com/connect/qrconnect?")
    assert url.endswith("#wechat_redirect")
    query = parse_qs(urlparse(url.split("#")[0]).query)
    assert query["appid"] == ["wxappid"]
    assert query["scope"] == ["snsapi_login"]
    assert query["redirect_uri"] == ["https://example.com/api/cb"]


def test_wechat_mp_authorize_url():
    provider = create_provider(
        ProviderConfig(
            id="mp", type="wechat_mp", client_id="wxmp", scope="snsapi_userinfo"
        )
    )
    url = provider.build_authorize_url("https://example.com/cb", "st")
    assert "connect/oauth2/authorize" in url


def test_unknown_provider_type():
    with pytest.raises(ValueError):
        create_provider(ProviderConfig(id="x", type="nope", client_id="a"))


def test_oidc_provider_requires_urls_to_enable():
    cfg = ProviderConfig(id="sso", type="oidc", client_id="a", client_secret="b")
    assert cfg.enabled is False


def test_wechat_userinfo_normalisation():
    provider = create_provider(
        ProviderConfig(
            id="wechat", type="wechat_open", client_id="a", client_secret="b"
        )
    )
    profile = provider.normalize_profile(
        {
            "openid": "oXyz123",
            "unionid": "union-1",
            "nickname": "张三",
            "headimgurl": "https://wx.qlogo.cn/x",
        }
    )
    assert profile.subject == "oXyz123"
    assert profile.unionid == "union-1"
    assert profile.display_name == "张三"
    assert profile.email is None  # WeChat never returns email


def test_wechat_errcode_raises_oauth_error():
    provider = create_provider(
        ProviderConfig(
            id="wechat", type="wechat_open", client_id="a", client_secret="b"
        )
    )
    with pytest.raises(OAuthError):
        provider._check_err(
            {"errcode": 40029, "errmsg": "invalid code"}, "token exchange"
        )


def test_github_profile_normalisation():
    provider = create_provider(
        ProviderConfig(id="github", type="github", client_id="a", client_secret="b")
    )
    profile = provider.normalize_profile(
        {
            "id": 9919,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octo@github.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/9919",
        }
    )
    assert profile.subject == "9919"
    assert profile.username == "octocat"
    assert profile.email == "octo@github.com"


def test_identity_linking_by_unionid(settings):
    """Two WeChat apps (open + mp) with one unionid must resolve to one user."""
    from gyra_user.db import init_engine, session_scope
    from gyra_user.models import User
    from gyra_user.service import UserService

    init_engine(settings.database_url)
    service_ctx = settings

    with session_scope() as session:
        service = UserService(session, service_ctx)
        user1, created1 = service.upsert_from_oauth(
            OAuthProfile(
                provider="wechat",
                subject="open-id-1",
                unionid="union-abc",
                display_name="张三",
            )
        )
        assert created1 is True

    with session_scope() as session:
        service = UserService(session, service_ctx)
        user2, created2 = service.upsert_from_oauth(
            OAuthProfile(
                provider="wechat_mp",
                subject="mp-id-2",
                unionid="union-abc",
                display_name="张三",
            )
        )
        assert created2 is False
        assert user2.id == user1.id

        bindings = service.list_bindings(user2.id)
        assert {b.provider for b in bindings} == {"wechat", "wechat_mp"}

        total = session.query(User).count()
        assert total == 1


def test_identity_linking_by_email(settings):
    from gyra_user.db import init_engine, session_scope
    from gyra_user.models import User
    from gyra_user.service import UserService

    init_engine(settings.database_url)

    with session_scope() as session:
        service = UserService(session, settings)
        local = service.create_local_user("carol", "password123", email="c@example.com")
        local_id = local.id

    with session_scope() as session:
        service = UserService(session, settings)
        user, created = service.upsert_from_oauth(
            OAuthProfile(
                provider="github",
                subject="4242",
                username="carol-gh",
                email="c@example.com",
                email_verified=True,
            )
        )
        assert created is False
        assert user.id == local_id
        assert session.query(User).count() == 1
