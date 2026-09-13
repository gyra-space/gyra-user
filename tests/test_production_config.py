"""A service that boots with a default secret and hands out tokens is worse
than one that refuses to boot. Pin that behaviour.
"""

from __future__ import annotations

import pytest

from gyra_user.app import create_app
from gyra_user.config import Settings

STRONG_SECRET = "x" * 48


def _settings(**overrides) -> Settings:
    base = dict(
        jwt_secret=STRONG_SECRET,
        data_dir="data",
        database_url="sqlite:///:memory:",
        public_base_url="https://auth.example.com",
        oidc_enabled=True,
        environment="development",
        providers=[],
    )
    base.update(overrides)
    return Settings(**base)


def test_strong_config_has_no_problems():
    assert _settings().production_problems() == []


def test_weak_secret_is_flagged():
    problems = _settings(jwt_secret="secret").production_problems()
    assert any("jwt_secret" in p for p in problems)


def test_missing_public_base_url_is_flagged_when_oidc_enabled():
    problems = _settings(public_base_url="").production_problems()
    assert any("public_base_url" in p for p in problems)


def test_plaintext_base_url_is_flagged():
    problems = _settings(public_base_url="http://auth.example.com").production_problems()
    assert any("plain HTTP" in p for p in problems)


def test_rs256_requires_keys():
    problems = _settings(jwt_algorithm="RS256").production_problems()
    assert any("jwt_private_key" in p for p in problems)
    assert any("jwt_public_key" in p for p in problems)


def test_development_only_warns():
    app = create_app(_settings(jwt_secret="secret"))
    assert app is not None  # warnings logged, service still starts


def test_production_refuses_to_boot():
    with pytest.raises(RuntimeError, match="unsafe configuration"):
        create_app(_settings(jwt_secret="secret", environment="production"))


def test_production_hides_docs():
    app = create_app(_settings(environment="production"))
    assert app.docs_url is None


def test_development_keeps_docs():
    app = create_app(_settings(environment="development"))
    assert app.docs_url == "/docs"
