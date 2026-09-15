"""A provider only shows up on the login page when its credentials reach
``Settings.providers``. Three ways in — TOML, the ``GYRA_USER_*`` shortcuts and
``.env`` — all have to land, otherwise the page silently drops to
password-only and looks like a UI bug.
"""

from __future__ import annotations

import pytest

from gyra_user.config import Settings, load_settings

BASE_TOML = """
app_name = "Test"

[[providers]]
id = "github"
type = "github"
label = "GitHub"

[[providers]]
id = "wechat"
type = "wechat_open"
label = "微信"
"""

ENV_KEYS = (
    "GYRA_USER_GITHUB_CLIENT_ID",
    "GYRA_USER_GITHUB_CLIENT_SECRET",
    "GYRA_USER_GITHUB_SCOPE",
    "GYRA_USER_WECHAT_APP_ID",
    "GYRA_USER_WECHAT_APP_SECRET",
    "GYRA_USER_WECHAT_MP_APP_ID",
    "GYRA_USER_WECHAT_MP_APP_SECRET",
)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """A clean project directory: one TOML file, no stray environment."""
    (tmp_path / "auth.toml").write_text(BASE_TOML)
    monkeypatch.chdir(tmp_path)
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    return tmp_path


def _load(workdir) -> Settings:
    return load_settings(str(workdir / "auth.toml"))


def test_declared_but_uncredentialed_providers_are_disabled(workdir):
    """The shipped default: both blocks exist, neither is usable."""
    settings = _load(workdir)
    assert [p.id for p in settings.providers] == ["github", "wechat"]
    assert settings.enabled_providers() == []


def test_real_env_vars_enable_providers(workdir, monkeypatch):
    monkeypatch.setenv("GYRA_USER_GITHUB_CLIENT_ID", "gh-id")
    monkeypatch.setenv("GYRA_USER_GITHUB_CLIENT_SECRET", "gh-secret")
    monkeypatch.setenv("GYRA_USER_WECHAT_APP_ID", "wx-id")
    monkeypatch.setenv("GYRA_USER_WECHAT_APP_SECRET", "wx-secret")

    settings = _load(workdir)
    assert {p.id for p in settings.enabled_providers()} == {"github", "wechat"}
    assert settings.provider("github").client_id == "gh-id"
    assert settings.provider("wechat").client_secret == "wx-secret"


def test_dotenv_values_enable_providers(workdir):
    """Credentials in ``.env`` must work too — every other setting does."""
    (workdir / ".env").write_text(
        "GYRA_USER_GITHUB_CLIENT_ID=gh-from-dotenv\n"
        "GYRA_USER_GITHUB_CLIENT_SECRET=gh-secret\n"
    )
    settings = _load(workdir)
    assert [p.id for p in settings.enabled_providers()] == ["github"]


def test_real_env_beats_dotenv(workdir, monkeypatch):
    (workdir / ".env").write_text("GYRA_USER_GITHUB_CLIENT_ID=from-dotenv\n")
    monkeypatch.setenv("GYRA_USER_GITHUB_CLIENT_ID", "from-env")
    assert _load(workdir).provider("github").client_id == "from-env"


def test_env_credentials_resurrect_a_removed_provider(workdir, monkeypatch):
    """Deleting the TOML block should not silently discard the credentials."""
    (workdir / "auth.toml").write_text('app_name = "Test"\n')
    monkeypatch.setenv("GYRA_USER_GITHUB_CLIENT_ID", "gh-id")

    settings = _load(workdir)
    assert [p.id for p in settings.enabled_providers()] == ["github"]
    # Falls back to the shipped definition, not a bare stub.
    assert settings.provider("github").label == "GitHub"
    assert settings.provider("github").scope == "read:user user:email"


def test_local_toml_overlay_still_merges_by_id(workdir):
    """The git-ignored overlay adds credentials to a declared provider."""
    (workdir / "auth.local.toml").write_text(
        '[[providers]]\nid = "github"\nclient_id = "from-local"\n'
    )
    settings = _load(workdir)
    assert [p.id for p in settings.enabled_providers()] == ["github"]
    # Untouched fields survive the merge.
    assert settings.provider("github").label == "GitHub"
