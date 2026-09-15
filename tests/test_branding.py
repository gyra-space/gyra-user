"""Brand copy is the thing an operator edits most often, so its resolution
rules — app / locale fallback, config layering and the hot-update path — are
worth pinning rather than eyeballing on the login page.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

from gyra_user.app import BRANDING_PLACEHOLDER, create_app  # noqa: E402
from gyra_user.branding import (  # noqa: E402
    Branding,
    BrandingContent,
    BrandingSlide,
    resolve_branding,
)
from gyra_user.config import config_files, load_settings  # noqa: E402
from gyra_user.db import init_engine, session_scope  # noqa: E402
from gyra_user.models import User  # noqa: E402


def _isolate_env(monkeypatch) -> None:
    """Drop inherited GYRA_USER_* so the file layer is what we are testing."""
    for key in list(os.environ):
        if key.startswith("GYRA_USER_"):
            monkeypatch.delenv(key, raising=False)


# ───────────────────────────── resolution ─────────────────────────────────


def test_builtin_copy_is_the_last_resort():
    data = resolve_branding(Branding())
    assert data["source"] == "builtin"
    assert data["slides"][0]["title"]
    assert data["ui"]["login"]


def test_config_copy_beats_builtin():
    branding = Branding(
        apps={"default": {"zh": BrandingContent(title="ACME", features=["one"])}}
    )
    data = resolve_branding(branding)
    assert (data["title"], data["source"]) == ("ACME", "config")


def test_app_falls_back_to_the_default_app():
    branding = Branding(
        apps={
            "default": {"zh": BrandingContent(title="BASE", features=["f"])},
            "gyra-web": {"zh": BrandingContent(title="GYRA", features=["g"])},
        }
    )
    assert resolve_branding(branding, app_id="gyra-web")["title"] == "GYRA"
    assert resolve_branding(branding, app_id="nobody")["title"] == "BASE"


def test_unknown_locale_falls_back_to_the_default_locale():
    branding = Branding(
        apps={"default": {"zh": BrandingContent(title="中文", features=["f"])}}
    )
    data = resolve_branding(branding, locale="fr")
    assert data["locale"] == "fr"
    assert data["title"] == "中文"


def test_slides_take_precedence_over_the_shorthand():
    content = BrandingContent(
        title="ignored",
        features=["ignored"],
        slides=[BrandingSlide(title="one"), BrandingSlide(title="two")],
    )
    data = resolve_branding(Branding(apps={"default": {"zh": content}}))
    assert [slide["title"] for slide in data["slides"]] == ["one", "two"]


def test_an_empty_content_falls_through_instead_of_blanking_the_panel():
    branding = Branding(
        apps={
            "default": {
                "zh": BrandingContent(title="BASE", features=["f"]),
                # An override that renders nothing must not win.
                "en": BrandingContent(),
            }
        }
    )
    data = resolve_branding(branding, locale="en")
    assert data["title"] == "BASE"


def test_override_wins_over_the_config_file():
    branding = Branding(
        apps={"default": {"zh": BrandingContent(title="CFG", features=["f"])}}
    )
    overrides = {("default", "zh"): BrandingContent(title="OPS", features=["o"])}
    data = resolve_branding(branding, overrides=overrides)
    assert (data["title"], data["source"]) == ("OPS", "override")


def test_locale_switcher_offers_builtin_languages():
    data = resolve_branding(Branding())
    assert {"zh", "en"} <= set(data["locales"])


# ───────────────────────────── endpoints ──────────────────────────────────


def test_branding_endpoint_is_public_and_locale_aware(client):
    assert client.get("/api/v1/auth/branding").status_code == 200

    english = client.get("/api/v1/auth/branding?lang=en").json()
    assert english["locale"] == "en"
    assert english["ui"]["login"] == "Sign in"


def test_branding_endpoint_reports_the_app_it_resolved_for(client):
    data = client.get("/api/v1/auth/branding?app=gyra-web").json()
    assert data["app_id"] == "gyra-web"


def test_login_page_inlines_the_resolved_copy(client):
    html = client.get("/login").text
    assert BRANDING_PLACEHOLDER not in html
    assert '"slides"' in html
    assert "Gyra 用户中心" in html


def test_login_page_honours_app_and_lang(client):
    html = client.get("/login?app=demo&lang=en").text
    assert '"app_id": "demo"' in html
    assert "Gyra Identity" in html


def test_login_page_survives_a_json_hostile_payload(client, settings):
    """``</script>`` in the copy must not close the inline block early."""
    settings.branding = Branding(
        apps={
            "default": {"zh": BrandingContent(title="</script><b>x", features=["ok"])}
        }
    )
    html = client.get("/login").text
    assert "</script><b>x" not in html
    assert "<\\/script>" in html


# ─────────────────────── hot update from the admin UI ─────────────────────


@pytest.fixture()
def admin_client(settings):
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


def test_branding_write_requires_admin(client):
    resp = client.put(
        "/api/v1/admin/branding/default/zh", json={"content": {"title": "x"}}
    )
    assert resp.status_code in (401, 403)


def test_admin_override_shows_up_without_a_restart(admin_client):
    body = {"content": {"title": "OPS 标题", "features": ["第一", "第二"]}}

    saved = admin_client.put("/api/v1/admin/branding/default/zh", json=body)
    assert saved.status_code == 200, saved.text
    assert saved.json()["source"] == "override"

    assert "OPS 标题" in admin_client.get("/login").text
    assert "OPS 标题" in admin_client.get("/api/v1/auth/branding").text

    listed = admin_client.get("/api/v1/admin/branding").json()
    assert [(row["app_id"], row["locale"]) for row in listed] == [("default", "zh")]

    assert admin_client.delete("/api/v1/admin/branding/default/zh").status_code == 200
    assert "OPS 标题" not in admin_client.get("/login").text


def test_inactive_override_is_ignored(admin_client):
    body = {"content": {"title": "HIDDEN", "features": ["x"]}, "is_active": False}
    assert (
        admin_client.put("/api/v1/admin/branding/default/zh", json=body).status_code
        == 200
    )
    assert "HIDDEN" not in admin_client.get("/login").text


def test_per_app_override_does_not_leak_to_the_default(client, settings):
    settings.branding = Branding(
        apps={"default": {"zh": BrandingContent(title="BASE", features=["f"])}}
    )
    init_engine(settings.database_url)
    with TestClient(create_app(settings)) as c:
        c.post(
            "/api/v1/auth/local/register",
            json={"username": "boss", "password": "secret123"},
        )
        with session_scope() as session:
            session.query(User).filter(User.name == "boss").one().role = "admin"
            session.flush()
        c.put(
            "/api/v1/admin/branding/gyra-web/zh",
            json={"content": {"title": "ONLY GYRA", "features": ["x"]}},
        )
        assert "ONLY GYRA" in c.get("/login?app=gyra-web").text
        assert "ONLY GYRA" not in c.get("/login").text


# ─────────────────────────── config layering ──────────────────────────────


def test_local_config_layer_merges_over_the_base(tmp_path, monkeypatch):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "auth.toml").write_text(
        'app_name = "Base"\n'
        "[[providers]]\n"
        'id = "github"\n'
        'type = "github"\n'
        'label = "GitHub"\n'
        'client_id = ""\n',
        encoding="utf-8",
    )
    (tmp_path / "configs" / "auth.local.toml").write_text(
        "[[providers]]\n"
        'id = "github"\n'
        'client_id = "cid-123"\n'
        "\n[branding]\n"
        "rotate_interval = 9\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _isolate_env(monkeypatch)

    settings = load_settings()

    assert len(config_files()) == 2
    assert settings.app_name == "Base"
    github = settings.provider("github")
    # Only the key the local file declares is replaced.
    assert (github.client_id, github.label) == ("cid-123", "GitHub")
    assert settings.branding.rotate_interval == 9


def test_env_beats_the_toml_file(tmp_path, monkeypatch):
    (tmp_path / "auth.toml").write_text('app_name = "From file"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _isolate_env(monkeypatch)
    monkeypatch.setenv("GYRA_USER_APP_NAME", "From env")

    assert load_settings().app_name == "From env"


def test_local_layer_still_applies_when_config_env_var_is_set(tmp_path, monkeypatch):
    """Pointing GYRA_USER_CONFIG elsewhere must not disable local overrides."""
    (tmp_path / "shared.toml").write_text('app_name = "Shared"\n', encoding="utf-8")
    (tmp_path / "auth.local.toml").write_text(
        "\n[branding]\nrotate_interval = 4\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    _isolate_env(monkeypatch)
    monkeypatch.setenv("GYRA_USER_CONFIG", "shared.toml")

    settings = load_settings()

    assert [p.name for p in config_files()] == ["shared.toml", "auth.local.toml"]
    assert settings.app_name == "Shared"
    assert settings.branding.rotate_interval == 4


def test_explicit_overrides_beat_the_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _isolate_env(monkeypatch)
    monkeypatch.setenv("GYRA_USER_APP_NAME", "From env")

    assert load_settings(overrides={"app_name": "Forced"}).app_name == "Forced"
