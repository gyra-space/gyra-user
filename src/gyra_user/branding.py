"""Brand copy for the hosted pages (left panel of ``/login``).

Resolution is per ``(app_id, locale)`` and falls back one step at a time, so a
deployment only overrides what it actually wants to change::

    app+locale  ->  app+default_locale
                ->  default app+locale
                ->  default app+default_locale
                ->  built-in copy

An app's own copy outranks a better language match on purpose: an app that only
wrote Chinese words still keeps its own name and pitch for an English visitor.
Configure both locales per app if that matters.

Three sources feed that chain, highest precedence first:

1. a database override saved from ``/admin`` — applies on the next page load,
   no restart (this is what makes the copy hot-swappable);
2. the ``[branding]`` table of the TOML config;
3. the built-in copy at the bottom of this module.

The front end never reads the database itself: it either gets the payload
inlined into ``/login`` (so the first paint is already correct) or fetches
``/api/v1/auth/branding`` when the visitor switches language or app.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from gyra_user.models import BrandingOverride

logger = logging.getLogger(__name__)

DEFAULT_APP_ID = "default"
DEFAULT_LOCALE = "zh"


class BrandingTheme(BaseModel):
    """Colours the login page adopts, so each app can look like itself."""

    primary: str = "#4f46e5"
    primary_hover: str = "#4338ca"


class BrandingSlide(BaseModel):
    """One screen of the left panel."""

    title: str = ""
    subtitle: str = ""
    features: List[str] = Field(default_factory=list)
    footer: str = ""


class BrandingContent(BaseModel):
    """One app's copy in one language."""

    app_name: str = ""
    # Several slides turn the left panel into a carousel; a single ``title`` /
    # ``subtitle`` / ``features`` triple is the shorthand for the common case.
    slides: List[BrandingSlide] = Field(default_factory=list)
    title: str = ""
    subtitle: str = ""
    features: List[str] = Field(default_factory=list)
    footer: str = ""
    # Overrides for the page's chrome (buttons, labels, alerts). Merged over
    # BUILTIN_UI for the resolved locale, so translating a page never means
    # touching the HTML.
    ui: Dict[str, str] = Field(default_factory=dict)

    def normalized_slides(self) -> List[BrandingSlide]:
        meaningful = [s for s in self.slides if s.title or s.subtitle or s.features]
        if meaningful:
            return meaningful
        if self.title or self.subtitle or self.features:
            return [
                BrandingSlide(
                    title=self.title,
                    subtitle=self.subtitle,
                    features=list(self.features),
                    footer=self.footer,
                )
            ]
        return []


class Branding(BaseModel):
    """The ``[branding]`` section of the config."""

    enabled: bool = True
    default_locale: str = DEFAULT_LOCALE
    # Locales offered in the page's language switcher. Empty -> derived from
    # the copy that actually exists.
    locales: List[str] = Field(default_factory=list)
    # Seconds between slides; 0 keeps the panel static.
    rotate_interval: int = 0
    theme: BrandingTheme = Field(default_factory=BrandingTheme)
    # app_id -> locale -> copy. Provider credentials never live here, so the
    # map is safe to keep in a committed config file.
    apps: Dict[str, Dict[str, BrandingContent]] = Field(default_factory=dict)


# ─────────────────────────── built-in copy ────────────────────────────────

BUILTIN_COPY: Dict[str, BrandingContent] = {
    "zh": BrandingContent(
        app_name="Gyra 用户中心",
        title="Gyra 用户中心",
        subtitle=(
            "统一的 OAuth2 / OIDC 认证服务。支持 GitHub、微信开放平台扫码登录"
            "与本地账号，数据落在 SQLite，可作为独立服务运行，也可以一行代码"
            "挂载进 Gyra。"
        ),
        features=[
            "标准 OAuth2 授权码流程，state + PKCE 防 CSRF",
            "JWT Access Token + 可轮换 / 可吊销 Refresh Token",
            "内置 OIDC Provider，一次登录全站通行（单点登录）",
            "微信 unionid 打通公众号与网站应用，同人同账号",
            "兼容 Gyra 现有 /api/v1/auth/* 契约，前端零改动",
        ],
    ),
    "en": BrandingContent(
        app_name="Gyra Identity",
        title="Gyra Identity",
        subtitle=(
            "One OAuth2 / OIDC service for every app you run. Sign in with "
            "GitHub, WeChat or a local account; data stays in SQLite and the "
            "whole thing mounts into Gyra in one line."
        ),
        features=[
            "Standard authorization code flow with state + PKCE",
            "Rotatable, revocable refresh tokens alongside JWT access tokens",
            "Built-in OIDC provider for single sign-on across your apps",
            "WeChat unionid links official accounts and websites to one user",
            "Speaks Gyra's /api/v1/auth/* contract, so no frontend change",
        ],
    ),
}


def _copy_for(locale: str) -> Optional[BrandingContent]:
    return BUILTIN_COPY.get(locale)


def builtin_locales() -> List[str]:
    return list(BUILTIN_COPY)


# Page chrome, per locale. Keys match the ``data-i18n`` attributes in
# login.html, so adding a language is a data edit rather than a code edit.
BUILTIN_UI: Dict[str, Dict[str, str]] = {
    "zh": {
        "login": "登录",
        "register": "注册",
        "subtitle_pick": "选择一种方式继续",
        "subtitle_register": "创建新账号",
        "tab_third_party": "第三方登录",
        "tab_password": "账号密码",
        "or": "或",
        "wechat_qr": "微信扫码登录",
        "username": "用户名",
        "username_placeholder": "用户名或邮箱",
        "email": "邮箱",
        "fullname": "昵称",
        "fullname_placeholder": "选填",
        "password": "密码",
        "password_placeholder": "至少 6 位",
        "confirm": "确认密码",
        "confirm_placeholder": "再输入一次",
        "agree": "我已阅读并同意服务条款与隐私政策",
        "register_link": "注册新账号",
        "back_login": "已有账号？去登录",
        "back": "返回登录",
        "continue": "继续",
        "continue_app": "继续访问应用",
        "logout": "退出登录",
        "account": "个人中心",
        "admin": "管理后台",
        "api_docs": "API 文档",
        "logged_in": "已登录",
        "no_email": "无邮箱",
        "err_required": "请输入用户名和密码",
        "err_username_len": "用户名至少 3 个字符",
        "err_password_len": "密码至少 6 位",
        "err_password_mismatch": "两次输入的密码不一致",
        "err_agree": "请先同意服务条款与隐私政策",
        "err_pending": "注册成功，等待管理员审核",
        "err_login_failed": "登录失败：",
    },
    "en": {
        "login": "Sign in",
        "register": "Create account",
        "subtitle_pick": "Choose how to continue",
        "subtitle_register": "Create a new account",
        "tab_third_party": "Third-party",
        "tab_password": "Password",
        "or": "or",
        "wechat_qr": "Sign in with WeChat",
        "username": "Username",
        "username_placeholder": "Username or email",
        "email": "Email",
        "fullname": "Display name",
        "fullname_placeholder": "Optional",
        "password": "Password",
        "password_placeholder": "At least 6 characters",
        "confirm": "Confirm password",
        "confirm_placeholder": "Type it again",
        "agree": "I agree to the terms of service and privacy policy",
        "register_link": "Create an account",
        "back_login": "Already have an account? Sign in",
        "back": "Back to sign in",
        "continue": "Continue",
        "continue_app": "Continue to the app",
        "logout": "Sign out",
        "account": "Account",
        "admin": "Admin",
        "api_docs": "API docs",
        "logged_in": "Signed in",
        "no_email": "no email",
        "err_required": "Enter your username and password",
        "err_username_len": "Username needs at least 3 characters",
        "err_password_len": "Password needs at least 6 characters",
        "err_password_mismatch": "The two passwords do not match",
        "err_agree": "Please accept the terms of service first",
        "err_pending": "Registered. Waiting for admin approval",
        "err_login_failed": "Sign-in failed: ",
    },
}


# ───────────────────────────── resolution ─────────────────────────────────


def _from_config(
    branding: Branding, app_id: str, locale: str
) -> Optional[BrandingContent]:
    return (branding.apps.get(app_id) or {}).get(locale)


def _lookup(
    branding: Branding,
    overrides: Dict[Tuple[str, str], BrandingContent],
    app_id: str,
    locale: str,
) -> Tuple[Optional[BrandingContent], str]:
    """An admin override wins over the config file for the same key."""
    override = overrides.get((app_id, locale))
    if override is not None and override.normalized_slides():
        return override, "override"
    configured = _from_config(branding, app_id, locale)
    if configured is not None and configured.normalized_slides():
        return configured, "config"
    return None, ""


def resolve_branding(
    branding: Branding,
    app_id: str = "",
    locale: str = "",
    overrides: Optional[Dict[Tuple[str, str], BrandingContent]] = None,
) -> Dict[str, Any]:
    """Resolve the payload the pages render, plus where each piece came from."""
    app_id = (app_id or "").strip() or DEFAULT_APP_ID
    default_locale = (branding.default_locale or "").strip().lower() or DEFAULT_LOCALE
    locale = (locale or "").strip().lower() or default_locale

    content: Optional[BrandingContent] = None
    source = "builtin"
    chain = (
        (app_id, locale),
        (app_id, default_locale),
        (DEFAULT_APP_ID, locale),
        (DEFAULT_APP_ID, default_locale),
    )
    for candidate_app, candidate_locale in chain:
        hit, hit_source = _lookup(
            branding, overrides or {}, candidate_app, candidate_locale
        )
        if hit is not None:
            content, source = hit, hit_source
            break
    if content is None:
        content = (
            _copy_for(locale)
            or _copy_for(default_locale)
            or (BUILTIN_COPY[DEFAULT_LOCALE])
        )

    slides = content.normalized_slides()
    first = slides[0] if slides else BrandingSlide()

    ui = dict(
        BUILTIN_UI.get(locale)
        or BUILTIN_UI.get(default_locale)
        or BUILTIN_UI[DEFAULT_LOCALE]
    )
    # A configured locale may fill gaps the built-in table does not have yet.
    ui = {**BUILTIN_UI.get(default_locale, {}), **ui, **(content.ui or {})}

    locales: List[str] = []
    for candidate in (
        list(branding.locales or [])
        + list((branding.apps.get(app_id) or {}).keys())
        + list((branding.apps.get(DEFAULT_APP_ID) or {}).keys())
        + builtin_locales()
        + [locale]
    ):
        normalized = (candidate or "").strip().lower()
        if normalized and normalized not in locales:
            locales.append(normalized)

    return {
        "app_id": app_id,
        "locale": locale,
        "default_locale": default_locale,
        "app_name": content.app_name or first.title,
        "title": first.title,
        "subtitle": first.subtitle,
        "features": list(first.features),
        "footer": content.footer or first.footer,
        "slides": [slide.model_dump() for slide in slides],
        "locales": locales,
        "ui": ui,
        "theme": branding.theme.model_dump(),
        "rotate_interval": max(0, int(branding.rotate_interval or 0)),
        # Surfaced so an operator can tell a hot override from the config file
        # without reading the database.
        "source": source,
    }


# ──────────────────────── database override layer ─────────────────────────


class BrandingStore:
    """Reads and writes the admin-saved overrides."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def overrides_for(
        self,
        app_id: str,
        locale: str,
        default_locale: str = DEFAULT_LOCALE,
    ) -> Dict[Tuple[str, str], BrandingContent]:
        """Load just the keys the fallback chain can reach (one query)."""
        app_ids = {app_id or DEFAULT_APP_ID, DEFAULT_APP_ID}
        locales = {locale or default_locale, default_locale}
        try:
            rows = self.session.scalars(
                select(BrandingOverride).where(
                    BrandingOverride.app_id.in_(app_ids),
                    BrandingOverride.locale.in_(locales),
                    BrandingOverride.is_active.is_(True),
                )
            ).all()
        except Exception as exc:  # noqa: BLE001
            # An un-migrated database must not take the login page down; the
            # config file still resolves, the override layer is simply empty.
            logger.warning("branding overrides unavailable: %s", exc)
            return {}

        result: Dict[Tuple[str, str], BrandingContent] = {}
        for row in rows:
            content = _decode_payload(row.payload)
            if content is not None:
                result[(row.app_id, row.locale)] = content
        return result

    def list_all(self) -> List[Dict[str, Any]]:
        rows = self.session.scalars(
            select(BrandingOverride).order_by(
                BrandingOverride.app_id, BrandingOverride.locale
            )
        ).all()
        return [
            {
                "app_id": row.app_id,
                "locale": row.locale,
                "is_active": bool(row.is_active),
                "payload": _decode_payload(row.payload) or BrandingContent(),
                "gmt_create": row.gmt_create.isoformat() if row.gmt_create else None,
                "gmt_modify": row.gmt_modify.isoformat() if row.gmt_modify else None,
            }
            for row in rows
        ]

    def get(self, app_id: str, locale: str) -> Optional[BrandingOverride]:
        return self.session.scalars(
            select(BrandingOverride).where(
                BrandingOverride.app_id == app_id,
                BrandingOverride.locale == locale,
            )
        ).first()

    def upsert(
        self,
        app_id: str,
        locale: str,
        content: BrandingContent,
        is_active: bool = True,
    ) -> BrandingOverride:
        row = self.get(app_id, locale)
        payload = content.model_dump_json()
        if row is None:
            row = BrandingOverride(
                app_id=app_id, locale=locale, payload=payload, is_active=is_active
            )
            self.session.add(row)
        else:
            row.payload = payload
            row.is_active = is_active
        self.session.flush()
        return row

    def delete(self, app_id: str, locale: str) -> bool:
        row = self.get(app_id, locale)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True


def resolve_with_session(
    session: Session,
    branding: Branding,
    app_id: str = "",
    locale: str = "",
) -> Dict[str, Any]:
    """Resolve for a request, layering the admin overrides from the database.

    Every caller that has a session should use this rather than
    :func:`resolve_branding` directly, so a saved override shows up on the very
    next page load instead of after a restart.
    """
    default_locale = (branding.default_locale or "").strip().lower() or DEFAULT_LOCALE
    store = BrandingStore(session)
    overrides = store.overrides_for(
        (app_id or "").strip() or DEFAULT_APP_ID,
        (locale or "").strip().lower() or default_locale,
        default_locale,
    )
    return resolve_branding(branding, app_id=app_id, locale=locale, overrides=overrides)


def _decode_payload(raw: Optional[str]) -> Optional[BrandingContent]:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        logger.warning("ignoring malformed branding payload")
        return None
    if not isinstance(data, dict):
        return None
    try:
        return BrandingContent(**data)
    except Exception as exc:  # noqa: BLE001 - a bad row must not break login
        logger.warning("ignoring invalid branding payload: %s", exc)
        return None


__all__ = [
    "BUILTIN_COPY",
    "BUILTIN_UI",
    "DEFAULT_APP_ID",
    "DEFAULT_LOCALE",
    "Branding",
    "BrandingContent",
    "BrandingSlide",
    "BrandingStore",
    "BrandingTheme",
    "builtin_locales",
    "resolve_branding",
    "resolve_with_session",
]
