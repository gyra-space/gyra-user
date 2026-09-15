"""Standalone ASGI application factory.

Run it directly::

    uvicorn gyra_user.app:app --reload

or embed it in Gyra::

    from gyra_user.app import create_app
    app.mount("/user", create_app(settings))
"""

from __future__ import annotations

import json
import logging
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from gyra_user import deps
from gyra_user.account import create_account_router
from gyra_user.admin import create_admin_router
from gyra_user.branding import resolve_with_session
from gyra_user.config import Settings, load_settings
from gyra_user.db import init_engine
from gyra_user.oidc import create_oidc_router
from gyra_user.router import create_auth_router

logger = logging.getLogger(__name__)

#: Used when the distribution metadata is missing *or* unreadable. A
#: half-finished reinstall leaves a dist-info directory behind whose Version
#: cannot be read, and FastAPI refuses to build an app from a falsy version —
#: a cosmetic detail must not be able to stop the service from booting.
_FALLBACK_VERSION = "0.0.0+dev"

try:
    __version__ = _pkg_version("gyra-user") or _FALLBACK_VERSION
except PackageNotFoundError:  # running from a source checkout
    __version__ = _FALLBACK_VERSION

# `login.html` ships with this token where the branding payload goes; the
# string is deliberately invalid JSON so a half-rendered page fails loudly in
# dev instead of silently showing stale copy.
BRANDING_PLACEHOLDER = "/*__BRANDING_JSON__*/"


def _inline_json(payload: Dict[str, Any]) -> str:
    """Serialise for a ``<script type="application/json">`` block.

    ``</script>`` anywhere in the copy would close the tag early, so every
    ``</`` is escaped — still valid JSON, still parsed by ``JSON.parse``.
    """
    return json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")


def _check_configuration(settings: Settings) -> None:
    """Warn (or refuse to boot) when the config is unsafe for production."""
    problems = settings.production_problems()
    if not problems:
        return
    if settings.environment == "production":
        raise RuntimeError(
            "refusing to start with unsafe configuration:\n  - "
            + "\n  - ".join(problems)
        )
    for problem in problems:
        logger.warning("config: %s", problem)


def create_app(
    settings: Optional[Settings] = None, api_prefix: str = "/api/v1"
) -> FastAPI:
    settings = settings or load_settings()
    _check_configuration(settings)
    deps.configure(settings)
    # In production the schema is owned by Alembic (see `gyra-user db upgrade`,
    # which the container entrypoint and systemd unit run before start). Creating
    # tables here would race across workers.
    auto_create = settings.environment != "production"
    init_engine(
        settings.resolved_database_url(),
        echo=settings.debug,
        create_tables=auto_create,
    )

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="统一用户中心：OAuth2 / OIDC 单点登录 / 微信 / GitHub / 本地账号",
        # Dev/staging keep the interactive docs; production hides the API surface.
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
    )
    app.state.settings = settings

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(create_auth_router(settings), prefix=api_prefix)
    app.include_router(create_admin_router(settings), prefix=api_prefix)
    app.include_router(create_account_router(settings), prefix=api_prefix)
    if settings.oidc_enabled:
        # Discovery must live at the issuer root, so no api_prefix here.
        app.include_router(create_oidc_router(settings))

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def page(name: str, branding: Optional[Dict[str, Any]] = None):
        target = static_dir / name
        if not target.is_file():
            return JSONResponse({"detail": f"{name} not bundled"}, status_code=404)
        if branding is None:
            return FileResponse(str(target))
        # Inlining the copy keeps the first paint correct — fetching it after
        # the HTML lands would flash the fallback markup on every page load.
        html = target.read_text(encoding="utf-8").replace(
            BRANDING_PLACEHOLDER, _inline_json(branding)
        )
        return HTMLResponse(html)

    @app.get("/healthz", tags=["System"])
    async def healthz():
        return {"status": "ok", "service": settings.app_name}

    @app.get("/login", include_in_schema=False)
    async def login_page(
        app_id: str = Query("", alias="app", description="接入应用 id"),
        lang: str = Query("", description="语言，如 zh / en"),
        session: Session = Depends(deps.get_db),
    ):
        branding = resolve_with_session(
            session, settings.branding, app_id=app_id, locale=lang
        )
        return page("login.html", branding)

    @app.get("/account", include_in_schema=False)
    async def account_page():
        return page("account.html")

    @app.get("/admin", include_in_schema=False)
    async def admin_page():
        return page("admin.html")

    @app.get("/", include_in_schema=False)
    async def root(
        app_id: str = Query("", alias="app", description="接入应用 id"),
        lang: str = Query("", description="语言，如 zh / en"),
        session: Session = Depends(deps.get_db),
    ):
        index = static_dir / "login.html"
        if index.is_file():
            branding = resolve_with_session(
                session, settings.branding, app_id=app_id, locale=lang
            )
            return page("login.html", branding)
        return {
            "service": settings.app_name,
            "docs": "/docs",
            "endpoints": [
                f"{api_prefix}/auth/oauth/status",
                f"{api_prefix}/auth/oauth/login",
                f"{api_prefix}/auth/me",
            ],
        }

    return app


_cached_app: Optional[FastAPI] = None


def build_default_app() -> FastAPI:
    """Lazily build (and cache) the standalone app.

    Keeping this lazy means ``import gyra_user`` never touches the database —
    important when Gyra only mounts the router.
    """
    global _cached_app
    if _cached_app is None:
        _cached_app = create_app()
    return _cached_app


def __getattr__(name: str):  # pragma: no cover - uvicorn entrypoint
    if name == "app":
        return build_default_app()
    raise AttributeError(name)


__all__ = ["build_default_app", "create_app"]
