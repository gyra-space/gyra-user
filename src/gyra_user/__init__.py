"""Gyra 用户中心 — standalone OAuth2 auth service, mountable into Gyra.

Quick start::

    uvicorn gyra_user.app:app --reload --port 8100

Mount into an existing FastAPI app::

    from gyra_user import create_auth_router, create_admin_router, create_oidc_router
    app.include_router(create_auth_router(), prefix="/api/v1")
    app.include_router(create_oidc_router(prefix="/api/v1"))
"""

from __future__ import annotations

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "create_account_router",
    "create_admin_router",
    "create_app",
    "create_auth_router",
    "create_oidc_router",
    "load_settings",
]


def __getattr__(name: str):
    # Imported lazily so that `import gyra_user` stays side-effect free.
    if name == "create_auth_router":
        from gyra_user.router import create_auth_router as _fn
    elif name == "create_admin_router":
        from gyra_user.admin import create_admin_router as _fn
    elif name == "create_account_router":
        from gyra_user.account import create_account_router as _fn
    elif name == "create_oidc_router":
        from gyra_user.oidc import create_oidc_router as _fn
    elif name == "create_app":
        from gyra_user.app import create_app as _fn
    elif name == "load_settings":
        from gyra_user.config import load_settings as _fn
    else:  # pragma: no cover
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = _fn
    return _fn
