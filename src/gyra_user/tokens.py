"""Cookie helpers shared by the router and the auth dependencies."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

from fastapi import Request, Response

from gyra_user.config import Settings
from gyra_user.deps import refresh_cookie_name


def parent_domain(request: Request) -> Optional[str]:
    """Return the shared parent domain, or None for localhost / raw IPs.

    Browsers reject ``Domain=`` on IP hosts, which silently breaks login — the
    exact bug Gyra hit when it set the cookie on every host.
    """
    host = request.headers.get("host", "").split(":")[0]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost":
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 2:
        return "." + ".".join(parts[-2:])
    return None


def _cookie_kwargs(settings: Settings, request: Request) -> Dict[str, Any]:
    secure = settings.cookie_secure
    if secure is None:
        secure = request.url.scheme == "https"
    return {
        "httponly": True,
        "secure": secure,
        "samesite": settings.cookie_samesite,
        "domain": settings.cookie_domain or parent_domain(request),
        "path": settings.cookie_path,
    }


def set_auth_cookies(
    response: Response,
    settings: Settings,
    request: Request,
    tokens: Dict[str, Any],
) -> None:
    kwargs = _cookie_kwargs(settings, request)
    access_max_age = int(tokens.get("expires_in") or settings.access_token_ttl)
    refresh_max_age = int(
        tokens.get("refresh_expires_in") or settings.refresh_token_ttl
    )
    response.set_cookie(
        key=settings.cookie_name,
        value=tokens["access_token"],
        max_age=access_max_age,
        **kwargs,
    )
    response.set_cookie(
        key=refresh_cookie_name(settings),
        value=tokens["refresh_token"],
        max_age=refresh_max_age,
        **kwargs,
    )


def clear_auth_cookies(
    response: Response, settings: Settings, request: Request
) -> None:
    kwargs = _cookie_kwargs(settings, request)
    response.delete_cookie(
        key=settings.cookie_name, path=settings.cookie_path, domain=kwargs["domain"]
    )
    response.delete_cookie(
        key=refresh_cookie_name(settings),
        path=settings.cookie_path,
        domain=kwargs["domain"],
    )


def base_url(request: Request, settings: Settings) -> str:
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")


__all__ = [
    "base_url",
    "clear_auth_cookies",
    "parent_domain",
    "set_auth_cookies",
]
