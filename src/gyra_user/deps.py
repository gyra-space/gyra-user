"""FastAPI dependencies: settings, DB session, current user, role guards."""

from __future__ import annotations

import logging
from typing import Iterator, Optional

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from gyra_user.config import Settings, load_settings
from gyra_user.db import get_db as _get_db
from gyra_user.models import User
from gyra_user.security import decode_token, verify_legacy_token
from gyra_user.service import UserService

logger = logging.getLogger(__name__)

_settings: Optional[Settings] = None


def configure(settings: Settings) -> Settings:
    """Install the process-wide settings instance (used by create_app/CLI)."""
    global _settings
    _settings = settings
    return settings


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def get_db() -> Iterator[Session]:
    yield from _get_db()


def get_user_service(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Iterator[UserService]:
    yield UserService(session, settings)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = request.headers.get("x-real-ip", "")
    if real:
        return real.strip()
    return request.client.host if request.client else ""


def extract_token(request: Request, settings: Settings) -> Optional[str]:
    """Read the bearer token from the Authorization header or the cookie."""
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    cookie_name = settings.legacy_session_cookie or settings.cookie_name
    return request.cookies.get(cookie_name) or request.cookies.get(settings.cookie_name)


def refresh_cookie_name(settings: Settings) -> str:
    return f"{settings.cookie_name}_refresh"


def resolve_user(
    request: Request,
    service: UserService,
    settings: Settings,
    response: Optional[Response] = None,
) -> Optional[User]:
    """Resolve the caller from a JWT, falling back to a legacy Gyra token.

    When the access token is expired but a valid refresh cookie is present the
    tokens are silently rotated and the fresh cookies written onto ``response``.
    """
    token = extract_token(request, settings)
    if not token:
        return None

    payload = None
    try:
        payload = decode_token(settings, token, expected_type="access")
    except Exception:  # noqa: BLE001 - fall through to refresh / legacy
        payload = None

    if payload is None and response is not None:
        rotated = _try_silent_refresh(request, service, settings, response)
        if rotated is not None:
            return rotated

    if payload is not None:
        user_id = payload.get("sub")
        try:
            user = service.get_by_id(int(user_id)) if user_id is not None else None
        except (TypeError, ValueError):
            user = None
        if user is None:
            return None
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled",
            )
        return user

    # Last resort: a token minted by gyra_app.auth.session (HMAC, not JWT).
    legacy = verify_legacy_token(settings, token)
    if legacy is None:
        return None
    user = _user_from_legacy_claims(service, legacy)
    if user is None:
        return None
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled"
        )
    logger.debug("Accepted legacy Gyra session for user id=%s", user.id)
    return user


def _try_silent_refresh(
    request: Request,
    service: UserService,
    settings: Settings,
    response: Response,
) -> Optional[User]:
    """Rotate an expiring browser session using the refresh cookie."""
    from gyra_user.tokens import set_auth_cookies

    refresh_token = request.cookies.get(refresh_cookie_name(settings))
    if not refresh_token:
        return None
    try:
        tokens = service.rotate_refresh_token(
            refresh_token,
            user_agent=request.headers.get("user-agent", ""),
            ip=client_ip(request),
        )
    except Exception:  # noqa: BLE001 - an invalid refresh cookie is not fatal
        return None
    user = service.get_by_id(int(tokens["user"]["id"]))
    if user is None or not user.is_active:
        return None
    set_auth_cookies(response, settings, request, tokens)
    return user


def _user_from_legacy_claims(service: UserService, claims: dict) -> Optional[User]:
    user_id = claims.get("id")
    if isinstance(user_id, int):
        user = service.get_by_id(user_id)
        if user is not None:
            return user
    provider = claims.get("oauth_provider")
    oauth_id = claims.get("oauth_id")
    if provider and oauth_id:
        binding = service.get_oauth_account(provider, str(oauth_id))
        if binding is not None:
            return service.get_by_id(binding.user_id)
    name = claims.get("name")
    if name:
        return service.get_by_username(name)
    return None


def get_current_user(
    request: Request,
    response: Response,
    service: UserService = Depends(get_user_service),
    settings: Settings = Depends(get_settings),
) -> User:
    user = resolve_user(request, service, settings, response=response)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    if user.is_pending:
        raise HTTPException(status_code=403, detail="Account pending approval")
    return user


def require_admin(user: User = Depends(get_current_active_user)) -> User:
    if (user.role or "normal") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def get_optional_user(
    request: Request,
    response: Response,
    service: UserService = Depends(get_user_service),
    settings: Settings = Depends(get_settings),
) -> Optional[User]:
    return resolve_user(request, service, settings, response=response)


__all__ = [
    "client_ip",
    "configure",
    "extract_token",
    "get_current_active_user",
    "get_current_user",
    "get_db",
    "get_optional_user",
    "get_settings",
    "get_user_service",
    "require_admin",
    "resolve_user",
]
