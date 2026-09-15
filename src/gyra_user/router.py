"""Auth router — mount at ``/api/v1`` to get ``/api/v1/auth/*``.

Endpoint contract is byte-compatible with Gyra's ``auth_api.py`` so
``web/src/services/auth.ts`` keeps working without a frontend change.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from gyra_user import deps
from gyra_user.branding import resolve_with_session
from gyra_user.config import Settings
from gyra_user.models import User
from gyra_user.providers import get_provider
from gyra_user.providers.base import OAuthError
from gyra_user.schemas import (
    BrandingOut,
    LocalLoginRequest,
    LocalRegisterRequest,
    MeResponse,
    OAuthStatusOut,
    ProviderOut,
    RefreshRequest,
    TokenRequest,
    TokenResponseOut,
)
from gyra_user.security import (
    code_challenge,
    create_state_token,
    decode_token,
    new_code_verifier,
    verify_state_token,
)
from gyra_user.service import UserService, UserServiceError
from gyra_user.tokens import base_url, clear_auth_cookies, set_auth_cookies

logger = logging.getLogger(__name__)

ANONYMOUS_USER: Dict[str, Any] = {
    "id": 0,
    "name": "gyra",
    "fullname": "Gyra",
    "email": "",
    "avatar": "",
}


def create_auth_router(settings: Optional[Settings] = None) -> APIRouter:
    """Build the auth router.

    ``settings`` is optional: when omitted the router resolves the global
    settings through :func:`gyra_user.deps.get_settings`, which makes
    ``app.dependency_overrides`` work as usual in tests.
    """
    router = APIRouter(prefix="/auth", tags=["Auth"])

    def cfg() -> Settings:
        return settings or deps.get_settings()

    # ─────────────────────────── discovery ─────────────────────────────────

    @router.get("/oauth/status", response_model=OAuthStatusOut)
    async def oauth_status(config: Settings = Depends(cfg)):
        """Providers advertised to the login page."""
        if not config.auth_required:
            return {"enabled": False, "providers": [], "sso_auto_login_provider": None}

        providers: List[ProviderOut] = [
            ProviderOut(id=p.id, type=p.type, label=p.label)
            for p in config.enabled_providers()
        ]
        if config.allow_local_login and not any(p.id == "local" for p in providers):
            providers.insert(0, ProviderOut(id="local", type="local", label="账号密码"))

        return {
            "enabled": bool(providers),
            "providers": providers,
            "sso_auto_login_provider": config.sso_auto_login_provider or None,
        }

    @router.get("/providers", response_model=List[ProviderOut])
    async def list_providers(config: Settings = Depends(cfg)):
        return [
            ProviderOut(id=p.id, type=p.type, label=p.label)
            for p in config.enabled_providers()
        ]

    @router.get("/branding", response_model=BrandingOut)
    async def branding(
        app: str = Query("", description="接入应用 id，缺省 default"),
        lang: str = Query("", description="语言，如 zh / en"),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Copy for the hosted pages, resolved for one app + locale.

        Public on purpose — the login page has to render before anyone is
        authenticated. ``/login`` inlines the same payload, so a visitor who
        switches language or app gets identical content from either source.
        """
        return resolve_with_session(session, config.branding, app_id=app, locale=lang)

    # ──────────────────────── authorization code ───────────────────────────

    @router.get("/oauth/login")
    async def oauth_login(
        request: Request,
        provider: str = Query(..., description="Provider id, e.g. github / wechat"),
        redirect_after: str = Query("", description="Where to land after login"),
        display: str = Query("redirect", pattern="^(redirect|qr)$"),
        config: Settings = Depends(cfg),
    ):
        """Start the flow: 302 to the provider, or render an embedded QR page."""
        oauth_provider = get_provider(config.providers, provider)
        if oauth_provider is None:
            raise HTTPException(
                status_code=400, detail=f"Provider {provider!r} unavailable"
            )

        redirect_uri = f"{base_url(request, config)}/api/v1/auth/oauth/callback"
        if display == "qr" and oauth_provider.type == "wechat_open":
            redirect_uri = f"{base_url(request, config)}/api/v1/auth/oauth/qr/done"

        verifier = new_code_verifier() if oauth_provider.supports_pkce else ""
        state = create_state_token(
            config,
            provider=provider,
            redirect_after=_safe_next(redirect_after),
            code_verifier=verifier,
        )
        auth_url = oauth_provider.build_authorize_url(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge(verifier) if verifier else None,
        )

        if display == "qr" and oauth_provider.type == "wechat_open":
            return HTMLResponse(_qr_page(provider, auth_url, config))

        logger.info(
            "OAuth login start provider=%s redirect_uri=%s", provider, redirect_uri
        )
        return RedirectResponse(url=auth_url)

    @router.get("/oauth/qr/{provider}", response_class=HTMLResponse)
    async def oauth_qr_page(
        provider: str,
        request: Request,
        redirect_after: str = Query(""),
        config: Settings = Depends(cfg),
    ):
        """Embedded WeChat QR page (iframe + top-window hand-off)."""
        oauth_provider = get_provider(config.providers, provider)
        if oauth_provider is None:
            raise HTTPException(status_code=400, detail="Provider unavailable")
        redirect_uri = f"{base_url(request, config)}/api/v1/auth/oauth/qr/done"
        state = create_state_token(
            config, provider=provider, redirect_after=_safe_next(redirect_after)
        )
        auth_url = oauth_provider.build_authorize_url(
            redirect_uri=redirect_uri, state=state
        )
        return HTMLResponse(_qr_page(provider, auth_url, config))

    @router.get("/oauth/qr/done", response_class=HTMLResponse)
    async def oauth_qr_done(
        code: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
    ):
        """Landing page inside the QR iframe — hands the code to the top window."""
        if not code or not state:
            return HTMLResponse(
                "<script>window.top.location.href='/login?error=missing_params';</script>"
            )
        target = (
            f"/api/v1/auth/oauth/callback?{urlencode({'code': code, 'state': state})}"
        )
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
            "扫码成功，正在登录…"
            f"<script>window.top.location.href={target!r};</script>"
            "</body></html>"
        )

    @router.get("/oauth/callback")
    async def oauth_callback(
        request: Request,
        response: Response,
        code: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
        provider: Optional[str] = Query(None),
        error: Optional[str] = Query(None),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Provider redirect target — exchange code, mint tokens, hand to frontend."""
        if error:
            return _login_error(config, request, f"provider_error:{error}")
        if not code or not state:
            return _login_error(config, request, "missing_params")

        claims = verify_state_token(config, state)
        if claims is None:
            return _login_error(config, request, "invalid_state")

        provider_id = provider or claims.get("provider") or ""
        oauth_provider = get_provider(config.providers, provider_id)
        if oauth_provider is None:
            return _login_error(config, request, "invalid_provider")

        redirect_uri = f"{base_url(request, config)}/api/v1/auth/oauth/callback"
        service = UserService(session, config)

        try:
            token = await oauth_provider.exchange_code(
                code,
                redirect_uri=redirect_uri,
                code_verifier=claims.get("code_verifier") or None,
            )
            profile = await oauth_provider.fetch_profile(token)
        except OAuthError as exc:
            logger.warning("OAuth failed provider=%s: %s", provider_id, exc)
            return _login_error(config, request, "token_exchange_failed")
        except Exception as exc:  # noqa: BLE001
            logger.exception("OAuth failed provider=%s", provider_id)
            return _login_error(
                config, request, "token_exchange_failed", detail=str(exc)
            )

        if not profile.is_complete():
            return _login_error(config, request, "userinfo_failed")

        try:
            user, created = service.upsert_from_oauth(profile, token_payload=token.raw)
        except UserServiceError as exc:
            return _login_error(
                config, request, "user_create_failed", detail=exc.message
            )

        if not user.is_active:
            return _login_error(config, request, "user_disabled")
        if user.is_pending:
            return _login_error(config, request, "user_pending_approval")

        tokens = service.issue_tokens(
            user,
            user_agent=request.headers.get("user-agent", ""),
            ip=deps.client_ip(request),
        )
        service.touch_login(user, ip=deps.client_ip(request))
        service.record_event(
            user_id=user.id,
            username=user.name or "",
            provider=provider_id,
            action="register" if created else "login",
            success=True,
            ip=deps.client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
        session.commit()

        return _login_success(
            config,
            request,
            response,
            tokens,
            next_url=claims.get("redirect_after") or "",
        )

    # ─────────────────────────── session APIs ──────────────────────────────

    @router.get("/me")
    async def get_me(
        request: Request,
        response: Response,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Current user. Returns an anonymous profile when auth is optional."""
        service = UserService(session, config)
        user = deps.resolve_user(request, service, config, response=response)
        if user is None:
            if not config.auth_required:
                return JSONResponse(
                    {
                        "user": dict(ANONYMOUS_USER),
                        "user_channel": "mock",
                        "user_no": "0",
                        "nick_name": "Gyra",
                        "avatar_url": "",
                        "email": "",
                        "role": "admin",
                    }
                )
            raise HTTPException(status_code=401, detail="Not authenticated")
        return JSONResponse(_me_payload(user, channel=user.oauth_provider or "oauth"))

    @router.post("/logout")
    async def logout(
        request: Request,
        response: Response,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        refresh_token = request.cookies.get(deps.refresh_cookie_name(config))
        if refresh_token:
            service.revoke_refresh_token(refresh_token)
            session.commit()
        payload = JSONResponse(content={"success": True})
        clear_auth_cookies(payload, config, request)
        return payload

    @router.post("/refresh", response_model=TokenResponseOut)
    async def refresh(
        request: Request,
        response: Response,
        body: Optional[RefreshRequest] = None,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Rotate the refresh token. Body token wins, else the refresh cookie."""
        service = UserService(session, config)
        token_value = (body.refresh_token if body else None) or request.cookies.get(
            deps.refresh_cookie_name(config)
        )
        if not token_value:
            raise HTTPException(status_code=401, detail="Missing refresh token")
        try:
            tokens = service.rotate_refresh_token(
                token_value,
                user_agent=request.headers.get("user-agent", ""),
                ip=deps.client_ip(request),
            )
        except UserServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.message
            ) from exc
        session.commit()
        payload = JSONResponse(content=_public_tokens(tokens))
        set_auth_cookies(payload, config, request, tokens)
        return payload

    @router.post("/token", response_model=TokenResponseOut)
    async def token_endpoint(
        request: Request,
        response: Response,
        body: TokenRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """RFC 6749 token endpoint — ``password`` and ``refresh_token`` grants."""
        service = UserService(session, config)
        if body.grant_type == "refresh_token":
            if not body.refresh_token:
                raise HTTPException(status_code=400, detail="refresh_token required")
            try:
                tokens = service.rotate_refresh_token(
                    body.refresh_token,
                    user_agent=request.headers.get("user-agent", ""),
                    ip=deps.client_ip(request),
                )
            except UserServiceError as exc:
                raise HTTPException(
                    status_code=exc.status_code, detail=exc.message
                ) from exc
        else:  # password grant
            if not config.allow_local_login:
                raise HTTPException(status_code=403, detail="Local login disabled")
            if not body.username or not body.password:
                raise HTTPException(
                    status_code=400, detail="username/password required"
                )
            user = service.verify_local_user(body.username, body.password)
            if user is None:
                service.record_event(
                    None,
                    "failed",
                    success=False,
                    provider="local",
                    username=body.username,
                )
                session.commit()
                raise HTTPException(status_code=401, detail="Invalid credentials")
            _assert_usable(user)
            tokens = service.issue_tokens(
                user,
                user_agent=request.headers.get("user-agent", ""),
                ip=deps.client_ip(request),
            )
            service.touch_login(user, ip=deps.client_ip(request))
            service.record_event(
                user.id, "login", provider="local", username=user.name or ""
            )
        session.commit()
        payload = JSONResponse(content=_public_tokens(tokens))
        set_auth_cookies(payload, config, request, tokens)
        return payload

    @router.post("/introspect")
    async def introspect(
        token: str = Query(..., description="Access token to inspect"),
        config: Settings = Depends(cfg),
    ):
        """RFC 7662 — lets other services validate tokens without a shared DB."""
        try:
            payload = decode_token(config, token, expected_type="access")
        except Exception:  # noqa: BLE001
            return {"active": False}
        return {
            "active": True,
            "sub": payload.get("sub"),
            "username": payload.get("name"),
            "role": payload.get("role"),
            "provider": payload.get("provider"),
            "exp": payload.get("exp"),
            "iss": payload.get("iss"),
            "token_type": payload.get("typ"),
        }

    # ───────────────────────── local credentials ───────────────────────────

    @router.post("/local/login")
    async def local_login(
        request: Request,
        response: Response,
        body: LocalLoginRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Username/password login (Gyra sends the password base64-encoded)."""
        if not config.allow_local_login:
            raise HTTPException(status_code=403, detail="Local login disabled")
        service = UserService(session, config)
        user = service.verify_local_user(body.username, body.password)
        if user is None:
            service.record_event(
                None,
                "failed",
                success=False,
                provider="local",
                username=body.username,
                ip=deps.client_ip(request),
            )
            session.commit()
            raise HTTPException(status_code=401, detail="Invalid username or password")
        _assert_usable(user)

        tokens = service.issue_tokens(
            user,
            user_agent=request.headers.get("user-agent", ""),
            ip=deps.client_ip(request),
        )
        service.touch_login(user, ip=deps.client_ip(request))
        service.record_event(
            user.id,
            "login",
            provider="local",
            username=user.name or "",
            ip=deps.client_ip(request),
        )
        session.commit()

        content = _me_payload(user, channel="local")
        content.update(_public_tokens(tokens))
        payload = JSONResponse(content=content)
        set_auth_cookies(payload, config, request, tokens)
        return payload

    @router.post("/local/register")
    async def local_register(
        request: Request,
        response: Response,
        body: LocalRegisterRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        try:
            user = service.create_local_user(
                username=body.username,
                password=body.password,
                email=body.email or "",
                fullname=body.fullname or "",
            )
        except UserServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.message
            ) from exc
        session.commit()

        if user.is_pending:
            return JSONResponse(
                content={
                    "success": True,
                    "pending": True,
                    "message": "Registration submitted, waiting for admin approval",
                    "user": user.as_gyra_dict(),
                }
            )

        tokens = service.issue_tokens(
            user,
            user_agent=request.headers.get("user-agent", ""),
            ip=deps.client_ip(request),
        )
        session.commit()
        content = _me_payload(user, channel="local")
        content.update(_public_tokens(tokens))
        payload = JSONResponse(content=content)
        set_auth_cookies(payload, config, request, tokens)
        return payload

    # ─────────────────────── identity management ───────────────────────────

    @router.get("/bindings")
    async def my_bindings(
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        return [binding.to_dict() for binding in service.list_bindings(current_user.id)]

    @router.delete("/bindings/{provider}")
    async def unbind(
        provider: str,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        bindings = service.list_bindings(current_user.id)
        if len(bindings) <= 1 and not current_user.password_hash:
            raise HTTPException(
                status_code=400,
                detail="Cannot unbind the only login method; set a password first",
            )
        if not service.unbind(current_user.id, provider):
            raise HTTPException(status_code=404, detail="Binding not found")
        session.commit()
        return {"success": True}

    return router


# ───────────────────────────── helpers ────────────────────────────────────


def _safe_next(value: str) -> str:
    """Only allow same-site relative paths in the post-login redirect."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return ""
    if value.startswith("/login") or value.startswith("/api/"):
        return ""
    return value


def _me_payload(user: User, channel: str = "oauth") -> Dict[str, Any]:
    return MeResponse(
        user=user.as_gyra_dict(),
        user_channel=channel,
        user_no=str(user.id),
        nick_name=user.fullname or user.name or "",
        avatar_url=user.avatar or "",
        email=user.email or "",
        role=user.role or "normal",
    ).model_dump()


def _public_tokens(tokens: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": tokens.get("token_type", "Bearer"),
        "expires_in": tokens["expires_in"],
        "refresh_expires_in": tokens["refresh_expires_in"],
        "user": tokens["user"],
    }


def _assert_usable(user: User) -> None:
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    if user.is_pending:
        raise HTTPException(status_code=403, detail="Account pending approval")


def _login_error(
    config: Settings,
    request: Request,
    reason: str,
    detail: str = "",
) -> RedirectResponse:
    path = config.frontend_login_path or "/login"
    query = urlencode({"error": reason, **({"detail": detail} if detail else {})})
    return RedirectResponse(url=f"{path}?{query}", status_code=302)


def _login_success(
    config: Settings,
    request: Request,
    response: Response,
    tokens: Dict[str, Any],
    next_url: str = "",
) -> Response:
    """Hand the token to the browser the way Gyra's frontend expects."""
    root = base_url(request, config)
    callback = config.frontend_callback_path or "/auth/callback"
    target = next_url or f"{root}/"
    if not target.startswith("http"):
        target = f"{root}{target}"

    if next_url.startswith("/oauth2/authorize"):
        # SSO hand-off: the browser must land back on the authorization
        # endpoint with its cookies set, not on the frontend callback.
        payload = RedirectResponse(url=target, status_code=302)
        set_auth_cookies(payload, config, request, tokens)
        return payload

    if config.token_in_fragment:
        redirect_to = f"{root}{callback}/#token={tokens['access_token']}"
        if next_url:
            redirect_to += f"&next={next_url}"
    else:
        redirect_to = f"{root}{callback}?token={tokens['access_token']}"

    payload = RedirectResponse(url=redirect_to, status_code=302)
    set_auth_cookies(payload, config, request, tokens)
    return payload


def _qr_page(provider: str, auth_url: str, config: Settings) -> str:
    """WeChat QR page: iframe renders the code, then hands off to the top window."""
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>微信扫码登录</title>
<style>
  body {{ margin:0; height:100vh; display:flex; align-items:center;
         justify-content:center; background:#f5f6f8;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }}
  .card {{ background:#fff; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,.08);
           padding:28px 32px; text-align:center; }}
  h1 {{ font-size:17px; font-weight:600; margin:0 0 18px; color:#1f2329; }}
  iframe {{ border:0; width:300px; height:400px; }}
  .tip {{ margin-top:14px; font-size:13px; color:#8a92a6; }}
  a {{ color:#4f46e5; }}
</style>
</head>
<body>
  <div class="card">
    <h1>微信扫码登录</h1>
    <iframe src="{auth_url}" title="wechat-qr" scrolling="no"
            sandbox="allow-scripts allow-same-origin allow-top-navigation"></iframe>
    <div class="tip">请使用微信扫描二维码 · <a href="/login">其他方式登录</a></div>
  </div>
</body>
</html>"""


__all__ = ["create_auth_router"]
