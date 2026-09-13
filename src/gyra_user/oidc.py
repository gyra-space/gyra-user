"""OIDC provider endpoints — this is what turns the service into an SSO hub.

Mount at the app root (standalone) or under an API prefix (embedded in Gyra)::

    app.include_router(create_oidc_router(settings))
    app.include_router(create_oidc_router(settings, prefix="/api/v1"))

Endpoints follow OpenID Connect Core 1.0 and RFC 6749/7636/7662/7009 so any
conformant client library can integrate just from the discovery document.
"""

from __future__ import annotations

import html
import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from gyra_user import deps
from gyra_user.config import Settings
from gyra_user.models import OAuthClient, User
from gyra_user.oidc_service import (
    SUPPORTED_GRANT_TYPES,
    SUPPORTED_SCOPES,
    OIDCError,
    OIDCService,
)
from gyra_user.security import create_token, decode_token, jwt_kid
from gyra_user.service import UserService, UserServiceError
from gyra_user.tokens import base_url, clear_auth_cookies

logger = logging.getLogger(__name__)

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

SCOPE_LABELS = {
    "openid": "确认你的身份（单点登录必需）",
    "profile": "读取昵称、头像等公开资料",
    "email": "读取邮箱地址",
    "role": "读取角色信息，用于权限判断",
    "offline_access": "在你不在线时刷新登录状态",
}


def create_oidc_router(
    settings: Optional[Settings] = None, prefix: str = ""
) -> APIRouter:
    """Build the OIDC router.

    ``prefix`` is baked into the route paths so discovery reports URLs that
    actually resolve — needed when the router is mounted under ``/api/v1``.
    """
    prefix = (prefix or "").rstrip("/")
    router = APIRouter(tags=["OIDC"])

    def cfg() -> Settings:
        return settings or deps.get_settings()

    # ─────────────────────────── discovery ────────────────────────────────

    @router.get(f"{prefix}/.well-known/openid-configuration")
    async def discovery(request: Request, config: Settings = Depends(cfg)):
        issuer = _issuer(request, config, prefix)
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth2/authorize",
            "token_endpoint": f"{issuer}/oauth2/token",
            "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "end_session_endpoint": f"{issuer}/oauth2/logout",
            "revocation_endpoint": f"{issuer}/oauth2/revoke",
            "introspection_endpoint": f"{issuer}/oauth2/introspect",
            "response_types_supported": ["code"],
            "grant_types_supported": list(SUPPORTED_GRANT_TYPES),
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [config.jwt_algorithm],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "scopes_supported": list(SUPPORTED_SCOPES),
            "claims_supported": [
                "sub",
                "name",
                "preferred_username",
                "email",
                "email_verified",
                "picture",
                "role",
                "updated_at",
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
        }

    @router.get(f"{prefix}/.well-known/jwks.json")
    async def jwks(config: Settings = Depends(cfg)):
        keys = _jwks(config)
        return {"keys": keys}

    # ────────────────────────── authorization ─────────────────────────────

    @router.get(f"{prefix}/oauth2/authorize")
    async def authorize_get(
        request: Request,
        resp: Response,
        response_type: str = Query("code"),
        client_id: str = Query(""),
        redirect_uri: str = Query(""),
        scope: str = Query(""),
        state: str = Query(""),
        code_challenge: str = Query(""),
        code_challenge_method: str = Query(""),
        nonce: str = Query(""),
        prompt: str = Query(""),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        if not config.oidc_enabled:
            raise HTTPException(status_code=404, detail="OIDC provider is disabled")
        data = {key: value for key, value in request.query_params.items()}
        return await _authorize(request, resp, data, session, config)

    @router.post(f"{prefix}/oauth2/authorize")
    async def authorize_post(
        request: Request,
        resp: Response,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Consent decision posted back by the consent screen."""
        if not config.oidc_enabled:
            raise HTTPException(status_code=404, detail="OIDC provider is disabled")
        form = await request.form()
        data = {key: str(value) for key, value in form.items()}
        return await _authorize(request, resp, data, session, config)

    # ──────────────────────────── token ───────────────────────────────────

    @router.post(f"{prefix}/oauth2/token")
    async def token(
        request: Request,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        if not config.oidc_enabled:
            raise HTTPException(status_code=404, detail="OIDC provider is disabled")
        body = await _read_body(request)
        oidc = OIDCService(session, config)
        service = UserService(session, config)

        try:
            client = oidc.authenticate_client(
                body.get("client_id", ""),
                body.get("client_secret", ""),
                request.headers.get("authorization", ""),
            )
            grant_type = body.get("grant_type", "")
            if grant_type not in client.grant_type_list:
                raise OIDCError(
                    "unsupported_grant_type", f"{grant_type} is not allowed"
                )

            if grant_type == "authorization_code":
                payload = _exchange_code(body, client, oidc, service, request, config)
            elif grant_type == "refresh_token":
                payload = _exchange_refresh(body, client, service, request, config)
            else:
                raise OIDCError("unsupported_grant_type", grant_type)
        except OIDCError as exc:
            return JSONResponse(
                exc.as_dict(), status_code=exc.status_code, headers=NO_STORE
            )

        session.commit()
        return JSONResponse(payload, headers=NO_STORE)

    # ─────────────────────────── userinfo ─────────────────────────────────

    @router.api_route(f"{prefix}/oauth2/userinfo", methods=["GET", "POST"])
    async def userinfo(
        request: Request,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        token_value = _bearer(request)
        if not token_value:
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Missing bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            payload = decode_token(config, token_value, expected_type="access")
        except Exception:  # noqa: BLE001
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        service = UserService(session, config)
        user = service.get_by_id(_as_int(payload.get("sub")))
        if user is None or not user.is_active:
            return JSONResponse({"error": "invalid_token"}, status_code=401)

        scope = (payload.get("scope") or "").split()
        claims: Dict[str, Any] = {"sub": str(user.id)}
        if "profile" in scope:
            claims.update(
                {
                    "name": user.fullname or user.name or "",
                    "preferred_username": user.name or "",
                    "nickname": user.fullname or user.name or "",
                    "picture": user.avatar or "",
                    "updated_at": int((user.gmt_modify or user.gmt_create).timestamp())
                    if (user.gmt_modify or user.gmt_create)
                    else None,
                }
            )
        if "email" in scope:
            claims["email"] = user.email or ""
            claims["email_verified"] = bool(user.email_verified)
        if "role" in scope:
            claims["role"] = user.role or "normal"
        return JSONResponse(claims, headers=NO_STORE)

    # ────────────────────── introspect / revoke ───────────────────────────

    @router.post(f"{prefix}/oauth2/introspect")
    async def introspect(
        request: Request,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        body = await _read_body(request)
        token_value = body.get("token", "")
        try:
            payload = decode_token(config, token_value)
        except Exception:  # noqa: BLE001 - RFC 7662: unknown tokens are inactive
            return JSONResponse({"active": False}, headers=NO_STORE)

        service = UserService(session, config)
        user = service.get_by_id(_as_int(payload.get("sub")))
        active = user is not None and user.is_active
        if active and payload.get("typ") == "refresh":
            active = service._find_refresh_record(payload.get("jti", "")) is not None
        return JSONResponse(
            {
                "active": active,
                "scope": payload.get("scope") or "",
                "client_id": payload.get("client_id") or payload.get("aud") or "",
                "username": user.name if user else None,
                "sub": payload.get("sub"),
                "aud": payload.get("aud"),
                "iss": payload.get("iss"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "token_type": payload.get("typ"),
            },
            headers=NO_STORE,
        )

    @router.post(f"{prefix}/oauth2/revoke")
    async def revoke(
        request: Request,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        body = await _read_body(request)
        token_value = body.get("token", "")
        hint = body.get("token_type_hint", "")
        service = UserService(session, config)
        if hint != "access_token":
            service.revoke_refresh_token(token_value)
            session.commit()
        # RFC 7009: always answer 200, even for tokens we do not know.
        return Response(status_code=200)

    # ────────────────────────── end session ───────────────────────────────

    @router.api_route(f"{prefix}/oauth2/logout", methods=["GET", "POST"])
    async def end_session(
        request: Request,
        resp: Response,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """RP-initiated logout: kill the SSO session, then bounce back."""
        body = await _read_body(request)
        service = UserService(session, config)
        refresh_token = request.cookies.get(deps.refresh_cookie_name(config))
        if refresh_token:
            service.revoke_refresh_token(refresh_token)
        session.commit()

        response: Response
        target = body.get("post_logout_redirect_uri", "")
        if target and _known_post_logout(session, target):
            state = body.get("state", "")
            if state:
                sep = "&" if "?" in target else "?"
                target = f"{target}{sep}{urlencode({'state': state})}"
            response = RedirectResponse(url=target, status_code=302)
        else:
            response = HTMLResponse(_logged_out_page(config))
        clear_auth_cookies(response, config, request)
        return response

    return router


# ───────────────────────────── helpers ───────────────────────────────────


async def _authorize(
    request: Request,
    resp: Response,
    data: Dict[str, str],
    session: Session,
    config: Settings,
) -> Response:
    oidc = OIDCService(session, config)
    service = UserService(session, config)

    client_id = data.get("client_id", "")
    redirect_uri = data.get("redirect_uri", "")
    state = data.get("state", "")
    response_type = data.get("response_type", "code")
    prompt = data.get("prompt", "")

    client = oidc.get_client(client_id)
    if client is None or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown or disabled client")

    # An unregistered redirect_uri is a misconfiguration, not a user error —
    # never bounce to an attacker-supplied URL with an error code.
    if not redirect_uri or not client.allows_redirect_uri(redirect_uri):
        raise HTTPException(status_code=400, detail="redirect_uri is not registered")

    if response_type != "code" or response_type not in client.response_type_list:
        return _redirect_error(redirect_uri, "unsupported_response_type", state)

    scope = data.get("scope") or client.scope
    requested = [item for item in scope.split() if item]
    unknown = [item for item in requested if item not in SUPPORTED_SCOPES]
    if unknown or not client.allows_scope(scope):
        return _redirect_error(redirect_uri, "invalid_scope", state, ",".join(unknown))

    code_challenge = data.get("code_challenge", "")
    if not client.is_confidential and not code_challenge:
        return _redirect_error(
            redirect_uri, "invalid_request", state, "public clients must use PKCE"
        )

    user = deps.resolve_user(request, service, config, response=resp)
    if user is None:
        if prompt == "none":
            return _redirect_error(redirect_uri, "login_required", state)
        return _to_login(request, config)

    if not user.is_active or user.is_pending:
        return _redirect_error(redirect_uri, "access_denied", state, "account inactive")

    decision = data.get("decision", "")
    needs_consent = prompt == "consent" or (
        not client.skip_consent
        and not oidc.consent_covers(user.id, client.client_id, scope)
    )
    if needs_consent and decision != "allow":
        if decision == "deny":
            return _redirect_error(redirect_uri, "access_denied", state)
        return HTMLResponse(_consent_page(client, user, data, scope), headers=NO_STORE)

    if decision == "allow":
        oidc.save_consent(user.id, client.client_id, scope)

    code = oidc.create_authorization_code(
        client,
        user,
        redirect_uri,
        scope,
        code_challenge=code_challenge,
        code_challenge_method=data.get("code_challenge_method", ""),
        nonce=data.get("nonce", ""),
    )
    service.record_event(
        user_id=user.id,
        action="sso_authorize",
        provider=client.client_id,
        username=user.name or "",
        detail=scope,
        ip=deps.client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    session.commit()
    logger.info("Issued authorization code for client=%s user=%s", client_id, user.id)

    sep = "&" if "?" in redirect_uri else "?"
    query = {"code": code}
    if state:
        query["state"] = state
    return RedirectResponse(
        url=f"{redirect_uri}{sep}{urlencode(query)}", status_code=302, headers=NO_STORE
    )


def _exchange_code(
    body: Dict[str, str],
    client: OAuthClient,
    oidc: OIDCService,
    service: UserService,
    request: Request,
    config: Settings,
) -> Dict[str, Any]:
    record = oidc.consume_authorization_code(
        body.get("code", ""),
        client,
        body.get("redirect_uri", ""),
        body.get("code_verifier", ""),
    )
    user = service.get_by_id(record.user_id)
    if user is None or not user.is_active or user.is_pending:
        raise OIDCError("invalid_grant", "Account unavailable")

    tokens = service.issue_tokens(
        user,
        user_agent=request.headers.get("user-agent", ""),
        ip=deps.client_ip(request),
        client_id=client.client_id,
        scope=record.scope,
        access_ttl=client.access_token_ttl,
    )
    service.record_event(
        user_id=user.id,
        action="sso_login",
        provider=client.client_id,
        username=user.name or "",
        detail=record.scope,
        ip=deps.client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )

    payload: Dict[str, Any] = {
        "access_token": tokens["access_token"],
        "token_type": "Bearer",
        "expires_in": tokens["expires_in"],
        "refresh_token": tokens["refresh_token"],
        "scope": record.scope,
    }
    if "openid" in (record.scope or "").split():
        payload["id_token"] = _id_token(config, user, client, record.nonce)
    return payload


def _exchange_refresh(
    body: Dict[str, str],
    client: OAuthClient,
    service: UserService,
    request: Request,
    config: Settings,
) -> Dict[str, Any]:
    try:
        tokens = service.rotate_refresh_token(
            body.get("refresh_token", ""),
            user_agent=request.headers.get("user-agent", ""),
            ip=deps.client_ip(request),
            client_id=client.client_id,
        )
    except UserServiceError as exc:
        raise OIDCError("invalid_grant", exc.message) from exc
    return {
        "access_token": tokens["access_token"],
        "token_type": "Bearer",
        "expires_in": tokens["expires_in"],
        "refresh_token": tokens["refresh_token"],
        "scope": tokens.get("scope", ""),
    }


def _id_token(
    config: Settings, user: User, client: OAuthClient, nonce: str = ""
) -> str:
    claims = {
        "aud": client.client_id,
        "name": user.fullname or user.name or "",
        "preferred_username": user.name or "",
        "picture": user.avatar or "",
        "role": user.role or "normal",
    }
    if nonce:
        claims["nonce"] = nonce
    scope = set((client.scope or "").split())
    if "email" in scope:
        claims["email"] = user.email or ""
        claims["email_verified"] = bool(user.email_verified)
    token, _, _ = create_token(
        config,
        str(user.id),
        "id_token",
        config.id_token_ttl,
        claims,
    )
    return token


def _redirect_error(
    redirect_uri: str, error: str, state: str = "", description: str = ""
) -> RedirectResponse:
    query = {"error": error}
    if description:
        query["error_description"] = description
    if state:
        query["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{sep}{urlencode(query)}", status_code=302, headers=NO_STORE
    )


def _to_login(request: Request, config: Settings) -> RedirectResponse:
    """Send an unauthenticated user to the login page, remembering this URL."""
    path = request.url.path
    next_url = f"{path}?{request.url.query}" if request.url.query else path
    login = config.frontend_login_path or "/login"
    return RedirectResponse(
        url=f"{login}?{urlencode({'next': next_url})}", status_code=302
    )


def _issuer(request: Request, config: Settings, prefix: str) -> str:
    return f"{base_url(request, config)}{prefix}"


def _jwks(config: Settings) -> list:
    """Publish the public key. Empty for HS256 — use RS256 in production."""
    if not config.jwt_algorithm.startswith("RS"):
        return []
    try:
        from cryptography.hazmat.primitives import serialization
        from jwt.algorithms import RSAAlgorithm

        from gyra_user.security import verifying_key

        public_key = serialization.load_pem_public_key(
            verifying_key(config).encode("utf-8")
        )
        jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
        jwk.update(
            {
                "kid": _kid(config),
                "alg": config.jwt_algorithm,
                "use": "sig",
            }
        )
        return [jwk]
    except Exception as exc:  # noqa: BLE001 - a broken key must not 500 discovery
        logger.warning("Cannot build JWKS: %s", exc)
        return []


def _kid(config: Settings) -> str:
    return jwt_kid(config)


def _known_post_logout(session: Session, target: str) -> bool:
    from gyra_user.models import OAuthClient

    clients = session.query(OAuthClient).filter(OAuthClient.is_active.is_(True)).all()
    return any(target in client.redirect_uri_list for client in clients)


async def _read_body(request: Request) -> Dict[str, str]:
    """Accept form-encoded (the OAuth2 default) and JSON bodies.

    ``GET`` requests (logout, authorize) carry their parameters in the query
    string, which is merged in so callers do not care about the method.
    """
    content_type = request.headers.get("content-type", "")
    if request.method == "GET":
        return {str(k): str(v) for k, v in request.query_params.items()}
    if "application/json" in content_type:
        try:
            raw = await request.json()
        except Exception:  # noqa: BLE001
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}
    try:
        form = await request.form()
    except Exception:  # noqa: BLE001
        return {}
    return {str(k): str(v) for k, v in form.items()}


def _bearer(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.query_params.get("access_token", "")


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _consent_page(client: OAuthClient, user: User, data: Dict[str, str], scope: str):
    requested = [item for item in scope.split() if item]
    rows = "".join(
        f"<li><span class='k'>{html.escape(item)}</span>"
        f"<span class='v'>{html.escape(SCOPE_LABELS.get(item, '授权访问你的账号信息'))}"
        "</span></li>"
        for item in requested
    )
    hidden = "".join(
        f"<input type='hidden' name='{html.escape(key)}' "
        f"value='{html.escape(str(value))}' />"
        for key, value in data.items()
        if key != "decision"
    )
    name = html.escape(client.name)
    account = html.escape(user.name or user.email or "")
    avatar = html.escape(
        user.avatar
        or f"https://api.dicebear.com/7.x/initials/svg?seed={quote(account or 'G')}"
    )
    logo = (
        f"<img class='logo' src='{html.escape(client.logo_url)}' alt='' />"
        if client.logo_url
        else "<div class='logo-fallback'>SSO</div>"
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>授权 {name}</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#f5f6f8; color:#1f2329;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }}
  .card {{ background:#fff; border-radius:12px; padding:32px 36px; width:420px;
           box-shadow:0 8px 32px rgba(0,0,0,.08); }}
  .head {{ display:flex; align-items:center; gap:12px; margin-bottom:6px; }}
  .logo, .logo-fallback {{ width:36px; height:36px; border-radius:8px;
                          object-fit:cover; }}
  .logo-fallback {{ background:#eef0ff; color:#4f46e5; display:flex;
                    align-items:center; justify-content:center;
                    font-size:12px; font-weight:600; }}
  h1 {{ font-size:17px; font-weight:600; margin:0; }}
  .sub {{ font-size:13px; color:#8a92a6; margin:0 0 18px; }}
  .who {{ display:flex; align-items:center; gap:10px; padding:10px 12px;
          background:#f7f8fa; border-radius:8px; margin-bottom:16px; }}
  .who img {{ width:28px; height:28px; border-radius:50%; }}
  .who b {{ font-size:13px; font-weight:500; }}
  ul {{ list-style:none; margin:0 0 22px; padding:0; }}
  li {{ padding:8px 0; border-bottom:1px solid #f0f1f4; font-size:13px;
        display:flex; gap:10px; }}
  li:last-child {{ border-bottom:0; }}
  .k {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
        color:#4f46e5; min-width:110px; }}
  .v {{ color:#5f6675; }}
  .actions {{ display:flex; gap:10px; }}
  button {{ flex:1; padding:10px; border-radius:8px; font-size:14px;
            cursor:pointer; border:1px solid #d9dce3; background:#fff;
            color:#5f6675; }}
  button.primary {{ background:#4f46e5; border-color:#4f46e5; color:#fff;
                    font-weight:500; }}
</style>
</head>
<body>
  <form class="card" method="post">
    <div class="head">{logo}<h1>{name} 请求授权</h1></div>
    <p class="sub">该应用希望使用你的账号登录</p>
    <div class="who"><img src="{avatar}" alt="" /><b>{account}</b></div>
    <ul>{rows}</ul>
    {hidden}
    <div class="actions">
      <button type="submit" name="decision" value="deny">取消</button>
      <button class="primary" type="submit" name="decision" value="allow">允许</button>
    </div>
  </form>
</body>
</html>"""


def _logged_out_page(config: Settings) -> str:
    name = html.escape(config.app_name)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>已退出登录</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#f5f6f8; color:#1f2329;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }}
  .card {{ background:#fff; border-radius:12px; padding:32px 40px; text-align:center;
           box-shadow:0 8px 32px rgba(0,0,0,.08); }}
  h1 {{ font-size:17px; font-weight:600; margin:0 0 10px; }}
  p {{ font-size:13px; color:#8a92a6; margin:0 0 18px; }}
  a {{ color:#4f46e5; font-size:13px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>已退出登录</h1>
    <p>{name}</p>
    <a href="/login">重新登录</a>
  </div>
</body>
</html>"""


__all__ = ["create_oidc_router"]
