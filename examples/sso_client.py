"""最小可运行的「接入方」示例，用来验证单点登录是否真的通。

把它当成一个独立业务系统（比如 gyra-web、内部后台）。它自己不管账号，
全部走 gyra-user 的 OIDC 授权码流程。

先注册本应用::

    python -m gyra_user.cli create-client "Demo App" \\
        --redirect-uri http://localhost:8200/callback --skip-consent

把输出的 client_id / client_secret 填进环境变量后运行::

    GYRA_USER_ISSUER=http://127.0.0.1:8100 \\
    DEMO_CLIENT_ID=xxx DEMO_CLIENT_SECRET=yyy \\
    python examples/sso_client.py           # http://localhost:8200

只想看命令行版流程（不启服务）::

    python examples/sso_client.py --selftest
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
from typing import Any, Dict
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

ISSUER = os.environ.get("GYRA_USER_ISSUER", "http://127.0.0.1:8100").rstrip("/")
CLIENT_ID = os.environ.get("DEMO_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("DEMO_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("DEMO_REDIRECT_URI", "http://localhost:8200/callback")
SCOPES = "openid profile email"


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def authorize_url(doc: Dict[str, Any], *, state: str, challenge: str) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "state": state,
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{doc['authorization_endpoint']}?{query}"


def discovery() -> Dict[str, Any]:
    """Everything a client needs comes from one well-known URL."""
    resp = httpx.get(f"{ISSUER}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    return resp.json()


def exchange_code(code: str, verifier: str) -> Dict[str, Any]:
    doc = discovery()
    resp = httpx.post(
        doc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_userinfo(access_token: str) -> Dict[str, Any]:
    doc = discovery()
    resp = httpx.get(
        doc["userinfo_endpoint"],
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ──────────────────────────── demo app ───────────────────────────────────

app = FastAPI(title="Demo relying party")
# Demo only: a real app keeps this server-side (Redis / signed cookie).
_sessions: Dict[str, Dict[str, Any]] = {}


@app.get("/")
async def index(request: Request):
    session = _sessions.get(request.cookies.get("demo_session", ""))
    if session is None:
        return HTMLResponse(
            "<h3>Demo App</h3><p>未登录。</p><a href='/login'>用 Gyra 用户中心登录</a>"
        )
    profile = session.get("profile", {})
    return HTMLResponse(
        f"<h3>Demo App</h3><p>已登录：<b>{profile.get('preferred_username')}</b>"
        f" ({profile.get('email', '无邮箱')})</p>"
        "<pre>" + json.dumps(profile, ensure_ascii=False, indent=2) + "</pre>"
        "<p><a href='/logout'>退出</a></p>"
    )


@app.get("/login")
async def login(request: Request):
    """302 to the user center. It owns the login page — we do not."""
    doc = discovery()
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    _sessions[state] = {"code_verifier": verifier}
    return RedirectResponse(url=authorize_url(doc, state=state, challenge=challenge))


@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    pending = _sessions.pop(state, None) if state else None
    if pending is None:
        return HTMLResponse("state 校验失败", status_code=400)
    tokens = exchange_code(code, pending["code_verifier"])
    profile = fetch_userinfo(tokens["access_token"])
    key = secrets.token_urlsafe(16)
    _sessions[key] = {"tokens": tokens, "profile": profile}
    response = RedirectResponse(url="/")
    response.set_cookie(key="demo_session", value=key, httponly=True)
    return response


@app.get("/logout")
async def logout(request: Request):
    """RP-initiated logout: kill the local session *and* the SSO session."""
    key = request.cookies.get("demo_session", "")
    session = _sessions.pop(key, None) or {}
    doc = discovery()
    home = REDIRECT_URI.rsplit("/", 1)[0] + "/"
    query = urlencode({"post_logout_redirect_uri": home})
    target = f"{doc['end_session_endpoint']}?{query}"
    refresh = (session.get("tokens") or {}).get("refresh_token")
    if refresh:
        httpx.post(
            doc["revocation_endpoint"],
            data={
                "token": refresh,
                "token_type_hint": "refresh_token",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
            timeout=10,
        )
    response = RedirectResponse(url=target)
    response.delete_cookie("demo_session")
    return response


# ────────────────────────── headless selftest ────────────────────────────


def selftest(username: str, password: str) -> int:
    """Drive the whole flow from the command line, mimicking a browser."""
    doc = discovery()
    print(f"issuer: {doc['issuer']}")
    print(f"authorize: {doc['authorization_endpoint']}")

    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    auth_url = authorize_url(doc, state=state, challenge=challenge)

    browser = httpx.Client(base_url=ISSUER, follow_redirects=False, timeout=10)

    # 1. Anonymous -> the user center bounces us to its login page.
    resp = browser.get(auth_url)
    assert resp.status_code == 302 and "/login?next=" in resp.headers["location"], (
        resp.status_code,
        resp.headers.get("location"),
    )
    print(f"1. anonymous -> {resp.headers['location'][:60]}...")

    # 2. Sign in (base64 password, same as the login page does).
    secret = base64.b64encode(password.encode()).decode()
    resp = browser.post(
        "/api/v1/auth/local/login",
        json={"username": username, "password": secret},
    )
    assert resp.status_code == 200, resp.text
    print(f"2. signed in as {username}")

    # 3. Repeat the authorization request -> code (skip_consent clients).
    resp = browser.get(auth_url)
    assert resp.status_code == 302, (resp.status_code, resp.text[:300])
    location = resp.headers["location"]
    if location.startswith("/login"):
        print("   (consent required — rerun with --selftest after granting consent)")
        return 1
    code = dict(pair.split("=", 1) for pair in location.split("?", 1)[1].split("&"))[
        "code"
    ]
    print(f"3. got authorization code {code[:16]}...")

    # 4. Exchange + userinfo.
    tokens = exchange_code(code, verifier)
    profile = fetch_userinfo(tokens["access_token"])
    print("4. access_token issued, userinfo:")
    print(json.dumps(profile, ensure_ascii=False, indent=2))
    assert profile.get("sub")

    # 5. Refresh.
    refreshed = httpx.post(
        doc["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=10,
    )
    assert refreshed.status_code == 200, refreshed.text
    print("5. refresh_token grant ok")
    print("\nSSO end-to-end OK")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        user = os.environ.get("DEMO_USERNAME", "admin")
        pwd = os.environ.get("DEMO_PASSWORD", "admin123")
        raise SystemExit(selftest(user, pwd))
    if not CLIENT_ID:
        print("set DEMO_CLIENT_ID (and DEMO_CLIENT_SECRET) first", file=sys.stderr)
        raise SystemExit(2)

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8200)
