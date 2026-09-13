"""WeChat OAuth2 providers.

Two flavours, because the protocols differ:

* ``wechat_open`` — 微信开放平台「网站应用」扫码登录 (``snsapi_login``).
  Works on any desktop browser. Requires a verified 开放平台 website app.
* ``wechat_mp`` — 微信公众号「网页授权」(``snsapi_userinfo``).
  Only usable inside the WeChat in-app browser.

Both return ``openid`` plus ``unionid`` when the app is bound to a 开放平台
account — ``unionid`` is what lets the same human keep one account across the
website app and the official account.
"""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlencode

from gyra_user.providers.base import (
    OAuth2Provider,
    OAuthError,
    OAuthProfile,
    TokenResponse,
)


class _WeChatBase(OAuth2Provider):
    """Shared behaviour: WeChat answers with HTTP 200 + ``errcode`` on failure."""

    def _check_err(self, payload: Dict[str, Any], stage: str) -> Dict[str, Any]:
        errcode = payload.get("errcode")
        if errcode:
            raise OAuthError(
                f"{self.id}: {stage} failed (errcode={errcode}, "
                f"errmsg={payload.get('errmsg')})"
            )
        return payload

    def build_authorize_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str | None = None,
        **extra: Any,
    ) -> str:
        # WeChat uses `appid` rather than the standard `client_id`, and requires
        # the trailing #wechat_redirect fragment.
        params: Dict[str, Any] = {
            "appid": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.scope,
            "state": state,
        }
        params.update(extra)
        sep = "&" if "?" in self.authorization_url else "?"
        return f"{self.authorization_url}{sep}{urlencode(params)}#wechat_redirect"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        # WeChat expects query params, not a form body.
        payload = await self._request_json(
            "GET",
            self.token_url,
            params={
                "appid": self.client_id,
                "secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
            },
        )
        payload = self._check_err(payload, "token exchange")
        access_token = payload.get("access_token")
        if not access_token:
            raise ValueError(f"{self.id}: token endpoint returned no access_token")
        return TokenResponse(
            access_token=str(access_token),
            refresh_token=payload.get("refresh_token"),
            expires_in=payload.get("expires_in"),
            scope=payload.get("scope", "") or "",
            raw=payload,
        )

    async def fetch_profile(self, token: TokenResponse) -> OAuthProfile:
        openid = token.raw.get("openid") or ""
        unionid = token.raw.get("unionid")
        profile: OAuthProfile | None = None
        try:
            payload = await self._request_json(
                "GET",
                self.userinfo_url,
                params={
                    "access_token": token.access_token,
                    "openid": openid,
                    "lang": "zh_CN",
                },
            )
            payload = self._check_err(payload, "userinfo")
            profile = self.normalize_profile({**payload, "openid": openid})
        except Exception:  # noqa: BLE001 - snsapi_base gives no userinfo endpoint
            profile = None

        if profile is None:
            # Still a valid login: openid is enough to identify the user.
            profile = OAuthProfile(
                provider=self.id,
                subject=openid,
                unionid=unionid,
                username=f"wx_{openid[-8:]}" if openid else "",
                display_name="微信用户",
                raw=token.raw,
            )
        if not profile.unionid:
            profile.unionid = unionid
        if not profile.subject:
            profile.subject = openid
        return profile

    def normalize_profile(self, payload: Dict[str, Any]) -> OAuthProfile:
        openid = payload.get("openid") or payload.get("unionid")
        if not openid:
            raise ValueError(f"{self.id}: userinfo missing 'openid'")
        return OAuthProfile(
            provider=self.id,
            subject=str(openid),
            unionid=payload.get("unionid"),
            username=payload.get("nickname") or "",
            display_name=payload.get("nickname") or "微信用户",
            email=None,  # WeChat never exposes email
            avatar_url=payload.get("headimgurl"),
            raw=payload,
        )


class WeChatOpenProvider(_WeChatBase):
    """微信开放平台网站应用扫码登录。"""

    type = "wechat_open"
    authorization_url = "https://open.weixin.qq.com/connect/qrconnect"
    token_url = "https://api.weixin.qq.com/sns/oauth2/access_token"
    userinfo_url = "https://api.weixin.qq.com/sns/userinfo"
    default_scope = "snsapi_login"


class WeChatMpProvider(_WeChatBase):
    """微信公众号网页授权（仅在微信内置浏览器中可用）。"""

    type = "wechat_mp"
    authorization_url = "https://open.weixin.qq.com/connect/oauth2/authorize"
    token_url = "https://api.weixin.qq.com/sns/oauth2/access_token"
    userinfo_url = "https://api.weixin.qq.com/sns/userinfo"
    default_scope = "snsapi_userinfo"


__all__ = ["WeChatMpProvider", "WeChatOpenProvider"]
