"""Provider abstraction: every OAuth2 login method implements this interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

from gyra_user.config import ProviderConfig


class OAuthError(RuntimeError):
    """Raised when a provider rejects a code or returns a malformed payload."""


@dataclass
class OAuthProfile:
    """Normalised identity returned by every provider."""

    provider: str
    subject: str  # openid for WeChat, numeric id for GitHub
    unionid: Optional[str] = None
    username: str = ""
    display_name: str = ""
    email: Optional[str] = None
    email_verified: bool = False
    avatar_url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def is_complete(self) -> bool:
        return bool(self.subject)


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: str = ""
    token_type: str = "Bearer"
    raw: Dict[str, Any] = field(default_factory=dict)


def _dig(data: Dict[str, Any], dotted_path: str) -> Optional[Any]:
    """Read a value from nested dicts using a dot path like ``a.b.c``."""
    if not dotted_path:
        return None
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _as_bool(value: Any) -> bool:
    """Interpret the ``email_verified`` claim, which providers spell freely.

    OIDC says it is a JSON boolean, but real providers send ``"true"``,
    ``1`` or omit it entirely. Anything we cannot read as a positive
    assertion counts as *not* verified: this value decides whether an address
    may be used to merge two accounts, so the safe default is what matters.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return False


class OAuth2Provider:
    """Base implementation of the OAuth2 authorization-code flow."""

    #: provider type key used in config
    type: str = "custom"
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    default_scope: str = ""
    supports_pkce: bool = False

    def __init__(
        self, config: ProviderConfig, http_client: Optional[httpx.AsyncClient] = None
    ):
        self.config = config
        self._client = http_client

    # ── identity ───────────────────────────────────────────────────────────
    @property
    def id(self) -> str:
        return self.config.id

    @property
    def label(self) -> str:
        return self.config.label or self.config.id

    @property
    def client_id(self) -> str:
        return self.config.client_id

    @property
    def client_secret(self) -> str:
        return self.config.client_secret

    @property
    def scope(self) -> str:
        return self.config.scope or self.default_scope

    # ── flow steps ─────────────────────────────────────────────────────────
    def build_authorize_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
        **extra: Any,
    ) -> str:
        params: Dict[str, Any] = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        if self.scope:
            params["scope"] = self.scope
        if code_challenge and self.supports_pkce:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        params.update(extra)
        params.update(self.extra_authorize_params())
        sep = "&" if "?" in self.authorization_url else "?"
        return f"{self.authorization_url}{sep}{urlencode(params)}"

    def extra_authorize_params(self) -> Dict[str, Any]:
        return {}

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        data: Dict[str, Any] = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier and self.supports_pkce:
            data["code_verifier"] = code_verifier
        payload = await self._post_token(data)
        access_token = payload.get("access_token")
        if not access_token:
            raise OAuthError(
                f"{self.id}: token endpoint returned no access_token: {payload}"
            )
        return TokenResponse(
            access_token=str(access_token),
            refresh_token=payload.get("refresh_token"),
            expires_in=payload.get("expires_in"),
            scope=payload.get("scope", "") or "",
            token_type=payload.get("token_type", "Bearer"),
            raw=payload,
        )

    async def fetch_profile(self, token: TokenResponse) -> OAuthProfile:
        payload = await self._get_userinfo(token.access_token)
        return self.normalize_profile(payload)

    def normalize_profile(self, payload: Dict[str, Any]) -> OAuthProfile:
        cfg = self.config
        subject = _dig(payload, cfg.id_path)
        if subject is None:
            raise OAuthError(f"{self.id}: userinfo has no id at {cfg.id_path!r}")
        return OAuthProfile(
            provider=self.id,
            subject=str(subject),
            unionid=_dig(payload, "unionid"),
            username=str(_dig(payload, cfg.username_path) or ""),
            display_name=str(_dig(payload, cfg.name_path) or ""),
            email=_dig(payload, cfg.email_path),
            email_verified=_as_bool(_dig(payload, cfg.email_verified_path)),
            avatar_url=_dig(payload, cfg.avatar_path),
            raw=payload,
        )

    # ── http helpers ───────────────────────────────────────────────────────
    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        if self._client is not None:
            resp = await self._client.request(
                method, url, params=params, data=data, headers=headers
            )
        else:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.request(
                    method, url, params=params, data=data, headers=headers
                )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError as exc:  # pragma: no cover - provider misbehaviour
            raise OAuthError(f"{self.id}: non-JSON response from {url}") from exc

    async def _post_token(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request_json(
            "POST", self.token_url, data=data, headers={"Accept": "application/json"}
        )

    async def _get_userinfo(self, access_token: str) -> Dict[str, Any]:
        return await self._request_json(
            "GET",
            self.userinfo_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )


__all__ = ["OAuth2Provider", "OAuthError", "OAuthProfile", "TokenResponse"]
