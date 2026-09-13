"""Generic OIDC / custom OAuth2 provider driven purely by configuration."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

from gyra_user.config import ProviderConfig
from gyra_user.providers.base import OAuth2Provider, OAuthProfile, TokenResponse


class GenericOIDCProvider(OAuth2Provider):
    """Any RFC 6749 provider: supply URLs + JSON dot-paths and it works.

    Optional ``id_token`` decoding: when the token response carries an
    ``id_token`` the claims are merged into the userinfo payload, which is how
    most OIDC providers (Google, Okta, Authing, 企业微信...) expose the subject.
    """

    type = "oidc"
    supports_pkce = True

    def __init__(self, config: ProviderConfig, http_client=None):
        super().__init__(config, http_client)
        self.authorization_url = config.authorization_url
        self.token_url = config.token_url
        self.userinfo_url = config.userinfo_url

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: Optional[str] = None
    ) -> TokenResponse:
        token = await super().exchange_code(code, redirect_uri, code_verifier)
        token.raw["_id_token_claims"] = self._decode_id_token(token.raw.get("id_token"))
        return token

    async def fetch_profile(self, token: TokenResponse) -> OAuthProfile:
        payload = await self._get_userinfo(token.access_token)
        claims: Dict[str, Any] = token.raw.get("_id_token_claims") or {}
        merged = {**claims, **payload}
        return self.normalize_profile(merged)

    @staticmethod
    def _decode_id_token(id_token: Optional[str]) -> Dict[str, Any]:
        if not id_token or id_token.count(".") < 2:
            return {}
        try:
            segment = id_token.split(".")[1]
            segment += "=" * (-len(segment) % 4)
            return json.loads(base64.urlsafe_b64decode(segment.encode()))
        except Exception:  # noqa: BLE001 - id_token is best-effort
            return {}


__all__ = ["GenericOIDCProvider"]
