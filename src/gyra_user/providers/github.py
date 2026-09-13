"""GitHub OAuth2 (authorization code flow, no PKCE support on GitHub)."""

from __future__ import annotations

from typing import Any, Dict, List

from gyra_user.providers.base import OAuth2Provider, OAuthProfile, TokenResponse


class GitHubProvider(OAuth2Provider):
    type = "github"
    authorization_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    userinfo_url = "https://api.github.com/user"
    emails_url = "https://api.github.com/user/emails"
    default_scope = "read:user user:email"

    def extra_authorize_params(self) -> Dict[str, Any]:
        # allow_signup=false stops brand-new GitHub accounts from registering.
        return {"allow_signup": "true" if self.config.allow_signup else "false"}

    async def _post_token(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # GitHub returns form-encoded unless Accept: application/json is set,
        # and it accepts the secret in the body only.
        return await self._request_json(
            "POST",
            self.token_url,
            data=data,
            headers={"Accept": "application/json"},
        )

    async def fetch_profile(self, token: TokenResponse) -> OAuthProfile:
        payload = await self._get_userinfo(token.access_token)
        profile = self.normalize_profile(payload)
        if not profile.email:
            profile.email = await self._primary_email(token.access_token)
            profile.email_verified = bool(profile.email)
        if not profile.username:
            profile.username = profile.display_name or f"gh_{profile.subject}"
        return profile

    def normalize_profile(self, payload: Dict[str, Any]) -> OAuthProfile:
        subject = payload.get("id")
        if subject is None:
            raise ValueError("github: userinfo missing 'id'")
        return OAuthProfile(
            provider=self.id,
            subject=str(subject),
            unionid=None,
            username=payload.get("login") or "",
            display_name=payload.get("name") or payload.get("login") or "",
            email=payload.get("email"),
            email_verified=bool(payload.get("email_verified")),
            avatar_url=payload.get("avatar_url"),
            raw=payload,
        )

    async def _primary_email(self, access_token: str) -> str:
        try:
            emails: List[Dict[str, Any]] = await self._request_json(
                "GET",
                self.emails_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
        except Exception:  # noqa: BLE001 - email is best-effort
            return ""
        if not isinstance(emails, list):
            return ""
        for item in emails:
            if item.get("primary") and item.get("verified"):
                return str(item.get("email", ""))
        for item in emails:
            if item.get("verified"):
                return str(item.get("email", ""))
        return emails[0].get("email", "") if emails else ""


__all__ = ["GitHubProvider"]
