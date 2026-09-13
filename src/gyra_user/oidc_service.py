"""OIDC provider logic: relying-party registry, authorization codes, consent.

Kept separate from :class:`gyra_user.service.UserService` so the user lifecycle
stays readable — this module is everything an *application* needs, not a person.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from gyra_user.config import Settings
from gyra_user.models import AuthorizationCode, OAuthClient, User, UserConsent
from gyra_user.security import (
    hash_client_secret,
    new_client_id,
    new_client_secret,
    verify_client_secret,
)

logger = logging.getLogger(__name__)

DEFAULT_SCOPES = "openid profile email"
SUPPORTED_SCOPES = ["openid", "profile", "email", "role", "offline_access"]
SUPPORTED_GRANT_TYPES = ["authorization_code", "refresh_token"]


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class OIDCError(RuntimeError):
    """An RFC 6749 error response."""

    def __init__(
        self,
        error: str,
        description: str = "",
        status_code: int = 400,
    ):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status_code = status_code

    def as_dict(self) -> Dict[str, str]:
        payload = {"error": self.error}
        if self.description:
            payload["error_description"] = self.description
        return payload


def pkce_verify(challenge: str, method: str, verifier: str) -> bool:
    if not challenge:
        return not verifier
    if not verifier:
        return False
    if (method or "plain").upper() == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return secrets.compare_digest(computed, challenge)
    return secrets.compare_digest(verifier, challenge)


class OIDCService:
    def __init__(self, session: Session, settings: Settings):
        self.session = session
        self.settings = settings

    # ─────────────────────────── clients ──────────────────────────────────

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        if not client_id:
            return None
        return (
            self.session.query(OAuthClient)
            .filter(OAuthClient.client_id == client_id)
            .one_or_none()
        )

    def get_client_by_pk(self, pk: int) -> Optional[OAuthClient]:
        return self.session.get(OAuthClient, pk)

    def list_clients(
        self, keyword: str = "", limit: int = 50, offset: int = 0
    ) -> Tuple[List[OAuthClient], int]:
        query = self.session.query(OAuthClient)
        if keyword:
            like = f"%{keyword}%"
            query = query.filter(
                or_(OAuthClient.name.like(like), OAuthClient.client_id.like(like))
            )
        total = query.with_entities(func.count(OAuthClient.id)).scalar() or 0
        items = query.order_by(OAuthClient.id.desc()).limit(limit).offset(offset).all()
        return items, int(total)

    def create_client(
        self,
        name: str,
        redirect_uris: List[str],
        scope: str = DEFAULT_SCOPES,
        grant_types: Optional[List[str]] = None,
        is_confidential: bool = True,
        skip_consent: bool = False,
        description: str = "",
        homepage_url: str = "",
        logo_url: str = "",
        access_token_ttl: Optional[int] = None,
        refresh_token_ttl: Optional[int] = None,
    ) -> Tuple[OAuthClient, str]:
        if not name:
            raise OIDCError("invalid_request", "name is required")
        if not redirect_uris:
            raise OIDCError("invalid_request", "at least one redirect_uri is required")
        for uri in redirect_uris:
            if uri.startswith("http://") and not _is_local(uri):
                # Loopback and http are fine for local dev; anything else must be TLS.
                raise OIDCError(
                    "invalid_request", f"redirect_uri must use https: {uri}"
                )

        grants = grant_types or list(SUPPORTED_GRANT_TYPES)
        client = OAuthClient(
            client_id=new_client_id(),
            name=name,
            description=description or None,
            homepage_url=homepage_url or None,
            logo_url=logo_url or None,
            redirect_uris=json.dumps(redirect_uris, ensure_ascii=False),
            grant_types=json.dumps(grants, ensure_ascii=False),
            scope=scope or DEFAULT_SCOPES,
            is_confidential=bool(is_confidential),
            skip_consent=bool(skip_consent),
            access_token_ttl=access_token_ttl,
            refresh_token_ttl=refresh_token_ttl,
        )
        secret = ""
        if client.is_confidential:
            secret = new_client_secret()
            client.client_secret_hash = hash_client_secret(secret)
            client.client_secret_last4 = secret[-4:]
        self.session.add(client)
        self.session.flush()
        logger.info("Registered OAuth client %s (%s)", client.client_id, name)
        return client, secret

    def update_client(self, client_id: str, **fields: Any) -> OAuthClient:
        client = self.get_client(client_id)
        if client is None:
            raise OIDCError("invalid_client", "Client not found", 404)

        list_fields = {"redirect_uris", "grant_types", "response_types"}
        for key, value in fields.items():
            if value is None:
                continue
            if key in list_fields:
                if key == "redirect_uris":
                    for uri in value:
                        if uri.startswith("http://") and not _is_local(uri):
                            raise OIDCError(
                                "invalid_request", f"redirect_uri must use https: {uri}"
                            )
                setattr(client, key, json.dumps(list(value), ensure_ascii=False))
            else:
                setattr(client, key, value)
        self.session.flush()
        return client

    def delete_client(self, client_id: str) -> bool:
        client = self.get_client(client_id)
        if client is None:
            return False
        self.session.query(UserConsent).filter(
            UserConsent.client_id == client_id
        ).delete()
        self.session.delete(client)
        self.session.flush()
        return True

    def rotate_secret(self, client_id: str) -> Tuple[OAuthClient, str]:
        client = self.get_client(client_id)
        if client is None:
            raise OIDCError("invalid_client", "Client not found", 404)
        if not client.is_confidential:
            raise OIDCError("invalid_request", "Public clients have no secret")
        secret = new_client_secret()
        client.client_secret_hash = hash_client_secret(secret)
        client.client_secret_last4 = secret[-4:]
        self.session.flush()
        return client, secret

    # ───────────────────── client authentication ──────────────────────────

    def authenticate_client(
        self,
        client_id: str,
        client_secret: str = "",
        authorization_header: str = "",
    ) -> OAuthClient:
        """Accept ``client_secret_basic`` and ``client_secret_post``."""
        header_id, header_secret = _basic_credentials(authorization_header)
        client_id = client_id or header_id
        client_secret = client_secret or header_secret

        client = self.get_client(client_id)
        if client is None or not client.is_active:
            raise OIDCError("invalid_client", "Unknown or disabled client", 401)

        if not client.is_confidential:
            # Public clients authenticate with PKCE only.
            return client
        if not client_secret:
            raise OIDCError("invalid_client", "Client authentication required", 401)
        if not verify_client_secret(client_secret, client.client_secret_hash or ""):
            raise OIDCError("invalid_client", "Client authentication failed", 401)
        return client

    # ─────────────────────── authorization codes ──────────────────────────

    def create_authorization_code(
        self,
        client: OAuthClient,
        user: User,
        redirect_uri: str,
        scope: str,
        code_challenge: str = "",
        code_challenge_method: str = "",
        nonce: str = "",
    ) -> str:
        code = secrets.token_urlsafe(32)
        record = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge or None,
            code_challenge_method=code_challenge_method or None,
            nonce=nonce or None,
            expires_at=_now() + timedelta(seconds=self.settings.authorization_code_ttl),
        )
        self.session.add(record)
        self.session.flush()
        return code

    def consume_authorization_code(
        self,
        code: str,
        client: OAuthClient,
        redirect_uri: str,
        code_verifier: str = "",
    ) -> AuthorizationCode:
        record = (
            self.session.query(AuthorizationCode)
            .filter(AuthorizationCode.code == code)
            .one_or_none()
        )
        if record is None:
            raise OIDCError("invalid_grant", "Authorization code not found")
        if record.client_id != client.client_id:
            # Never reuse — a code leaked to another app must die immediately.
            record.used_at = record.used_at or _now()
            self.session.flush()
            raise OIDCError("invalid_grant", "Code was issued to another client")
        if record.used_at is not None:
            self._revoke_user_codes(record.user_id, client.client_id)
            self.session.flush()
            raise OIDCError("invalid_grant", "Authorization code already used")
        if record.expires_at <= _now():
            raise OIDCError("invalid_grant", "Authorization code expired")
        if record.redirect_uri != redirect_uri:
            raise OIDCError("invalid_grant", "redirect_uri mismatch")
        if record.code_challenge and not pkce_verify(
            record.code_challenge,
            record.code_challenge_method or "plain",
            code_verifier,
        ):
            raise OIDCError("invalid_grant", "PKCE verification failed")

        record.used_at = _now()
        self.session.flush()
        return record

    def _revoke_user_codes(self, user_id: int, client_id: str) -> None:
        (
            self.session.query(AuthorizationCode)
            .filter(
                AuthorizationCode.user_id == user_id,
                AuthorizationCode.client_id == client_id,
                AuthorizationCode.used_at.is_(None),
            )
            .update({"used_at": _now()})
        )

    # ──────────────────────────── consent ─────────────────────────────────

    def get_consent(self, user_id: int, client_id: str) -> Optional[UserConsent]:
        return (
            self.session.query(UserConsent)
            .filter(UserConsent.user_id == user_id, UserConsent.client_id == client_id)
            .one_or_none()
        )

    def consent_covers(self, user_id: int, client_id: str, scope: str) -> bool:
        consent = self.get_consent(user_id, client_id)
        if consent is None:
            return False
        granted = set(consent.scope_list)
        return set(scope.split()).issubset(granted)

    def save_consent(self, user_id: int, client_id: str, scope: str) -> UserConsent:
        consent = self.get_consent(user_id, client_id)
        if consent is None:
            consent = UserConsent(user_id=user_id, client_id=client_id, scope=scope)
            self.session.add(consent)
        else:
            merged = sorted(set(consent.scope_list) | set(scope.split()))
            consent.scope = " ".join(merged)
        self.session.flush()
        return consent

    def revoke_consent(self, user_id: int, client_id: str) -> bool:
        consent = self.get_consent(user_id, client_id)
        if consent is None:
            return False
        self.session.delete(consent)
        self.session.flush()
        return True

    def list_consents(self, user_id: int) -> List[UserConsent]:
        return (
            self.session.query(UserConsent)
            .filter(UserConsent.user_id == user_id)
            .order_by(UserConsent.gmt_modify.desc())
            .all()
        )


def _is_local(uri: str) -> bool:
    host = uri.split("://", 1)[-1].split("/")[0].split(":")[0]
    return host in ("localhost", "127.0.0.1", "[::1]")


def _basic_credentials(header: str) -> Tuple[str, str]:
    """Parse an HTTP Basic ``Authorization`` header into (client_id, secret)."""
    if not header or not header.lower().startswith("basic "):
        return "", ""
    try:
        decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        client_id, _, secret = decoded.partition(":")
        return client_id, secret
    except Exception:  # noqa: BLE001 - malformed header is just no credentials
        return "", ""


__all__ = [
    "DEFAULT_SCOPES",
    "OIDCError",
    "OIDCService",
    "SUPPORTED_GRANT_TYPES",
    "SUPPORTED_SCOPES",
    "pkce_verify",
]
