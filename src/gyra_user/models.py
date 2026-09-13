"""Database models for the user center.

The ``users`` table keeps Gyra's legacy column set (``name`` / ``fullname`` /
``oauth_provider`` / ``oauth_id`` / ``is_active`` / ``gmt_create`` / ...) so the
existing admin UI keeps working, and adds what a real auth center needs:
password policy fields, ``unionid`` for cross-app WeChat identity, a separate
``oauth_accounts`` table (one user may link many providers) and revocable
refresh tokens.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from gyra_user.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _loads(raw: str, fallback: List[str]) -> List[str]:
    """Read a JSON list column, tolerating hand-written comma-separated values."""
    if not raw:
        return list(fallback)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # username / login handle, unique across the whole system
    name = Column(String(50), nullable=True, index=True)
    fullname = Column(String(100), nullable=True)
    email = Column(String(255), nullable=True, index=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    avatar = Column(String(512), nullable=True)

    password_hash = Column(String(255), nullable=True)

    # Denormalised "primary" identity, kept for Gyra compatibility.
    oauth_provider = Column(String(64), nullable=True)
    oauth_id = Column(String(255), nullable=True)
    unionid = Column(String(255), nullable=True, index=True)

    role = Column(String(32), nullable=False, default="normal")
    is_active = Column(Boolean, nullable=False, default=True)
    # Set when require_approval is on and the account awaits admin activation.
    is_pending = Column(Boolean, nullable=False, default=False)

    department_1 = Column(String(100), nullable=True)
    department_2 = Column(String(100), nullable=True)

    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(64), nullable=True)
    login_count = Column(Integer, nullable=False, default=0)

    gmt_create = Column(DateTime, nullable=False, default=_utcnow)
    gmt_modify = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    oauth_accounts = relationship(
        "OAuthAccount",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "name": self.name or "",
            "fullname": self.fullname or "",
            "email": self.email or "",
            "email_verified": bool(self.email_verified),
            "avatar": self.avatar or "",
            "oauth_provider": self.oauth_provider or "",
            "oauth_id": self.oauth_id or "",
            "unionid": self.unionid or "",
            "role": self.role or "normal",
            "is_active": bool(self.is_active),
            "is_pending": bool(self.is_pending),
            "department_1": self.department_1 or "",
            "department_2": self.department_2 or "",
            "last_login_at": self.last_login_at.isoformat()
            if self.last_login_at
            else None,
            "login_count": self.login_count or 0,
            "gmt_create": self.gmt_create.isoformat() if self.gmt_create else None,
            "gmt_modify": self.gmt_modify.isoformat() if self.gmt_modify else None,
        }
        if include_sensitive:
            data["has_password"] = bool(self.password_hash)
        return data

    def as_gyra_dict(self) -> Dict[str, Any]:
        """Shape consumed by Gyra's frontend (``/auth/me`` -> ``user``)."""
        return {
            "id": self.id,
            "name": self.name or "",
            "fullname": self.fullname or "",
            "email": self.email or "",
            "avatar": self.avatar or "",
            "oauth_provider": self.oauth_provider or "",
            "oauth_id": self.oauth_id or "",
            "role": self.role or "normal",
            "department_1": self.department_1 or "",
            "department_2": self.department_2 or "",
            "is_active": 1 if self.is_active else 0,
            "gmt_create": self.gmt_create.isoformat() if self.gmt_create else None,
            "gmt_modify": self.gmt_modify.isoformat() if self.gmt_modify else None,
        }


class OAuthAccount(Base):
    """A third-party identity bound to a local user."""

    __tablename__ = "oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_uid", name="uq_oauth_provider_uid"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider = Column(String(64), nullable=False)
    provider_uid = Column(String(255), nullable=False)  # openid / github id
    unionid = Column(String(255), nullable=True, index=True)

    username = Column(String(100), nullable=True)
    display_name = Column(String(100), nullable=True)
    email = Column(String(255), nullable=True)
    avatar = Column(String(512), nullable=True)

    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    raw_profile = Column(Text, nullable=True)

    gmt_create = Column(DateTime, nullable=False, default=_utcnow)
    gmt_modify = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    user = relationship("User", back_populates="oauth_accounts")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "provider_uid": self.provider_uid,
            "unionid": self.unionid or "",
            "username": self.username or "",
            "display_name": self.display_name or "",
            "email": self.email or "",
            "avatar": self.avatar or "",
            "gmt_create": self.gmt_create.isoformat() if self.gmt_create else None,
        }


class RefreshToken(Base):
    """Stored refresh tokens — enables rotation, revocation and reuse detection."""

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash = Column(String(128), nullable=False)
    family = Column(String(64), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    replaced_by = Column(String(64), nullable=True)
    # Which relying party this session belongs to ("" = the user center itself).
    client_id = Column(String(64), nullable=True, index=True)
    user_agent = Column(String(255), nullable=True)
    ip = Column(String(64), nullable=True)
    gmt_create = Column(DateTime, nullable=False, default=_utcnow)

    user = relationship("User", back_populates="refresh_tokens")

    @property
    def is_valid(self) -> bool:
        return self.revoked_at is None and self.expires_at > _utcnow()


class LoginEvent(Base):
    """Audit trail: logins, refreshes, failures, logouts."""

    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(50), nullable=True)
    provider = Column(String(64), nullable=True)
    action = Column(String(32), nullable=False)  # login|register|refresh|logout|failed
    success = Column(Boolean, nullable=False, default=True)
    detail = Column(String(255), nullable=True)
    ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    gmt_create = Column(DateTime, nullable=False, default=_utcnow)


class OAuthClient(Base):
    """A relying party — any app that wants to log users in through us.

    Public (SPA / mobile) clients keep an empty secret and must use PKCE;
    confidential clients authenticate at the token endpoint.
    """

    __tablename__ = "oauth_clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(64), nullable=False, unique=True, index=True)
    # sha256 of the secret — only shown once, at creation time.
    client_secret_hash = Column(String(128), nullable=False, default="")
    client_secret_last4 = Column(String(8), nullable=False, default="")

    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    homepage_url = Column(String(512), nullable=True)
    logo_url = Column(String(512), nullable=True)

    redirect_uris = Column(Text, nullable=False, default="[]")
    grant_types = Column(
        Text, nullable=False, default='["authorization_code", "refresh_token"]'
    )
    response_types = Column(Text, nullable=False, default='["code"]')
    scope = Column(String(255), nullable=False, default="openid profile email")
    token_endpoint_auth_method = Column(
        String(32), nullable=False, default="client_secret_post"
    )

    is_confidential = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    # First-party apps skip the consent screen (real single sign-on feel).
    skip_consent = Column(Boolean, nullable=False, default=False)

    access_token_ttl = Column(Integer, nullable=True)
    refresh_token_ttl = Column(Integer, nullable=True)

    gmt_create = Column(DateTime, nullable=False, default=_utcnow)
    gmt_modify = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    @property
    def redirect_uri_list(self) -> List[str]:
        return _loads(self.redirect_uris, [])

    @property
    def grant_type_list(self) -> List[str]:
        return _loads(self.grant_types, ["authorization_code", "refresh_token"])

    @property
    def response_type_list(self) -> List[str]:
        return _loads(self.response_types, ["code"])

    @property
    def scope_list(self) -> List[str]:
        return [item for item in (self.scope or "").split() if item]

    def allows_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uri_list

    def allows_scope(self, scope: str) -> bool:
        requested = [item for item in (scope or "").split() if item]
        return set(requested).issubset(set(self.scope_list))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "client_id": self.client_id,
            "client_secret_last4": self.client_secret_last4,
            "name": self.name,
            "description": self.description or "",
            "homepage_url": self.homepage_url or "",
            "logo_url": self.logo_url or "",
            "redirect_uris": self.redirect_uri_list,
            "grant_types": self.grant_type_list,
            "response_types": self.response_type_list,
            "scope": self.scope,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "is_confidential": bool(self.is_confidential),
            "is_active": bool(self.is_active),
            "skip_consent": bool(self.skip_consent),
            "access_token_ttl": self.access_token_ttl,
            "refresh_token_ttl": self.refresh_token_ttl,
            "gmt_create": self.gmt_create.isoformat() if self.gmt_create else None,
            "gmt_modify": self.gmt_modify.isoformat() if self.gmt_modify else None,
        }


class AuthorizationCode(Base):
    """One-shot authorization codes (RFC 6749 §4.1)."""

    __tablename__ = "oauth_authorization_codes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(128), nullable=False, unique=True, index=True)
    client_id = Column(String(64), nullable=False, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    redirect_uri = Column(String(512), nullable=False)
    scope = Column(String(255), nullable=False, default="")
    code_challenge = Column(String(128), nullable=True)
    code_challenge_method = Column(String(16), nullable=True)
    nonce = Column(String(255), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    gmt_create = Column(DateTime, nullable=False, default=_utcnow)

    user = relationship("User")

    @property
    def is_valid(self) -> bool:
        return self.used_at is None and self.expires_at > _utcnow()


class UserConsent(Base):
    """Remembers which scopes a user already granted to a client."""

    __tablename__ = "oauth_consents"
    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_consent_user_client"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_id = Column(String(64), nullable=False, index=True)
    scope = Column(String(255), nullable=False, default="")
    gmt_create = Column(DateTime, nullable=False, default=_utcnow)
    gmt_modify = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    @property
    def scope_list(self) -> List[str]:
        return [item for item in (self.scope or "").split() if item]


__all__ = [
    "AuthorizationCode",
    "Base",
    "LoginEvent",
    "OAuthAccount",
    "OAuthClient",
    "RefreshToken",
    "User",
    "UserConsent",
]
