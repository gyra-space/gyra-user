"""Business logic: user lifecycle, identity linking, token issuing."""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from gyra_user.config import Settings
from gyra_user.db import session_scope
from gyra_user.models import LoginEvent, OAuthAccount, RefreshToken, User
from gyra_user.providers.base import OAuthProfile
from gyra_user.security import (
    create_token,
    decode_frontend_password,
    hash_password,
    token_fingerprint,
    verify_password,
)

logger = logging.getLogger(__name__)

LOCAL_PROVIDER = "local"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UserServiceError(RuntimeError):
    """Domain-level failure carrying an HTTP-friendly message."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class UserService:
    """All user/auth operations. Session-scoped; construct per request."""

    def __init__(self, session: Session, settings: Settings):
        self.session = session
        self.settings = settings

    # ─────────────────────────── queries ───────────────────────────────────

    def get_by_id(self, user_id: int) -> Optional[User]:
        return self.session.get(User, user_id)

    def get_by_username(self, username: str) -> Optional[User]:
        return self.session.query(User).filter(User.name == username).one_or_none()

    def get_by_email(self, email: str) -> Optional[User]:
        if not email:
            return None
        return self.session.query(User).filter(User.email == email).one_or_none()

    def get_oauth_account(
        self, provider: str, provider_uid: str
    ) -> Optional[OAuthAccount]:
        return (
            self.session.query(OAuthAccount)
            .filter(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_uid == provider_uid,
            )
            .one_or_none()
        )

    def list_bindings(self, user_id: int) -> List[OAuthAccount]:
        return (
            self.session.query(OAuthAccount)
            .filter(OAuthAccount.user_id == user_id)
            .order_by(OAuthAccount.gmt_create)
            .all()
        )

    # ───────────────────────── local accounts ──────────────────────────────

    def create_local_user(
        self,
        username: str,
        password: str,
        email: str = "",
        fullname: str = "",
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> User:
        if not self.settings.allow_registration:
            raise UserServiceError("Registration is disabled", 403)
        if self.get_by_username(username):
            raise UserServiceError("Username already exists", 400)
        if email and self.get_by_email(email):
            raise UserServiceError("Email already registered", 400)

        pending = self.settings.require_approval
        user = User(
            name=username,
            fullname=fullname or username,
            email=email or None,
            password_hash=hash_password(password),
            role=role or self.settings.default_role,
            is_active=False if pending else True,
            is_pending=pending,
            oauth_provider=LOCAL_PROVIDER,
            oauth_id=username,
        )
        self.session.add(user)
        self.session.flush()
        self.record_event(
            user_id=user.id,
            username=username,
            provider=LOCAL_PROVIDER,
            action="register",
            success=True,
            detail="pending approval" if pending else "",
        )
        return user

    def verify_local_user(self, username: str, password: str) -> Optional[User]:
        user = self.get_by_username(username) or self.get_by_email(username)
        if user is None or not user.password_hash:
            return None
        candidate = decode_frontend_password(password)
        if not verify_password(candidate, user.password_hash):
            # Some clients send the password already decoded; try it verbatim.
            if candidate == password or not verify_password(
                password, user.password_hash
            ):
                return None
        return user

    def set_password(self, user_id: int, password: str) -> User:
        user = self.get_by_id(user_id)
        if user is None:
            raise UserServiceError("User not found", 404)
        user.password_hash = hash_password(password)
        self.session.flush()
        return user

    # ──────────────────────── OAuth identity ───────────────────────────────

    def upsert_from_oauth(
        self, profile: OAuthProfile, token_payload: Optional[Dict[str, Any]] = None
    ) -> Tuple[User, bool]:
        """Find or create the user behind an OAuth identity.

        Linking order:
        1. ``(provider, subject)`` already bound            -> log in
        2. ``unionid`` bound to any account (WeChat)        -> link & log in
        3. same verified email, when ``link_by_email``      -> link & log in
        4. otherwise                                        -> create account
        """
        token_payload = token_payload or {}
        binding = self.get_oauth_account(profile.provider, profile.subject)
        if binding is not None:
            return self._refresh_binding(binding, profile, token_payload), False

        user: Optional[User] = None
        if profile.unionid:
            user = self._find_by_unionid(profile.unionid)

        if user is None and self.settings.link_by_email and profile.email:
            user = self.get_by_email(profile.email)

        created = user is None
        if user is None:
            if not profile.is_complete():
                raise UserServiceError("OAuth profile is incomplete", 400)
            pending = self.settings.require_approval
            user = User(
                name=self._unique_username(profile),
                fullname=profile.display_name or profile.username or profile.subject,
                email=profile.email,
                email_verified=bool(profile.email and profile.email_verified),
                avatar=profile.avatar_url,
                role=self.settings.default_role,
                is_active=False if pending else True,
                is_pending=pending,
                oauth_provider=profile.provider,
                oauth_id=profile.subject,
                unionid=profile.unionid,
            )
            self.session.add(user)
            self.session.flush()

        binding = OAuthAccount(
            user_id=user.id,
            provider=profile.provider,
            provider_uid=profile.subject,
            unionid=profile.unionid,
            username=profile.username,
            display_name=profile.display_name,
            email=profile.email,
            avatar=profile.avatar_url,
            raw_profile=json.dumps(profile.raw, ensure_ascii=False)[:65535],
        )
        self._apply_token(binding, token_payload)
        self.session.add(binding)

        if not user.avatar and profile.avatar_url:
            user.avatar = profile.avatar_url
        if not user.unionid and profile.unionid:
            user.unionid = profile.unionid
        if not user.oauth_provider:
            user.oauth_provider = profile.provider
            user.oauth_id = profile.subject
        self.session.flush()
        return user, created

    def _refresh_binding(
        self,
        binding: OAuthAccount,
        profile: OAuthProfile,
        token_payload: Dict[str, Any],
    ) -> User:
        binding.username = profile.username or binding.username
        binding.display_name = profile.display_name or binding.display_name
        binding.email = profile.email or binding.email
        binding.avatar = profile.avatar_url or binding.avatar
        if profile.unionid:
            binding.unionid = profile.unionid
        binding.raw_profile = json.dumps(profile.raw, ensure_ascii=False)[:65535]
        self._apply_token(binding, token_payload)
        user = self.get_by_id(binding.user_id)
        if user is None:  # pragma: no cover - FK guarantees existence
            raise UserServiceError("Linked user no longer exists", 409)
        if user.avatar in (None, "") and profile.avatar_url:
            user.avatar = profile.avatar_url
        self.session.flush()
        return user

    @staticmethod
    def _apply_token(binding: OAuthAccount, token_payload: Dict[str, Any]) -> None:
        if not token_payload:
            return
        binding.access_token = token_payload.get("access_token")
        binding.refresh_token = token_payload.get("refresh_token")
        expires_in = token_payload.get("expires_in")
        if isinstance(expires_in, int):
            binding.expires_at = _now() + timedelta(seconds=expires_in)

    def _find_by_unionid(self, unionid: str) -> Optional[User]:
        user = self.session.query(User).filter(User.unionid == unionid).first()
        if user is not None:
            return user
        binding = (
            self.session.query(OAuthAccount)
            .filter(OAuthAccount.unionid == unionid)
            .first()
        )
        return self.get_by_id(binding.user_id) if binding else None

    def _unique_username(self, profile: OAuthProfile) -> str:
        base = (
            profile.username
            or profile.display_name
            or f"{profile.provider}_{profile.subject}"
        )
        base = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)[:40]
        if not base:
            base = f"{profile.provider}_{profile.subject}"
        candidate = base
        suffix = 1
        while self.get_by_username(candidate) is not None:
            suffix += 1
            candidate = f"{base}_{suffix}"
            if suffix > 50:  # pragma: no cover - safety valve
                candidate = f"{base}_{secrets.token_hex(4)}"
                break
        return candidate

    def unbind(self, user_id: int, provider: str) -> bool:
        binding = (
            self.session.query(OAuthAccount)
            .filter(OAuthAccount.user_id == user_id, OAuthAccount.provider == provider)
            .one_or_none()
        )
        if binding is None:
            return False
        self.session.delete(binding)
        self.session.flush()
        return True

    # ──────────────────────────── tokens ───────────────────────────────────

    def issue_tokens(
        self,
        user: User,
        user_agent: str = "",
        ip: str = "",
        family: Optional[str] = None,
        client_id: str = "",
        scope: str = "",
        access_ttl: Optional[int] = None,
        refresh_ttl: Optional[int] = None,
    ) -> Dict[str, Any]:
        settings = self.settings
        access_ttl = int(access_ttl or settings.access_token_ttl)
        refresh_ttl = int(refresh_ttl or settings.refresh_token_ttl)
        claims = {
            "name": user.name or "",
            "role": user.role or "normal",
            "provider": user.oauth_provider or "",
        }
        if client_id:
            # Relying parties verify `aud` against their own client_id.
            claims["aud"] = client_id
            claims["client_id"] = client_id
        if scope:
            claims["scope"] = scope
        access_token, _, access_exp = create_token(
            settings, str(user.id), "access", access_ttl, claims
        )
        refresh_token, jti, refresh_exp = create_token(
            settings, str(user.id), "refresh", refresh_ttl
        )

        record = RefreshToken(
            jti=jti,
            user_id=user.id,
            token_hash=token_fingerprint(refresh_token),
            family=family or secrets.token_urlsafe(16),
            expires_at=refresh_exp.replace(tzinfo=None),
            client_id=client_id or None,
            user_agent=user_agent[:255],
            ip=ip[:64],
        )
        self.session.add(record)
        self.session.flush()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": access_ttl,
            "refresh_expires_in": refresh_ttl,
            "expires_at": access_exp.replace(tzinfo=None),
            "jti": jti,
            "family": record.family,
            "scope": scope or "",
            "user": user.as_gyra_dict(),
        }

    def rotate_refresh_token(
        self,
        refresh_token: str,
        user_agent: str = "",
        ip: str = "",
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange a refresh token for a new pair, revoking the old one.

        ``client_id`` pins a token to the app it was issued to: a code stolen
        from one relying party cannot be replayed at another.
        """
        from gyra_user.security import decode_token

        try:
            payload = decode_token(
                self.settings, refresh_token, expected_type="refresh"
            )
        except Exception as exc:  # noqa: BLE001
            raise UserServiceError(f"Invalid refresh token: {exc}", 401) from exc

        record = self._find_refresh_record(payload.get("jti", ""))
        if record is None:
            raise UserServiceError("Refresh token not recognised", 401)

        if client_id is not None and (record.client_id or "") != client_id:
            self._revoke_family(record.family, reason="client mismatch", commit=True)
            raise UserServiceError("Refresh token was issued to another client", 401)

        if record.revoked_at is not None:
            # Reuse of a rotated token: assume theft and kill the whole family.
            # Commit immediately — this runs on an error path, and the request
            # scope would otherwise roll the revocation back with everything else.
            self._revoke_family(record.family, reason="reuse", commit=True)
            raise UserServiceError("Refresh token already used; session revoked", 401)

        if record.expires_at <= _now():
            raise UserServiceError("Refresh token expired", 401)

        user = self.get_by_id(record.user_id)
        if user is None or not user.is_active:
            raise UserServiceError("Account unavailable", 403)

        tokens = self.issue_tokens(
            user,
            user_agent=user_agent,
            ip=ip,
            family=record.family,
            client_id=record.client_id or "",
            scope=payload.get("scope") or "",
        )
        if self.settings.refresh_token_rotation:
            record.revoked_at = _now()
            record.replaced_by = tokens["jti"]
        self.session.flush()
        return tokens

    def revoke_refresh_token(self, refresh_token: str) -> bool:
        from gyra_user.security import decode_token

        try:
            payload = decode_token(
                self.settings, refresh_token, expected_type="refresh"
            )
        except Exception:  # noqa: BLE001 - revoking an invalid token is a no-op
            return False
        record = self._find_refresh_record(payload.get("jti", ""))
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = _now()
        self.session.flush()
        return True

    def revoke_all_for_user(self, user_id: int, client_id: str = "") -> int:
        query = self.session.query(RefreshToken).filter(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
        if client_id:
            query = query.filter(RefreshToken.client_id == client_id)
        count = query.update({"revoked_at": _now()})
        self.session.flush()
        return count

    def revoke_session(self, user_id: int, jti: str) -> bool:
        record = (
            self.session.query(RefreshToken)
            .filter(RefreshToken.user_id == user_id, RefreshToken.jti == jti)
            .one_or_none()
        )
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = _now()
        self.session.flush()
        return True

    def list_sessions(
        self, user_id: int, only_active: bool = True
    ) -> List[RefreshToken]:
        query = self.session.query(RefreshToken).filter(RefreshToken.user_id == user_id)
        if only_active:
            query = query.filter(RefreshToken.revoked_at.is_(None))
        return query.order_by(RefreshToken.id.desc()).limit(100).all()

    def _find_refresh_record(self, jti: str) -> Optional[RefreshToken]:
        if not jti:
            return None
        return (
            self.session.query(RefreshToken)
            .filter(RefreshToken.jti == jti)
            .one_or_none()
        )

    def _revoke_family(
        self, family: str, reason: str = "", commit: bool = False
    ) -> None:
        (
            self.session.query(RefreshToken)
            .filter(RefreshToken.family == family, RefreshToken.revoked_at.is_(None))
            .update({"revoked_at": _now()})
        )
        logger.warning("Revoked refresh token family %s (%s)", family, reason)
        if commit:
            self.session.commit()

    # ────────────────────────── admin helpers ──────────────────────────────

    def list_users(
        self,
        keyword: str = "",
        role: str = "",
        is_active: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[User], int]:
        query = self.session.query(User)
        if keyword:
            like = f"%{keyword}%"
            query = query.filter(
                or_(
                    User.name.like(like),
                    User.fullname.like(like),
                    User.email.like(like),
                )
            )
        if role:
            query = query.filter(User.role == role)
        if is_active is not None:
            query = query.filter(User.is_active.is_(is_active))
        total = query.with_entities(func.count(User.id)).scalar() or 0
        items = query.order_by(User.id.desc()).limit(limit).offset(offset).all()
        return items, int(total)

    def update_user(self, user_id: int, **fields: Any) -> User:
        user = self.get_by_id(user_id)
        if user is None:
            raise UserServiceError("User not found", 404)
        allowed = {
            "fullname",
            "email",
            "role",
            "is_active",
            "is_pending",
            "department_1",
            "department_2",
            "avatar",
        }
        for key, value in fields.items():
            if key in allowed and value is not None:
                setattr(user, key, value)
        self.session.flush()
        return user

    def delete_user(self, user_id: int) -> bool:
        user = self.get_by_id(user_id)
        if user is None:
            return False
        self.session.delete(user)
        self.session.flush()
        return True

    # ─────────────────────────── auditing ──────────────────────────────────

    def record_event(
        self,
        user_id: Optional[int],
        action: str,
        success: bool = True,
        provider: str = "",
        username: str = "",
        detail: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> None:
        self.session.add(
            LoginEvent(
                user_id=user_id,
                username=username[:50] if username else None,
                provider=provider or None,
                action=action,
                success=success,
                detail=detail[:255] if detail else None,
                ip=ip[:64] if ip else None,
                user_agent=user_agent[:255] if user_agent else None,
            )
        )

    def touch_login(self, user: User, ip: str = "") -> None:
        user.last_login_at = _now()
        user.last_login_ip = ip[:64] if ip else None
        user.login_count = (user.login_count or 0) + 1
        self.session.flush()


def ensure_bootstrap_admin(settings: Settings, password: str = "") -> Optional[User]:
    """Create the first admin when the database has no users at all."""
    from gyra_user.security import hash_password as _hash

    if not password:
        return None
    with session_scope() as session:
        count = session.query(func.count(User.id)).scalar() or 0
        if count:
            return None
        user = User(
            name="admin",
            fullname="Administrator",
            password_hash=_hash(password),
            role="admin",
            is_active=True,
            oauth_provider=LOCAL_PROVIDER,
            oauth_id="admin",
        )
        session.add(user)
        session.flush()
        logger.info("Bootstrap admin created: admin")
        return user


__all__ = ["UserService", "UserServiceError", "ensure_bootstrap_admin"]
