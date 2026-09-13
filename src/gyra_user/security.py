"""Password hashing, JWT issuing/verification and legacy-token compatibility."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import bcrypt
import jwt

from gyra_user.config import Settings

logger = logging.getLogger(__name__)

_BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores anything past 72 bytes


# ─────────────────────────── passwords ────────────────────────────────────


def hash_password(password: str) -> str:
    raw = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: Optional[str]) -> bool:
    if not password_hash:
        return False
    raw = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def decode_frontend_password(raw: str) -> str:
    """Gyra's frontend base64-encodes passwords; accept both forms."""
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        if base64.b64encode(decoded.encode("utf-8")).decode("utf-8") == raw:
            return decoded
    except Exception:
        pass
    return raw


# ────────────────────────── key management ────────────────────────────────

_insecure_secret: Optional[str] = None


def _secret_file_path(settings: Settings) -> Optional[Path]:
    if settings.legacy_secret_file:
        return Path(settings.legacy_secret_file).expanduser()
    return None


def _load_or_create_secret(settings: Settings) -> str:
    """Persist a random signing key so dev sessions survive restarts."""
    global _insecure_secret

    path = _secret_file_path(settings)
    if path is None:
        data_dir = Path(settings.data_dir).expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / ".jwt_secret"

    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            _insecure_secret = value
            return value

    value = secrets.token_urlsafe(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    logger.warning(
        "GYRA_USER_JWT_SECRET not set — generated %s. Set it in production so "
        "tokens stay valid across replicas and restarts.",
        path,
    )
    _insecure_secret = value
    return value


def _resolve_pem(inline: str, path: str) -> str:
    """Accept a PEM inline or a path to a PEM file (``~`` is expanded)."""
    value = (inline or "").strip()
    if value:
        if "\n" not in value and len(value) < 512:
            candidate = Path(value).expanduser()
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8")
        return value
    if path:
        candidate = Path(path).expanduser()
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return ""


def signing_key(settings: Settings) -> str:
    if settings.jwt_algorithm.startswith("RS"):
        key = _resolve_pem(settings.jwt_private_key, settings.jwt_private_key_file)
        if not key:
            raise RuntimeError("jwt_private_key is required for RS* algorithms")
        return key
    if settings.jwt_secret:
        return settings.jwt_secret
    env_secret = os.environ.get("GYRA_USER_JWT_SECRET")
    if env_secret:
        return env_secret
    if _insecure_secret:
        return _insecure_secret
    return _load_or_create_secret(settings)


def verifying_key(settings: Settings) -> str:
    if settings.jwt_algorithm.startswith("RS"):
        key = _resolve_pem(settings.jwt_public_key, settings.jwt_public_key_file)
        if not key:
            raise RuntimeError("jwt_public_key is required for RS* algorithms")
        return key
    return signing_key(settings)


# ─────────────────────────────── JWT ──────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def jwt_kid(settings: Settings) -> str:
    """Key id published in the JWKS and stamped on every token."""
    return hashlib.sha256(verifying_key(settings).encode("utf-8")).hexdigest()[:16]


def create_token(
    settings: Settings,
    subject: str,
    token_type: str,
    ttl_seconds: int,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, datetime]:
    """Create a JWT. Returns ``(token, jti, expires_at)``."""
    issued_at = _now()
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    jti = secrets.token_urlsafe(24)
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "typ": token_type,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.jwt_issuer,
    }
    # Only stamp `aud` when we actually verify it — otherwise third-party
    # verifiers that do not know our audience would reject valid tokens.
    if settings.verify_audience and settings.jwt_audience:
        payload["aud"] = settings.jwt_audience
    if extra_claims:
        payload.update(extra_claims)

    headers = (
        {"kid": jwt_kid(settings)} if settings.jwt_algorithm.startswith("RS") else None
    )
    token = jwt.encode(
        payload,
        signing_key(settings),
        algorithm=settings.jwt_algorithm,
        headers=headers,
    )
    return token, jti, expires_at


def decode_token(
    settings: Settings,
    token: str,
    expected_type: Optional[str] = None,
    verify_aud: Optional[bool] = None,
) -> Dict[str, Any]:
    """Decode and validate a JWT, raising ``jwt.PyJWTError`` on failure."""
    audience = (
        settings.jwt_audience if (verify_aud or settings.verify_audience) else None
    )
    options = {"verify_aud": bool(audience)}
    payload = jwt.decode(
        token,
        verifying_key(settings),
        algorithms=[settings.jwt_algorithm],
        audience=audience,
        options=options,
    )
    if expected_type and payload.get("typ") != expected_type:
        raise jwt.InvalidTokenError(
            f"expected token type {expected_type!r}, got {payload.get('typ')!r}"
        )
    return payload


def token_fingerprint(token: str) -> str:
    """Store refresh tokens hashed, never in plaintext."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ───────────────── Gyra legacy HMAC session compatibility ─────────────────


def _legacy_secret(settings: Settings) -> str:
    if settings.legacy_session_secret:
        return settings.legacy_session_secret
    env_secret = os.environ.get("OAUTH2_SESSION_SECRET")
    if env_secret:
        return env_secret
    path = _secret_file_path(settings)
    if path and path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _legacy_sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _b64_decode(value: str) -> str:
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value.encode()).decode()


def verify_legacy_token(settings: Settings, token: str) -> Optional[Dict[str, Any]]:
    """Verify a token issued by ``gyra_app.auth.session``.

    Gyra signs ``base64url(json)`` with HMAC-SHA256 and ships it as
    ``<payload>.<hexdigest>``. Returning the embedded user dict lets an existing
    Gyra session keep working while you roll out this service.
    """
    secret = _legacy_secret(settings)
    if not secret or not token or "." not in token:
        return None
    try:
        payload_b64, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _legacy_sign(secret, payload_b64)):
            return None
        payload = json.loads(_b64_decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            return None
        user = payload.get("user")
        return user if isinstance(user, dict) else None
    except Exception:  # noqa: BLE001 - legacy tokens are best-effort
        return None


# ─────────────────────────── misc helpers ─────────────────────────────────


# ────────────────────── OAuth client credentials ──────────────────────────

CLIENT_ID_BYTES = 16
CLIENT_SECRET_BYTES = 32


def new_client_id() -> str:
    return secrets.token_urlsafe(CLIENT_ID_BYTES).replace("-", "")[:24]


def new_client_secret() -> str:
    return secrets.token_urlsafe(CLIENT_SECRET_BYTES)


def hash_client_secret(secret: str) -> str:
    """Client secrets are high-entropy random strings — SHA-256 is enough.

    bcrypt would only slow down every token exchange for no gain here.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_client_secret(secret: str, stored_hash: str) -> bool:
    if not stored_hash or not secret:
        return False
    return hmac.compare_digest(hash_client_secret(secret), stored_hash)


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """Generate an RS256 signing pair. Returns ``(private_pem, public_pem)``."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "cryptography is required to generate RSA keys: pip install cryptography"
        ) from exc

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(48)


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# ──────────────────── OAuth state (stateless, CSRF + PKCE) ────────────────

STATE_TTL_SECONDS = 600


def create_state_token(
    settings: Settings,
    provider: str,
    redirect_after: str = "",
    code_verifier: str = "",
) -> str:
    """Encode the OAuth ``state`` as a short-lived signed token.

    Stateless by design: no server-side store means it keeps working behind a
    load balancer or across process restarts, and it carries the PKCE verifier
    so the callback does not need a session cookie.
    """
    token, _, _ = create_token(
        settings,
        subject=provider,
        token_type="oauth_state",
        ttl_seconds=STATE_TTL_SECONDS,
        extra_claims={
            "provider": provider,
            "redirect_after": redirect_after,
            "code_verifier": code_verifier,
        },
    )
    return token


def verify_state_token(settings: Settings, state: str) -> Optional[Dict[str, Any]]:
    try:
        return decode_token(settings, state, expected_type="oauth_state")
    except Exception:  # noqa: BLE001
        return None


__all__ = [
    "CLIENT_ID_BYTES",
    "CLIENT_SECRET_BYTES",
    "STATE_TTL_SECONDS",
    "code_challenge",
    "create_state_token",
    "create_token",
    "decode_frontend_password",
    "decode_token",
    "generate_rsa_keypair",
    "hash_client_secret",
    "jwt_kid",
    "hash_password",
    "new_client_id",
    "new_client_secret",
    "new_code_verifier",
    "new_state",
    "token_fingerprint",
    "verify_client_secret",
    "verify_legacy_token",
    "verify_password",
    "verify_state_token",
]
