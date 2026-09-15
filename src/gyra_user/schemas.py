"""Pydantic request/response models.

The response shapes intentionally mirror Gyra's ``/api/v1/auth/*`` contract so
the existing Next.js frontend (``src/services/auth.ts``) works unchanged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from gyra_user.branding import BrandingContent, BrandingSlide, BrandingTheme

# ───────────────────────────── requests ───────────────────────────────────


class LocalLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    # Gyra's frontend sends the password base64-encoded; both forms accepted.
    password: str = Field(..., min_length=1, max_length=256)


class LocalRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=256)
    email: Optional[str] = None
    fullname: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class TokenRequest(BaseModel):
    """Standard OAuth2 token endpoint (RFC 6749 §3.2)."""

    grant_type: str = Field(..., pattern="^(password|refresh_token)$")
    username: Optional[str] = None
    password: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: str = ""
    client_id: Optional[str] = None


class UpdateUserRequest(BaseModel):
    fullname: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    department_1: Optional[str] = None
    department_2: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=6, max_length=256)


# ───────────────────── OIDC relying-party management ──────────────────────


class ClientCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    redirect_uris: List[str] = Field(default_factory=list)
    scope: str = "openid profile email"
    grant_types: Optional[List[str]] = None
    is_confidential: bool = True
    skip_consent: bool = False
    description: Optional[str] = None
    homepage_url: Optional[str] = None
    logo_url: Optional[str] = None
    access_token_ttl: Optional[int] = None
    refresh_token_ttl: Optional[int] = None


class ClientUpdateRequest(BaseModel):
    name: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    scope: Optional[str] = None
    description: Optional[str] = None
    homepage_url: Optional[str] = None
    logo_url: Optional[str] = None
    is_active: Optional[bool] = None
    is_confidential: Optional[bool] = None
    skip_consent: Optional[bool] = None
    access_token_ttl: Optional[int] = None
    refresh_token_ttl: Optional[int] = None


# ──────────────────────── self-service account ────────────────────────────


class ProfileUpdateRequest(BaseModel):
    fullname: Optional[str] = Field(None, max_length=100)
    email: Optional[str] = None
    avatar: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=6, max_length=256)


# ───────────────────────── branding / 品牌文案 ────────────────────────────


class BrandingUpsertRequest(BaseModel):
    """Body of ``PUT /admin/branding/{app_id}/{locale}``."""

    content: BrandingContent = Field(default_factory=BrandingContent)
    is_active: bool = True


# ───────────────────────────── responses ──────────────────────────────────


class ProviderOut(BaseModel):
    id: str
    type: str
    label: str = ""


class OAuthStatusOut(BaseModel):
    enabled: bool
    providers: List[ProviderOut] = Field(default_factory=list)
    sso_auto_login_provider: Optional[str] = None


class UserOut(BaseModel):
    id: int
    name: str = ""
    fullname: str = ""
    email: str = ""
    email_verified: bool = False
    avatar: str = ""
    oauth_provider: str = ""
    oauth_id: str = ""
    role: str = "normal"
    is_active: bool = True
    is_pending: bool = False
    department_1: str = ""
    department_2: str = ""
    last_login_at: Optional[datetime] = None
    login_count: int = 0
    gmt_create: Optional[datetime] = None
    gmt_modify: Optional[datetime] = None


class MeResponse(BaseModel):
    """Exactly the payload Gyra's ``authService.getMe()`` expects."""

    user: Dict[str, Any]
    user_channel: str = "oauth"
    user_no: str = ""
    nick_name: str = ""
    avatar_url: str = ""
    email: str = ""
    role: str = "normal"


class TokenResponseOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_in: int
    user: Dict[str, Any]


class BindingOut(BaseModel):
    id: int
    provider: str
    provider_uid: str
    unionid: str = ""
    username: str = ""
    display_name: str = ""
    avatar: str = ""
    email: str = ""


class BrandingOut(BaseModel):
    """Resolved copy for the hosted pages (see :mod:`gyra_user.branding`)."""

    app_id: str = "default"
    locale: str = "zh"
    default_locale: str = "zh"
    app_name: str = ""
    title: str = ""
    subtitle: str = ""
    features: List[str] = Field(default_factory=list)
    footer: str = ""
    slides: List[BrandingSlide] = Field(default_factory=list)
    locales: List[str] = Field(default_factory=list)
    # Page chrome for the resolved locale, keyed by ``data-i18n`` attribute.
    ui: Dict[str, str] = Field(default_factory=dict)
    theme: BrandingTheme = Field(default_factory=BrandingTheme)
    rotate_interval: int = 0
    # "override" (admin) | "config" | "builtin" — tells an operator where the
    # copy on screen actually came from.
    source: str = "builtin"


class BrandingOverrideOut(BaseModel):
    app_id: str
    locale: str
    is_active: bool = True
    payload: BrandingContent = Field(default_factory=BrandingContent)
    gmt_create: Optional[datetime] = None
    gmt_modify: Optional[datetime] = None


__all__ = [
    "BindingOut",
    "BrandingOut",
    "BrandingOverrideOut",
    "BrandingUpsertRequest",
    "ChangePasswordRequest",
    "ClientCreateRequest",
    "ClientUpdateRequest",
    "LocalLoginRequest",
    "LocalRegisterRequest",
    "MeResponse",
    "OAuthStatusOut",
    "ProfileUpdateRequest",
    "ProviderOut",
    "RefreshRequest",
    "ResetPasswordRequest",
    "TokenRequest",
    "TokenResponseOut",
    "UpdateUserRequest",
    "UserOut",
]
