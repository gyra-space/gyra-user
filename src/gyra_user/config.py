"""Configuration for the Gyra user center.

Four layers, later wins:

1. defaults in :class:`Settings`
2. a base TOML file (``$GYRA_USER_CONFIG``, ``./configs/auth.toml`` or
   ``./auth.toml``)
3. a local TOML file merged on top (``./configs/auth.local.toml`` or
   ``./auth.local.toml``), git-ignored, for credentials and copy you keep off
   the repository
4. ``GYRA_USER_*`` environment variables

(explicit ``overrides`` passed to :func:`load_settings` beat all four; the
ordering of 2-4 is enforced by :meth:`Settings.settings_customise_sources`.)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from gyra_user.branding import Branding

ENV_PREFIX = "GYRA_USER_"

# Base config — the first file that exists wins.
DEFAULT_CONFIG_LOCATIONS = (
    "configs/auth.toml",
    "auth.toml",
    "configs/gyra-user.toml",
)

# Merged on top of the base, in order, when present. .gitignore keeps these
# out of the repository.
LOCAL_CONFIG_LOCATIONS = (
    "configs/auth.local.toml",
    "auth.local.toml",
)


def _deep_merge(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``new`` into ``base``; lists and scalars replace."""
    merged = dict(base)
    for key, value in new.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _load_toml_text(path: Path) -> Dict[str, Any]:
    try:
        import tomllib  # Python >= 3.11
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _candidate_config_files(explicit: Optional[str] = None) -> List[Path]:
    if explicit:
        return [Path(explicit).expanduser()]
    env_path = os.environ.get(f"{ENV_PREFIX}CONFIG")
    if env_path:
        return [Path(env_path).expanduser()]
    cwd = Path.cwd()
    return [cwd / name for name in DEFAULT_CONFIG_LOCATIONS]


def find_config_file(explicit: Optional[str] = None) -> Optional[Path]:
    for candidate in _candidate_config_files(explicit):
        if candidate.is_file():
            return candidate
    return None


def config_files(explicit: Optional[str] = None) -> List[Path]:
    """Every config file to read, in merge order (later overrides earlier).

    The base is whichever of ``$GYRA_USER_CONFIG`` / ``configs/auth.toml`` /
    ``auth.toml`` exists first; the git-ignored ``*.local.toml`` overlay is
    appended on top either way, so pointing ``GYRA_USER_CONFIG`` at a shared
    file does not silently disable a developer's local overrides.
    """
    cwd = Path.cwd()
    if explicit:
        base = [Path(explicit).expanduser()]
    else:
        env_path = os.environ.get(f"{ENV_PREFIX}CONFIG")
        if env_path:
            base = [Path(env_path).expanduser()]
        else:
            candidates = [cwd / name for name in DEFAULT_CONFIG_LOCATIONS]
            base = [p for p in candidates if p.is_file()][:1]
    local = [p for p in (cwd / n for n in LOCAL_CONFIG_LOCATIONS) if p.is_file()]
    return base + local


def env_lookup() -> Dict[str, str]:
    """Environment values for the provider shortcuts: ``.env`` overlaid by the
    real environment.

    ``Settings`` reads ``.env`` through pydantic-settings, but the provider
    shortcuts below look names up by hand — so without this, credentials placed
    in ``.env`` (and *only* there) were silently dropped: every other setting
    worked, the login page just never grew its GitHub / WeChat buttons.
    Real environment variables win, matching the precedence in
    :meth:`Settings.settings_customise_sources`.
    """
    values: Dict[str, str] = {}
    try:
        from dotenv import dotenv_values
    except ModuleNotFoundError:  # pragma: no cover - pydantic-settings pulls it in
        dotenv_values = None  # type: ignore[assignment]
    if dotenv_values is not None:
        for name, value in dotenv_values(".env").items():
            if value is not None and value != "":
                values[name] = value
    values.update(os.environ)
    return values


# Environment shortcuts that patch a provider matched by its ``type``.
# e.g. GYRA_USER_GITHUB_CLIENT_ID -> providers[type=github].client_id
_PROVIDER_ENV_SHORTCUTS = {
    "github": {
        "client_id": f"{ENV_PREFIX}GITHUB_CLIENT_ID",
        "client_secret": f"{ENV_PREFIX}GITHUB_CLIENT_SECRET",
        "scope": f"{ENV_PREFIX}GITHUB_SCOPE",
    },
    "wechat_open": {
        "client_id": f"{ENV_PREFIX}WECHAT_APP_ID",
        "client_secret": f"{ENV_PREFIX}WECHAT_APP_SECRET",
        "scope": f"{ENV_PREFIX}WECHAT_SCOPE",
    },
    "wechat_mp": {
        "client_id": f"{ENV_PREFIX}WECHAT_MP_APP_ID",
        "client_secret": f"{ENV_PREFIX}WECHAT_MP_APP_SECRET",
        "scope": f"{ENV_PREFIX}WECHAT_MP_SCOPE",
    },
}


class ProviderConfig(BaseModel):
    """One OAuth2 provider (GitHub, WeChat open platform, WeChat MP, OIDC...)."""

    id: str = Field(..., description="Stable provider id, e.g. 'github'")
    type: str = Field(
        "custom",
        description="github | wechat_open | wechat_mp | oidc | custom",
    )
    label: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    allow_signup: bool = True

    # Only needed for type=oidc / custom
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    # Dot paths used to read values out of the userinfo JSON payload.
    id_path: str = "id"
    username_path: str = "login"
    name_path: str = "name"
    email_path: str = "email"
    # Dot path of the "this address is verified" claim. A provider that does
    # not assert verification leaves this absent, and the address is then
    # treated as unverified — unverified addresses are not identity anchors.
    email_verified_path: str = "email_verified"
    avatar_path: str = "avatar_url"

    # Provider is usable only when credentials are present.
    @property
    def enabled(self) -> bool:
        if not self.client_id:
            return False
        if self.type in ("oidc", "custom"):
            return bool(self.authorization_url and self.token_url and self.userinfo_url)
        return True


DEFAULT_PROVIDERS: List[Dict[str, Any]] = [
    {
        "id": "github",
        "type": "github",
        "label": "GitHub",
        "scope": "read:user user:email",
    },
    {
        "id": "wechat",
        "type": "wechat_open",
        "label": "微信",
        "scope": "snsapi_login",
    },
]


class Settings(BaseSettings):
    """Runtime settings for the auth center."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type,
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ):
        """Put ``GYRA_USER_*`` above the TOML file.

        The TOML file arrives as ``init`` kwargs, and ``init`` outranks ``env``
        by default — so a key present in the file could never be overridden
        from the environment, the exact opposite of what the config file
        promises (and what a container needs). Explicit ``overrides`` are
        applied by :func:`load_settings` after this, so they still win.
        """
        return (env_settings, dotenv_settings, init_settings, file_secret_settings)

    # ── service ────────────────────────────────────────────────────────────
    app_name: str = "Gyra User Center"
    data_dir: str = "data"
    database_url: str = ""  # empty -> sqlite:///{data_dir}/gyra_user.db
    public_base_url: str = ""  # set when behind a proxy, used for redirect_uri
    cors_origins: List[str] = Field(default_factory=list)

    # ── tokens ─────────────────────────────────────────────────────────────
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    # RS256 keys: either paste the PEM inline or point at a PEM file.
    jwt_private_key: str = ""
    jwt_public_key: str = ""
    jwt_private_key_file: str = ""
    jwt_public_key_file: str = ""
    jwt_issuer: str = "gyra-user"
    jwt_audience: str = "gyra"
    access_token_ttl: int = 30 * 60  # 30 minutes
    refresh_token_ttl: int = 7 * 24 * 3600  # 7 days
    refresh_token_rotation: bool = True
    verify_audience: bool = False

    # ── OIDC provider (single sign-on) ─────────────────────────────────────
    oidc_enabled: bool = True
    id_token_ttl: int = 60 * 60  # 1 hour
    authorization_code_ttl: int = 60  # seconds, RFC recommends <= 10 min
    # Where the OIDC endpoints live; "" -> root when standalone, "/api/v1"
    # when the router is mounted under an existing API prefix.
    oidc_prefix: str = ""

    # ── cookies ────────────────────────────────────────────────────────────
    cookie_name: str = "gyra_session"
    cookie_domain: str = ""
    cookie_path: str = "/"
    cookie_samesite: str = "lax"
    cookie_secure: Optional[bool] = None  # None -> follow request scheme
    cookie_max_age: int = 7 * 24 * 3600
    token_in_fragment: bool = True  # keep Gyra's /auth/callback/#token= behaviour

    # ── local accounts ─────────────────────────────────────────────────────
    allow_local_login: bool = True
    allow_registration: bool = True
    require_approval: bool = False
    default_role: str = "normal"
    password_min_length: int = 6
    password_max_length: int = 128

    # ── behaviour ──────────────────────────────────────────────────────────
    # Link a new OAuth identity onto an existing account with the same email.
    link_by_email: bool = True
    # An email may only merge two identities when *both* sides proved they own
    # it. Turning this off restores the old behaviour, where a local account
    # that merely typed an address in could absorb the real owner's OAuth
    # login — see UserService._link_target_by_email.
    link_by_email_requires_verified: bool = True
    # When a provider proves an address belongs to the logging-in identity but
    # an unverified account is squatting on it, hand the address to its real
    # owner. Off -> the address is left with neither, rather than being kept as
    # a login handle on an account that never proved it owned one.
    reclaim_unverified_email: bool = True
    # Always require authentication (when false, /me returns an anonymous user).
    auth_required: bool = True
    sso_auto_login_provider: str = ""
    frontend_callback_path: str = "/auth/callback"
    frontend_login_path: str = "/login"

    # ── Gyra compatibility ─────────────────────────────────────────────────
    # Secret used by gyra_app.auth.session (HMAC-SHA256). Set it to accept
    # tokens issued by the legacy implementation during a rolling migration.
    legacy_session_secret: str = ""
    legacy_session_cookie: str = "gyra_session"
    # Path of the legacy token file (gyra home/.session_secret) as a fallback.
    legacy_secret_file: str = ""

    # ── providers ──────────────────────────────────────────────────────────
    providers: List[ProviderConfig] = Field(
        default_factory=lambda: [ProviderConfig(**item) for item in DEFAULT_PROVIDERS]
    )

    # ── branding ───────────────────────────────────────────────────────────
    # Left-panel copy of the hosted pages. Overridable per app and per locale,
    # and hot-editable from /admin; see gyra_user.branding.
    branding: Branding = Field(default_factory=Branding)

    # ── misc ───────────────────────────────────────────────────────────────
    debug: bool = False
    # "development" | "staging" | "production".
    # Only "production" turns the safety checks in production_problems() fatal.
    environment: str = "development"

    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        data_dir = Path(self.data_dir).expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{data_dir / 'gyra_user.db'}"

    def provider(self, provider_id: str) -> Optional[ProviderConfig]:
        for item in self.providers:
            if item.id == provider_id:
                return item
        return None

    def enabled_providers(self) -> List[ProviderConfig]:
        return [p for p in self.providers if p.enabled]

    def production_problems(self) -> List[str]:
        """Things that are merely sloppy in dev but outright unsafe in prod.

        Called by :func:`gyra_user.app.create_app` when ``debug`` is off, so a
        misconfigured deployment fails at boot instead of leaking tokens.
        """
        problems: List[str] = []
        weak = {"", "changeme", "secret", "please-change-me-to-a-long-random-string"}

        if self.jwt_algorithm.startswith("RS"):
            if not (self.jwt_private_key or self.jwt_private_key_file):
                problems.append(
                    "jwt_private_key / jwt_private_key_file is required for "
                    f"{self.jwt_algorithm}"
                )
            if not (self.jwt_public_key or self.jwt_public_key_file):
                problems.append(
                    "jwt_public_key / jwt_public_key_file is required for "
                    f"{self.jwt_algorithm}"
                )
        else:
            if self.jwt_secret.strip() in weak or len(self.jwt_secret) < 32:
                problems.append(
                    "jwt_secret is missing or too short; "
                    "generate one with: openssl rand -base64 48"
                )

        if self.oidc_enabled and not self.public_base_url:
            problems.append(
                "public_base_url is required when OIDC is enabled "
                "(issuer and redirect_uri must be absolute URLs)"
            )
        if self.public_base_url.startswith("http://"):
            problems.append(
                f"public_base_url={self.public_base_url!r} is plain HTTP; "
                "tokens and cookies would travel in cleartext"
            )
        if self.cookie_samesite.lower() not in {"lax", "strict", "none"}:
            problems.append(
                f"cookie_samesite={self.cookie_samesite!r} must be lax/strict/none"
            )
        return problems


def load_settings(
    config_file: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> Settings:
    """Build settings from TOML files + environment + explicit overrides."""

    data: Dict[str, Any] = {}
    provider_items: Dict[str, Dict[str, Any]] = {}
    for path in config_files(config_file):
        raw = _load_toml_text(path)
        for key, value in raw.items():
            if key == "providers":
                if not isinstance(value, list):
                    continue
                # Providers merge by id, so a local file can add credentials
                # to a provider the committed file already declares.
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    item_id = str(item.get("id") or item.get("type") or "")
                    provider_items[item_id] = _deep_merge(
                        provider_items.get(item_id, {}), item
                    )
                continue
            current = data.get(key)
            if isinstance(current, dict) and isinstance(value, dict):
                data[key] = _deep_merge(current, value)
            else:
                data[key] = value

    if provider_items:
        data["providers"] = [ProviderConfig(**item) for item in provider_items.values()]

    # Env shortcuts patch provider credentials by provider type.
    env = env_lookup()
    defaults_by_type = {str(item["type"]): item for item in DEFAULT_PROVIDERS}
    for ptype, mapping in _PROVIDER_ENV_SHORTCUTS.items():
        patched: Dict[str, str] = {}
        for field_name, env_name in mapping.items():
            value = env.get(env_name)
            if value:
                patched[field_name] = value
        if not patched:
            continue
        providers = data.get("providers")
        if providers is None:
            providers = [ProviderConfig(**item) for item in DEFAULT_PROVIDERS]
        found = False
        for provider in providers:
            if provider.type == ptype:
                for field_name, value in patched.items():
                    setattr(provider, field_name, value)
                found = True
        if not found and ptype in defaults_by_type:
            # Credentials were supplied for a provider the config file no
            # longer declares — reinstate the shipped definition rather than
            # dropping the credentials on the floor.
            patched.setdefault("id", str(defaults_by_type[ptype]["id"]))
            patched["type"] = ptype
            providers.append(ProviderConfig(**{**defaults_by_type[ptype], **patched}))
        data["providers"] = providers

    settings = Settings(**data)

    if overrides:
        # Explicit overrides beat everything, including the environment.
        settings = settings.model_copy(update=overrides)

    if not settings.data_dir:
        settings.data_dir = "data"
    return settings


__all__ = [
    "ENV_PREFIX",
    "ProviderConfig",
    "Settings",
    "config_files",
    "env_lookup",
    "find_config_file",
    "load_settings",
]
