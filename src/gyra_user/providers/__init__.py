"""Provider registry — map config ``type`` to an implementation."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from gyra_user.config import ProviderConfig
from gyra_user.providers.base import OAuth2Provider
from gyra_user.providers.generic import GenericOIDCProvider
from gyra_user.providers.github import GitHubProvider
from gyra_user.providers.wechat import WeChatMpProvider, WeChatOpenProvider

PROVIDER_TYPES: Dict[str, Type[OAuth2Provider]] = {
    "github": GitHubProvider,
    "wechat_open": WeChatOpenProvider,
    "wechat_mp": WeChatMpProvider,
    "oidc": GenericOIDCProvider,
    "custom": GenericOIDCProvider,
}


def create_provider(config: ProviderConfig, http_client=None) -> OAuth2Provider:
    cls = PROVIDER_TYPES.get(config.type)
    if cls is None:
        raise ValueError(
            f"unknown provider type {config.type!r} "
            f"(known: {', '.join(sorted(PROVIDER_TYPES))})"
        )
    return cls(config, http_client=http_client)


def build_providers(
    configs: List[ProviderConfig], http_client=None
) -> Dict[str, OAuth2Provider]:
    providers: Dict[str, OAuth2Provider] = {}
    for config in configs:
        if not config.enabled:
            continue
        providers[config.id] = create_provider(config, http_client=http_client)
    return providers


def get_provider(
    configs: List[ProviderConfig], provider_id: str, http_client=None
) -> Optional[OAuth2Provider]:
    for config in configs:
        if config.id == provider_id and config.enabled:
            return create_provider(config, http_client=http_client)
    return None


__all__ = [
    "PROVIDER_TYPES",
    "GenericOIDCProvider",
    "GitHubProvider",
    "OAuth2Provider",
    "WeChatMpProvider",
    "WeChatOpenProvider",
    "build_providers",
    "create_provider",
    "get_provider",
]
