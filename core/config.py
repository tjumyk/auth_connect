"""Configuration loading helpers for OAuth Flask integration."""

from __future__ import annotations

import json
import os
from typing import Any

from .exceptions import OAuthResultError
from .validation import validate_oauth_config


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _as_int(value: str | None, *, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _csv_list(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _build_oauth_config_from_env() -> dict[str, Any] | None:
    """Build oauth config payload from OAUTH_* environment variables.

    Returns None when no OAuth env vars are present.
    """
    env = os.environ
    env_keys = (
        "OAUTH_SERVER_PUBLIC_URL",
        "OAUTH_SERVER_INTERNAL_URL",
        "OAUTH_SERVER_URL",
        "OAUTH_CLIENT_URL",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_CLIENT_ID",
        "OAUTH_ENABLED",
    )
    if not any(env.get(key) for key in env_keys):
        return None

    server_public_url = env.get("OAUTH_SERVER_PUBLIC_URL", "").strip()
    server_internal_url = env.get("OAUTH_SERVER_INTERNAL_URL", "").strip()
    server_url = env.get("OAUTH_SERVER_URL", "").strip()
    if not server_public_url:
        server_public_url = server_url
    if not server_internal_url:
        server_internal_url = server_url
    client_url = env.get("OAUTH_CLIENT_URL", "").strip()
    client_secret = env.get("OAUTH_CLIENT_SECRET", "").strip()
    if not server_public_url or not server_internal_url or not client_url or not client_secret:
        raise OAuthResultError(
            "invalid oauth env config",
            detail=(
                "Set OAUTH_SERVER_PUBLIC_URL and OAUTH_SERVER_INTERNAL_URL "
                "(or OAUTH_SERVER_URL as fallback), plus OAUTH_CLIENT_URL and "
                "OAUTH_CLIENT_SECRET when using environment-based OAuth config."
            ),
        )

    config: dict[str, Any] = {
        "enabled": _as_bool(env.get("OAUTH_ENABLED"), default=True),
        "resolve_real_ip": _as_bool(env.get("OAUTH_RESOLVE_REAL_IP"), default=False),
        "whitelist": _csv_list(env.get("OAUTH_WHITELIST")),
        "server": {
            "url": server_public_url,
            "public_url": server_public_url,
            "internal_url": server_internal_url,
            "connect_page": env.get("OAUTH_CONNECT_PAGE", "/oauth/connect"),
            "token_api": env.get("OAUTH_TOKEN_API", "/api/oauth/token"),
            "profile_api": env.get("OAUTH_PROFILE_API", "/api/account/me"),
            "admin_users_api": env.get("OAUTH_ADMIN_USERS_API", "/api/admin/users"),
            "admin_user_by_name_api": env.get(
                "OAUTH_ADMIN_USER_BY_NAME_API", "/api/admin/user-by-name"
            ),
            "admin_groups_api": env.get("OAUTH_ADMIN_GROUPS_API", "/api/admin/groups"),
            "profile_page": env.get("OAUTH_PROFILE_PAGE", "/settings/profile"),
            "admin_user_page": env.get("OAUTH_ADMIN_USER_PAGE", "/admin/account/users/u/{uid}"),
            "admin_group_page": env.get("OAUTH_ADMIN_GROUP_PAGE", "/admin/account/groups/g/{gid}"),
        },
        "client": {
            "id": _as_int(env.get("OAUTH_CLIENT_ID"), default=1),
            "secret": client_secret,
            "url": client_url,
            "callback_path": env.get("OAUTH_CLIENT_CALLBACK_PATH", "/oauth-callback"),
            "profile_path": env.get("OAUTH_CLIENT_PROFILE_PATH", "/account/profile"),
            "admin_user_path": env.get("OAUTH_CLIENT_ADMIN_USER_PATH", "/admin/users/<int:uid>"),
            "admin_group_path": env.get(
                "OAUTH_CLIENT_ADMIN_GROUP_PATH", "/admin/groups/<int:gid>"
            ),
        },
    }

    logout_page = env.get("OAUTH_LOGOUT_PAGE")
    if logout_page is not None and logout_page.strip():
        config["server"]["logout_page"] = logout_page.strip()
    return config


def _normalize_oauth_config(config: dict[str, Any]) -> dict[str, Any]:
    """Normalize server URL aliases for public/internal routing."""
    server = config.get("server")
    if not isinstance(server, dict):
        return config
    public_url = (server.get("public_url") or server.get("url") or "").strip()
    internal_url = (server.get("internal_url") or server.get("url") or public_url).strip()
    if public_url:
        server["public_url"] = public_url
        server["url"] = public_url  # legacy compatibility
    if internal_url:
        server["internal_url"] = internal_url
    return config


def load_oauth_config(config_file: str) -> dict[str, Any]:
    """Load OAuth config from env vars or JSON file and validate it."""
    env_config = _build_oauth_config_from_env()
    if env_config is not None:
        return _normalize_oauth_config(validate_oauth_config(env_config))

    try:
        with open(config_file, encoding="utf-8") as file_obj:
            config = json.load(file_obj)
    except FileNotFoundError as exc:
        raise OAuthResultError(
            "oauth config not found",
            detail=(
                f"Cannot find '{config_file}'. Either provide this file or set "
                "OAUTH_SERVER_PUBLIC_URL/OAUTH_SERVER_INTERNAL_URL (or OAUTH_SERVER_URL), "
                "OAUTH_CLIENT_URL, and OAUTH_CLIENT_SECRET."
            ),
        ) from exc
    return _normalize_oauth_config(validate_oauth_config(config))
