"""Backward-compatible public OAuth API exports.

The implementation now lives under `auth_connect.core`, while this file remains
the stable import surface.
"""

try:  # pragma: no cover - compatibility for direct module import
    from .core.constants import (
        ADMIN_GROUP_NAME as _admin_group_name,
        CONFIG_KEY as _config_key,
        REQUEST_USER_KEY as _request_user_key,
        SESSION_ACCESS_TOKEN_KEY as _session_access_token_key,
        SESSION_UID_KEY as _session_uid_key,
    )
    from .core.exceptions import OAuthAPIError, OAuthError, OAuthRequestError, OAuthRequired, OAuthResultError
    from .core.flask_integration import (
        _is_oauth_skipped,
        add_group,
        clear_user,
        get_group_by_id,
        get_groups,
        get_uid,
        get_user,
        get_user_by_id,
        get_user_by_id_with_token,
        get_user_by_name,
        get_users,
        get_users_in_group,
        init_app,
        requires_admin,
        requires_login,
        build_oauth_connect_url,
        build_oauth_logout_url,
    )
    from .core.models import Group, User
except ImportError:  # pragma: no cover
    from core.constants import (  # type: ignore
        ADMIN_GROUP_NAME as _admin_group_name,
        CONFIG_KEY as _config_key,
        REQUEST_USER_KEY as _request_user_key,
        SESSION_ACCESS_TOKEN_KEY as _session_access_token_key,
        SESSION_UID_KEY as _session_uid_key,
    )
    from core.exceptions import OAuthAPIError, OAuthError, OAuthRequestError, OAuthRequired, OAuthResultError  # type: ignore
    from core.flask_integration import (  # type: ignore
        _is_oauth_skipped,
        add_group,
        clear_user,
        get_group_by_id,
        get_groups,
        get_uid,
        get_user,
        get_user_by_id,
        get_user_by_id_with_token,
        get_user_by_name,
        get_users,
        get_users_in_group,
        init_app,
        requires_admin,
        requires_login,
        build_oauth_connect_url,
        build_oauth_logout_url,
    )
    from core.models import Group, User  # type: ignore

__all__ = [
    "OAuthError",
    "OAuthRequired",
    "OAuthRequestError",
    "OAuthAPIError",
    "OAuthResultError",
    "User",
    "Group",
    "requires_login",
    "requires_admin",
    "_is_oauth_skipped",
    "get_uid",
    "get_user",
    "clear_user",
    "get_user_by_id",
    "get_user_by_id_with_token",
    "get_user_by_name",
    "get_users",
    "get_group_by_id",
    "get_groups",
    "get_users_in_group",
    "add_group",
    "init_app",
    "build_oauth_connect_url",
    "build_oauth_logout_url",
]
