"""HTTP client helpers for OAuth/account/admin API calls."""

from __future__ import annotations

import requests

from .constants import PARAM_OAUTH_TOKEN
from .exceptions import OAuthAPIError, OAuthRequestError, OAuthResultError
from .parsers import parse_group, parse_response_error, parse_user
from .validation import (
    validate_add_group_payload,
    validate_admin_users_payload,
    validate_token_request,
    validate_token_response,
)


def _server_public_url(config: dict) -> str:
    server = config["server"]
    return server.get("public_url") or server["url"]


def _server_internal_url(config: dict) -> str:
    server = config["server"]
    return server.get("internal_url") or server.get("public_url") or server["url"]


def request_access_token(config, authorization_token):
    """Exchange an authorization token for an access token."""
    if not authorization_token:
        raise OAuthRequestError("authorization token is required")

    config_server = config["server"]
    config_client = config["client"]
    params = {
        "client_id": config_client["id"],
        "client_secret": config_client["secret"],
        "redirect_url": config_client["url"] + config_client["callback_path"],
        "token": authorization_token,
    }
    params = validate_token_request(params)

    try:
        response = requests.post(_server_internal_url(config) + config_server["token_api"], params)
    except IOError as exc:
        raise OAuthAPIError("failed to access OAuth API (access token)") from exc

    if response.status_code != 200:
        raise parse_response_error(response)
    try:
        data = response.json()
    except ValueError as exc:
        raise OAuthResultError("invalid data format (token)") from exc

    data = validate_token_response(data)
    token = data.get("access_token")
    if not token:
        raise OAuthResultError("access_token is missing or empty")
    return token


def request_resource(config, path, access_token, method="get", **kwargs):
    """Request OAuth server resource with mandatory oauth access token."""
    if not access_token:
        raise OAuthRequestError("access token is required")
    config_server = config["server"]

    params = dict(kwargs.get("params") or {})
    params[PARAM_OAUTH_TOKEN] = access_token

    try:
        response = requests.request(method, _server_internal_url(config) + path, params=params, **kwargs)
    except IOError as exc:
        raise OAuthAPIError("failed to access OAuth API") from exc

    if response.status_code // 100 != 2:
        raise parse_response_error(response)
    return response


def request_resource_json(config, path, access_token, method="get", **kwargs):
    """Request JSON payload from OAuth server resource."""
    response = request_resource(config, path, access_token, method, **kwargs)
    try:
        return response.json()
    except ValueError as exc:
        raise OAuthResultError("invalid data format") from exc


def request_oauth_user(config, access_token):
    """Fetch current user profile from OAuth account API."""
    data = request_resource_json(config, config["server"]["profile_api"], access_token)
    return parse_user(data, _server_public_url(config))


def get_user_by_id(config, uid, access_token):
    """Fetch a user by id from admin users API."""
    path = config["server"]["admin_users_api"].rstrip("/") + "/%d" % uid
    data = request_resource_json(config, path, access_token)
    return parse_user(data, _server_public_url(config))


def get_user_by_name(config, name, access_token):
    """Fetch a user by name from admin API."""
    path = config["server"]["admin_user_by_name_api"].rstrip("/") + "/%s" % name
    data = request_resource_json(config, path, access_token)
    return parse_user(data, _server_public_url(config))


def get_users(config, access_token):
    """Fetch all users and expand their group ids to group objects."""
    data = request_resource_json(config, config["server"]["admin_users_api"], access_token)
    normalized = validate_admin_users_payload(data)
    user_dicts = normalized["users"]
    group_dicts = normalized["groups"]
    groups = {_group["id"]: parse_group(_group) for _group in group_dicts}
    users = []
    for user_dict in user_dicts:
        user = parse_user(user_dict, _server_public_url(config))
        for gid in user_dict.get("group_ids", []):
            if gid in groups:
                user.groups.append(groups[gid])
        users.append(user)
    return users


def get_group_by_id(config, gid, access_token):
    """Fetch a group by id from admin groups API."""
    path = config["server"]["admin_groups_api"].rstrip("/") + "/%d" % gid
    data = request_resource_json(config, path, access_token)
    return parse_group(data)


def get_groups(config, access_token):
    """Fetch all groups from admin groups API."""
    data = request_resource_json(config, config["server"]["admin_groups_api"], access_token)
    return [parse_group(group_dict) for group_dict in data]


def get_users_in_group(config, gid, access_token):
    """Fetch users inside a specific group id."""
    path = config["server"]["admin_groups_api"].rstrip("/") + "/%d/users" % gid
    data = request_resource_json(config, path, access_token)
    return [parse_user(user_dict, _server_public_url(config)) for user_dict in data]


def add_group(config, access_token, name, description=None):
    """Create a group via admin groups API."""
    group_data = validate_add_group_payload({"name": name, "description": description})
    data = request_resource_json(
        config,
        config["server"]["admin_groups_api"],
        access_token,
        method="post",
        json=group_data,
    )
    return parse_group(data)
