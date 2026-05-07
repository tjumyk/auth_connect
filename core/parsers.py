"""Parsers for OAuth server responses into library domain objects."""

from __future__ import annotations

import json

from .exceptions import OAuthAPIError, OAuthRequestError, OAuthResultError
from .models import Group, User
from .validation import validate_user_payload


def parse_response_error(response):
    """Convert a failed HTTP response to a typed OAuth exception."""
    try:
        data = json.loads(response.text)
        msg = data.get("msg")
        if response.status_code // 100 == 4:
            return OAuthRequestError(msg=msg, detail=data.get("detail"))
        return OAuthAPIError(msg=msg, detail=data.get("detail"))
    except (ValueError, KeyError):
        return OAuthAPIError(msg="Status %d" % response.status_code, detail=response.text)


def parse_group(group_dict):
    """Parse and validate a group payload into a `Group` model."""
    if not group_dict:
        raise OAuthResultError("empty group body")
    group = Group(group_dict.get("id"), group_dict.get("name"), group_dict.get("description"))
    if group.id is None:
        raise OAuthResultError("group id is missing")
    if type(group.id) != int:
        raise OAuthResultError("group id should be an integer")
    if not group.name:
        raise OAuthResultError("group name is missing or empty")
    return group


def parse_user(user_dict, server_url):
    """Parse and validate a user payload into a `User` model."""
    if not user_dict:
        raise OAuthResultError("empty user body")
    normalized = validate_user_payload(user_dict)
    user = User(
        normalized.get("id"),
        normalized.get("name"),
        normalized.get("email"),
        normalized.get("nickname"),
        normalized.get("avatar"),
    )
    if user.id is None:
        raise OAuthResultError("user id is missing")
    if type(user.id) != int:
        raise OAuthResultError("user id should be an integer")
    if not user.name:
        raise OAuthResultError("user name is missing or empty")
    if not user.email:
        raise OAuthResultError("user email is missing or empty")
    if user.avatar and not user.avatar.startswith("http://") and not user.avatar.startswith("https://"):
        user.avatar = server_url + "/" + user.avatar.lstrip("/")
    group_dicts = normalized.get("groups")
    if group_dicts:
        for group_dict in group_dicts:
            user.groups.append(parse_group(group_dict))
    return user
