"""Flask integration layer for the OAuth client library."""

from __future__ import annotations

from functools import wraps
from typing import Callable, List
from urllib.parse import urlencode

from flask import Flask, current_app, g, jsonify, redirect, request, session

from .client import (
    add_group as _add_group,
    get_group_by_id as _get_group_by_id,
    get_groups as _get_groups,
    get_user_by_id as _get_user_by_id,
    get_user_by_name as _get_user_by_name,
    get_users as _get_users,
    get_users_in_group as _get_users_in_group,
    request_access_token,
    request_oauth_user,
)
from .config import load_oauth_config
from .constants import (
    ADMIN_GROUP_NAME,
    CONFIG_KEY,
    REQUEST_USER_KEY,
    SESSION_ACCESS_TOKEN_KEY,
    SESSION_UID_KEY,
    STATE_NEW_REQUEST,
    STATE_REQUEST_ERROR,
)
from .exceptions import OAuthError, OAuthRequestError, OAuthRequired
from .models import Group, User
from .validation import serialize_error_payload, serialize_route_bindings

_login_callback: Callable[[User], object] | None = None


def _error_html(msg, detail=None):
    if detail is None:
        detail = ""
    return "<html><body><h1>%s</h1><p>%s</p></body></html>" % (str(msg), str(detail))


def _preferred_mime():
    mimes = request.accept_mimetypes
    for mime in mimes:
        if mime[0] == "text/html":
            return mime[0]
        if mime[0] == "application/json":
            return mime[0]
    return "text/html"


def _get_config():
    config = current_app.config.get(CONFIG_KEY)
    if config is None:
        raise OAuthRequestError("oauth app is not initialized")
    return config


def _build_redirect_url(original_path, state):
    config = _get_config()
    config_server = config["server"]
    config_client = config["client"]
    params = {
        "client_id": config_client["id"],
        "redirect_url": config_client["url"] + config_client["callback_path"],
    }
    if original_path:
        params["original_path"] = original_path
    if state:
        params["state"] = state
    redirect_url = config_server["url"] + config_server["connect_page"]
    return redirect_url + "?" + urlencode(params)


def build_oauth_connect_url(original_path='/'):
    """Build Identity OAuth connect URL for optional SSO button."""
    return _build_redirect_url(original_path=original_path, state=STATE_NEW_REQUEST)


def _build_error_response(error: OAuthError, original_path=None, previous_state=None):
    mime = _preferred_mime()
    if isinstance(error, (OAuthRequired, OAuthRequestError)) and previous_state not in [
        STATE_NEW_REQUEST,
        STATE_REQUEST_ERROR,
    ]:
        state = STATE_NEW_REQUEST if isinstance(error, OAuthRequired) else STATE_REQUEST_ERROR
        redirect_url = _build_redirect_url(original_path=original_path, state=state)
        if mime == "text/html":
            return redirect(redirect_url)
        return jsonify(serialize_error_payload(error.msg, error.detail, redirect_url)), 401

    if mime == "text/html":
        return _error_html(error.msg, error.detail), 500
    return jsonify(serialize_error_payload(error.msg, error.detail)), 500


def _is_oauth_skipped():
    config = _get_config()
    if not config.get("enabled"):
        return True

    whitelist = config.get("whitelist")
    if whitelist:
        if config.get("resolve_real_ip"):
            ip = request.environ.get("HTTP_X_REAL_IP") or request.remote_addr
        else:
            ip = request.remote_addr
        if ip in whitelist:
            return True
    return False


def _get_original_path():
    if _preferred_mime() == "text/html":
        return request.full_path.rstrip("?")

    referrer = request.referrer
    config = _get_config()
    client_url_prefix = config["client"]["url"].rstrip("/")
    if referrer and referrer.startswith(client_url_prefix):
        path = referrer[len(client_url_prefix) :]
        if not path:
            return "/"
        if path[0] != "/":
            return None
        return path
    return None


def _get_access_token():
    token = session.get(SESSION_ACCESS_TOKEN_KEY)
    if token is None:
        clear_user()
        raise OAuthRequired()
    return token


def _oauth_callback():
    config = _get_config()
    client_config = config["client"]

    token = request.args.get("token")
    state = request.args.get("state")
    original_path = request.args.get("original_path")

    try:
        access_token = request_access_token(config, token)
        user = request_oauth_user(config, access_token)

        if _login_callback:
            ret = _login_callback(user)
            if ret is not None:
                return ret

        session[SESSION_UID_KEY] = user.id
        session[SESSION_ACCESS_TOKEN_KEY] = access_token

        if original_path:
            if original_path[0] != "/":
                original_path = "/" + original_path
        else:
            original_path = "/"
        return redirect(client_config["url"].rstrip("/") + original_path)
    except OAuthError as error:
        return _build_error_response(error, original_path, state)


def requires_login(f):
    """Protect a route and require a valid OAuth user session."""

    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            user = get_user()
            if user and _login_callback:
                ret = _login_callback(user)
                if ret is not None:
                    return ret
            return f(*args, **kwargs)
        except OAuthError as error:
            return _build_error_response(error, _get_original_path())

    return wrapped


def requires_admin(f):
    """Protect a route and additionally require group `admin`."""

    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            user = get_user()
            if user and _login_callback:
                ret = _login_callback(user)
                if ret is not None:
                    return ret
            if user is None:
                return jsonify(serialize_error_payload("user info required")), 401
            is_admin = any(group.name == ADMIN_GROUP_NAME for group in user.groups)
            if not is_admin:
                return jsonify(serialize_error_payload("admin required")), 403
            return f(*args, **kwargs)
        except OAuthError as error:
            return _build_error_response(error, _get_original_path())

    return wrapped


def get_uid() -> [int, None]:
    """Get current OAuth user id from session."""
    return session.get(SESSION_UID_KEY)


def get_user() -> [User, None]:
    """Get current user and cache it on Flask request context."""
    if _is_oauth_skipped():
        return None
    user = g.get(REQUEST_USER_KEY)
    if user is not None:
        return user
    uid = get_uid()
    if uid is None:
        clear_user()
        raise OAuthRequired()
    access_token = _get_access_token()
    user = request_oauth_user(_get_config(), access_token)
    setattr(g, REQUEST_USER_KEY, user)
    return user


def clear_user() -> None:
    """Remove all OAuth data in the current session/request context."""
    if REQUEST_USER_KEY in g:
        g.pop(REQUEST_USER_KEY)
    if SESSION_UID_KEY in session:
        del session[SESSION_UID_KEY]
    if SESSION_ACCESS_TOKEN_KEY in session:
        del session[SESSION_ACCESS_TOKEN_KEY]


def get_user_by_id(uid: int) -> [User, None]:
    """Fetch a user by id using current session access token."""
    return _get_user_by_id(_get_config(), uid, _get_access_token())


def get_user_by_id_with_token(uid: int, access_token: str) -> [User, None]:
    """Fetch user by id using a provided access token."""
    return _get_user_by_id(_get_config(), uid, access_token)


def get_user_by_name(name: str) -> [User, None]:
    """Fetch a user by display name or nickname."""
    return _get_user_by_name(_get_config(), name, _get_access_token())


def get_users() -> List[User]:
    """Fetch all users from admin API with groups expanded."""
    return _get_users(_get_config(), _get_access_token())


def get_group_by_id(gid: int) -> [Group, None]:
    """Fetch a group by id from admin API."""
    return _get_group_by_id(_get_config(), gid, _get_access_token())


def get_groups() -> List[Group]:
    """Fetch all groups from admin API."""
    return _get_groups(_get_config(), _get_access_token())


def get_users_in_group(gid: int) -> List[User]:
    """Fetch all users in a given group."""
    return _get_users_in_group(_get_config(), gid, _get_access_token())


def add_group(name, description=None) -> Group:
    """Create a group in remote admin API."""
    return _add_group(_get_config(), _get_access_token(), name, description)


def init_app(app: Flask, config_file: str = "oauth.config.json", login_callback=None) -> None:
    """Initialize OAuth config and register integration routes."""
    global _login_callback
    config = load_oauth_config(config_file)
    app.config[CONFIG_KEY] = config

    server_config = config["server"]
    client_config = config["client"]
    server_url = server_config["url"]

    routes = serialize_route_bindings(
        {
            "callback_path": client_config["callback_path"],
            "profile_path": client_config["profile_path"],
            "admin_user_path": client_config["admin_user_path"],
            "admin_group_path": client_config["admin_group_path"],
            "profile_page": server_config["profile_page"],
            "admin_user_page": server_config["admin_user_page"],
            "admin_group_page": server_config["admin_group_page"],
        }
    )

    app.add_url_rule(routes["callback_path"], None, _oauth_callback)
    app.add_url_rule(
        routes["profile_path"],
        "account_profile",
        lambda: redirect(server_url + routes["profile_page"]),
    )
    app.add_url_rule(
        routes["admin_user_path"],
        "admin_user",
        lambda uid: redirect(server_url + routes["admin_user_page"].format(uid=uid)),
    )
    app.add_url_rule(
        routes["admin_group_path"],
        "admin_group",
        lambda gid: redirect(server_url + routes["admin_group_page"].format(gid=gid)),
    )
    _login_callback = login_callback
