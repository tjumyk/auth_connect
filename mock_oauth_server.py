"""
Minimal mock OAuth 2.0 server compatible with auth_connect client logic.

Implements:
- GET  /oauth/connect              — authorization page; redirects to client callback with token
- POST /api/oauth/token             — exchange authorization token for access_token
- GET  /api/account/me              — profile (oauth_token in query)
- GET  /api/admin/users             — admin users list (oauth_token in query)
- GET  /api/admin/users/<uid>       — single user by id (oauth_token in query)
- GET  /api/admin/user-by-name/<name> — single user by name (oauth_token in query)
- GET  /api/admin/groups            — admin groups list (oauth_token in query)
- GET  /api/admin/groups/<gid>      — single group by id (oauth_token in query)
- GET  /api/admin/groups/<gid>/users — users in group (oauth_token in query)
"""

import json
import os
import secrets
from pathlib import Path
from typing import Any

from urllib.parse import urlencode

from flask import Flask, request, redirect, jsonify, Response, session
from pydantic import BaseModel

_SESSION_USER_ID_KEY = "mock_user_id"

# Default config file at project root (oauth.mock.config.json), when run from project root
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "oauth.mock.config.json"


# --- Config (server runtime + loaded from oauth.mock.config.json) ---

class OAuthClientConfig(BaseModel):
    id: int
    secret: str
    redirect_url: str = "http://localhost:8888/oauth-callback"


class MockOAuthConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8077
    client_id: int = 1
    client_secret: str = "someLongSecret"
    default_redirect_url: str = "http://localhost:8888/oauth-callback"


def _load_mock_data(config_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Load users, groups, and clients from oauth.mock.config.json. Returns (users, groups, clients)."""
    with open(config_path, encoding="utf-8") as f:
        data = json.load(f)
    users = data.get("users") or []
    groups = data.get("groups") or []
    clients = data.get("clients") or []
    return users, groups, clients


def _expand_user_groups(users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> None:
    """In-place: replace each user's 'groups' (list of {id} or ids) with full group dicts from groups list."""
    groups_by_id = {g["id"]: dict(g) for g in groups}
    for u in users:
        raw = u.get("groups") or []
        if not raw:
            u["groups"] = []
            continue
        ids = []
        for x in raw:
            if isinstance(x, dict):
                gid = x.get("id")
                if gid is not None:
                    ids.append(gid)
            else:
                ids.append(x)
        u["groups"] = [groups_by_id[gid] for gid in ids if gid in groups_by_id]


def load_mock_oauth_config(config_path: Path | str | None = None) -> tuple[MockOAuthConfig, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Load server config (env overrides) and mock data from oauth.mock.config.json. Returns (server_config, users, groups, clients)."""
    path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
    users, groups, clients = _load_mock_data(path)
    _expand_user_groups(users, groups)

    # First client in file is the default; env can override
    default_client = clients[0] if clients else {"id": 1, "secret": "someLongSecret", "redirect_url": "http://localhost:8888/oauth-callback"}
    client_id = int(os.environ.get("MOCK_OAUTH_CLIENT_ID", str(default_client["id"])))
    client_secret = os.environ.get("MOCK_OAUTH_CLIENT_SECRET")
    default_redirect_url = os.environ.get("MOCK_OAUTH_REDIRECT_URL")
    if clients and (client_secret is None or default_redirect_url is None):
        c = next((c for c in clients if c["id"] == client_id), default_client)
        if client_secret is None:
            client_secret = c.get("secret", "someLongSecret")
        if default_redirect_url is None:
            default_redirect_url = c.get("redirect_url", "http://localhost:8888/oauth-callback")

    server_config = MockOAuthConfig(
        port=int(os.environ.get("MOCK_OAUTH_PORT", "8077")),
        client_id=client_id,
        client_secret=client_secret or "someLongSecret",
        default_redirect_url=default_redirect_url or "http://localhost:8888/oauth-callback",
    )
    return server_config, users, groups, clients


# --- In-memory token store (user/group data comes from config file) ---

# auth_token -> (client_id, redirect_url, user_id)
_auth_tokens: dict[str, tuple[int, str, int]] = {}
# access_token -> user_id
_access_tokens: dict[str, int] = {}

# Loaded at startup (see main / _create_app)
MOCK_USERS: list[dict[str, Any]] = []
MOCK_GROUPS: list[dict[str, Any]] = []
MOCK_CLIENTS: list[dict[str, Any]] = []


def _user_by_id(uid: int) -> dict[str, Any] | None:
    for u in MOCK_USERS:
        if u["id"] == uid:
            return u
    return None


def _user_by_name(name: str) -> dict[str, Any] | None:
    name_lower = (name or "").strip().lower()
    if not name_lower:
        return None
    for u in MOCK_USERS:
        if (u.get("nickname") or "").lower() == name_lower or (u.get("name") or "").lower() == name_lower:
            return u
    return None


def _group_by_id(gid: int) -> dict[str, Any] | None:
    for g in MOCK_GROUPS:
        if g["id"] == gid:
            return g
    return None


def _create_app(config: MockOAuthConfig) -> Flask:
    global MOCK_USERS, MOCK_GROUPS
    app = Flask(__name__)
    app.secret_key = os.environ.get("MOCK_OAUTH_SECRET_KEY", "mock-oauth-dev-secret")
    # Use first matching client from config file, or server config default
    client_dict = next(
        (c for c in MOCK_CLIENTS if c.get("id") == config.client_id),
        {"id": config.client_id, "secret": config.client_secret, "redirect_url": config.default_redirect_url},
    )
    client = OAuthClientConfig(
        id=client_dict["id"],
        secret=client_dict.get("secret") or config.client_secret,
        redirect_url=client_dict.get("redirect_url") or config.default_redirect_url,
    )

    # --- GET /oauth/connect (authorization page) ---
    # Client sends: client_id, redirect_url, optional original_path, state
    # If no user_id: show minimal UI to pick a user. If user_id present: issue token and redirect.
    def _connect_params() -> dict[str, str]:
        return {
            "client_id": request.args.get("client_id", ""),
            "redirect_url": request.args.get("redirect_url", ""),
            "original_path": request.args.get("original_path", ""),
            "state": request.args.get("state", ""),
        }

    def _user_picker_rows(link_base: str, extra_params: dict[str, str] | None = None) -> str:
        """HTML <li> items for each mock user. Links to link_base?user_id=X & extra_params."""
        params = dict(extra_params) if extra_params else {}
        rows = []
        for u in MOCK_USERS:
            q = {**params, "user_id": str(u["id"])}
            qs = urlencode({k: v for k, v in q.items() if v})
            label = u.get("name") or u.get("nickname") or f"User {u['id']}"
            rows.append(f'<li><a href="{link_base}?{qs}">{label}</a></li>')
        return "".join(rows)

    def _connect_picker_html() -> str:
        base = request.path
        params = _connect_params()
        rows = _user_picker_rows(base, params)
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Mock OAuth – Choose user</title></head>"
            "<body><h1>Mock OAuth</h1><p>Choose a user to log in as:</p><ul>"
            + rows
            + "</ul></body></html>"
        )

    def _index_picker_html() -> str:
        """Same picker UI for / when not logged in."""
        rows = _user_picker_rows("/login", {})
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Mock OAuth</title></head>"
            "<body><h1>Mock OAuth</h1><p>Choose a user to log in as:</p><ul>"
            + rows
            + "</ul></body></html>"
        )

    def _index_logged_in_html(user: dict[str, Any]) -> str:
        name = user.get("name") or user.get("nickname") or f"User {user['id']}"
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Mock OAuth</title></head>"
            "<body><h1>Mock OAuth</h1><p>Logged in as <strong>"
            + _html_escape(name)
            + "</strong> (id="
            + str(user["id"])
            + ").</p><p><a href='/logout'>Log out</a></p></body></html>"
        )

    def _html_escape(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    # --- GET / (mock server home: pick user or show current user + log out) ---
    @app.route("/", methods=["GET"])
    def index() -> Any:
        uid = session.get(_SESSION_USER_ID_KEY)
        if uid is None:
            return Response(_index_picker_html(), mimetype="text/html")
        user = _user_by_id(uid)
        if user is None:
            session.pop(_SESSION_USER_ID_KEY, None)
            return Response(_index_picker_html(), mimetype="text/html")
        return Response(_index_logged_in_html(user), mimetype="text/html")

    # --- GET /login?user_id=X (set session and redirect to /) ---
    @app.route("/login", methods=["GET"])
    def login() -> Any:
        user_id = request.args.get("user_id", type=int)
        if user_id is not None and _user_by_id(user_id) is not None:
            session[_SESSION_USER_ID_KEY] = user_id
        return redirect("/")

    # --- GET /logout (clear session and redirect to /) ---
    @app.route("/logout", methods=["GET"])
    def logout() -> Any:
        session.pop(_SESSION_USER_ID_KEY, None)
        return redirect("/")

    @app.route("/oauth/connect", methods=["GET"])
    def oauth_connect() -> Any:
        client_id = request.args.get("client_id", type=int)
        redirect_url = request.args.get("redirect_url", "").strip()
        original_path = request.args.get("original_path", "")
        state = request.args.get("state", "")

        if not redirect_url:
            return jsonify(msg="redirect_url required", detail="missing"), 400
        if client_id != client.id:
            return jsonify(msg="invalid client", detail="client_id"), 400

        user_id = request.args.get("user_id", type=int)
        # If no user in query but we have a valid session user, use it (skip picker)
        if user_id is None:
            uid = session.get(_SESSION_USER_ID_KEY)
            if uid is not None and _user_by_id(uid) is not None:
                user_id = uid
        if user_id is None:
            return Response(_connect_picker_html(), mimetype="text/html")

        if _user_by_id(user_id) is None:
            return jsonify(msg="user not found", detail="user_id"), 400

        # Share login state: set session so / and /logout reflect this user
        session[_SESSION_USER_ID_KEY] = user_id

        auth_token = secrets.token_urlsafe(32)
        _auth_tokens[auth_token] = (client_id, redirect_url, user_id)

        sep = "&" if "?" in redirect_url else "?"
        params = [f"token={auth_token}"]
        if state:
            params.append(f"state={state}")
        if original_path:
            params.append(f"original_path={original_path}")
        return redirect(redirect_url + sep + "&".join(params))

    # --- POST /api/oauth/token ---
    # Params: client_id, client_secret, redirect_url, token (auth_connect sends them as query params)
    # Returns: { "access_token": "..." }
    @app.route("/api/oauth/token", methods=["POST"])
    def oauth_token() -> Any:
        data = request.args or request.get_json(silent=True) or request.form or {}
        client_id = data.get("client_id")
        if client_id is not None:
            try:
                client_id = int(client_id)
            except (TypeError, ValueError):
                client_id = None
        client_secret = data.get("client_secret", "")
        redirect_url = (data.get("redirect_url") or "").strip()
        token = data.get("token", "").strip()

        if not token:
            return jsonify(msg="authorization token is required", detail="token"), 400
        if client_id != client.id or client_secret != client.secret:
            return jsonify(msg="invalid client", detail="client_id/secret"), 401

        payload = _auth_tokens.pop(token, None)
        if payload is None:
            return jsonify(msg="invalid or expired token", detail="token"), 400
        stored_client_id, stored_redirect_url, user_id = payload
        if stored_client_id != client_id or stored_redirect_url != redirect_url:
            return jsonify(msg="redirect_url or client mismatch", detail="request"), 400

        access_token = secrets.token_urlsafe(32)
        _access_tokens[access_token] = user_id
        return jsonify(access_token=access_token)

    def _require_access_token() -> tuple[int | None, Any]:
        token = request.args.get("oauth_token", "").strip()
        if not token:
            return None, (jsonify(msg="access token is required", detail="oauth_token"), 401)
        user_id = _access_tokens.get(token)
        if user_id is None:
            return None, (jsonify(msg="invalid or expired access token", detail="oauth_token"), 401)
        return user_id, None

    # --- GET /api/account/me ---
    # Query: oauth_token
    # Returns: user object (id, name, email, nickname, avatar, groups)
    @app.route("/api/account/me", methods=["GET"])
    def account_me() -> Any:
        user_id, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        user = _user_by_id(user_id)
        if user is None:
            return jsonify(msg="user not found", detail="id"), 404
        return jsonify(user)

    # --- GET /api/admin/users ---
    # Returns: { "users": [...], "groups": [...] } with group_ids on users (auth_connect expects this)
    @app.route("/api/admin/users", methods=["GET"])
    def admin_users() -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        users_payload = [
            {
                **u,
                "group_ids": [g["id"] for g in u.get("groups", [])],
            }
            for u in MOCK_USERS
        ]
        return jsonify(users=users_payload, groups=MOCK_GROUPS)

    # --- GET /api/admin/groups ---
    @app.route("/api/admin/groups", methods=["GET"])
    def admin_groups() -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        return jsonify(MOCK_GROUPS)

    # --- GET /api/admin/users/<int:uid> ---
    @app.route("/api/admin/users/<int:uid>", methods=["GET"])
    def admin_user_by_id(uid: int) -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        user = _user_by_id(uid)
        if user is None:
            return jsonify(msg="user not found", detail="id"), 404
        return jsonify(user)

    # --- GET /api/admin/user-by-name/<name> ---
    @app.route("/api/admin/user-by-name/<path:name>", methods=["GET"])
    def admin_user_by_name(name: str) -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        user = _user_by_name(name)
        if user is None:
            return jsonify(msg="user not found", detail="name"), 404
        return jsonify(user)

    # --- GET /api/admin/groups/<int:gid> ---
    @app.route("/api/admin/groups/<int:gid>", methods=["GET"])
    def admin_group_by_id(gid: int) -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        group = _group_by_id(gid)
        if group is None:
            return jsonify(msg="group not found", detail="id"), 404
        return jsonify(group)

    # --- GET /api/admin/groups/<int:gid>/users ---
    @app.route("/api/admin/groups/<int:gid>/users", methods=["GET"])
    def admin_group_users(gid: int) -> Any:
        _, err = _require_access_token()
        if err is not None:
            return err[0], err[1]
        if _group_by_id(gid) is None:
            return jsonify(msg="group not found", detail="id"), 404
        users_in_group = [u for u in MOCK_USERS if any(g["id"] == gid for g in u.get("groups", []))]
        return jsonify(users_in_group)

    return app


def main() -> None:
    config, users, groups, clients = load_mock_oauth_config()
    if not users:
        raise SystemExit("oauth.mock.config.json must define at least one user")
    global MOCK_USERS, MOCK_GROUPS, MOCK_CLIENTS
    MOCK_USERS = users
    MOCK_GROUPS = groups
    MOCK_CLIENTS = clients
    app = _create_app(config)
    print(f"Mock OAuth server: http://{config.host}:{config.port}")
    print("  Connect: GET /oauth/connect?client_id=1&redirect_url=...")
    print("  Token:   POST /api/oauth/token")
    print("  Profile: GET /api/account/me?oauth_token=...")
    app.run(host=config.host, port=config.port, debug=False)


if __name__ == "__main__":
    main()
