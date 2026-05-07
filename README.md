# auth_connect

OAuth 2.0 client library for Flask applications. Handles login flow, session, and role checks (e.g. admin via group membership). Compatible with an external OAuth provider or the included mock server for development.

## Requirements

- Python 3.x
- Flask
- requests
- pydantic v2 (optional, enables request/response validation + route payload serialization)

Install with:

```bash
pip install -r requirements.txt
```

Optional validation mode:

```bash
pip install pydantic>=2,<3
```

When `pydantic` is installed, `auth_connect` validates OAuth server request/response payloads and serializes app-bound route/error payloads with schemas. Without `pydantic`, it preserves legacy parsing behavior.

## Quick start

1. Copy the client config example and point it at your OAuth server:

   ```bash
   cp oauth.config.example.json oauth.config.json
   # Edit oauth.config.json: server.url, client.url, client.id, client.secret, paths
   ```

2. In your Flask app:

   ```python
   from flask import Flask
   from auth_connect import oauth

   app = Flask(__name__)
   app.config["SECRET_KEY"] = "your-secret-key"
   oauth.init_app(app, config_file="oauth.config.json")

   @app.route("/api/me")
   @oauth.requires_login
   def me():
       user = oauth.get_user()
       return {"uid": user.id, "name": user.name, "email": user.email}
   ```

3. Your app must use sessions (e.g. `SECRET_KEY` and session cookie config). The library stores `uid` and `access_token` in the session and registers the callback route (e.g. `/oauth-callback`) and optional redirect routes (profile, admin user/group pages).

## Client config: `oauth.config.json`

Do not commit `oauth.config.json` (it contains secrets); it is listed in `.gitignore`. Use `oauth.config.example.json` as a template.

Top-level options:

| Key | Description |
|-----|-------------|
| `enabled` | If `false`, OAuth is skipped and `get_user()` returns `None` in protected routes. |
| `resolve_real_ip` | If `true`, use `X-Real-IP` (or similar) for whitelist checks when behind a proxy. |
| `whitelist` | List of client IPs that skip OAuth when `enabled` is true. |

### `server`

OAuth provider base URL and API paths:

| Key | Description |
|-----|-------------|
| `url` | Base URL of the OAuth server (e.g. `https://oauth.example.com`). |
| `connect_page` | Authorization page path (e.g. `/oauth/connect`). |
| `token_api` | Token exchange endpoint (POST). |
| `profile_api` | Profile endpoint (GET, `oauth_token` in query). |
| `profile_page` | Path on the server for “profile” (used for redirects). |
| `admin_users_api`, `admin_user_by_name_api`, `admin_groups_api` | Admin APIs (GET; optional for admin features). |
| `admin_user_page`, `admin_group_page` | URL templates for redirects (e.g. `{uid}`, `{gid}`). |

### `client`

Your app’s OAuth client and local routes:

| Key | Description |
|-----|-------------|
| `id`, `secret` | OAuth client id and secret. |
| `url` | Public URL of your app (e.g. `https://myapp.example.com`). |
| `callback_path` | Path for the OAuth callback (e.g. `/oauth-callback`). |
| `profile_path` | Path that redirects to the server’s profile page. |
| `admin_user_path`, `admin_group_path` | Paths that redirect to server admin pages (e.g. `/admin/users/<int:uid>`). |

## Decorators and API

- **`@oauth.requires_login`**  
  Ensures the user is logged in. If not, triggers redirect to the OAuth server (or returns 401 with `redirect_url` for API clients). After login, the user is available via `oauth.get_user()`.

- **`@oauth.requires_admin`**  
  Same as login, and additionally requires the user to be in a group named `admin` (see “Admin group” below). Otherwise returns 403.

- **`oauth.get_user()`**  
  Returns the current `User` (or `None` if OAuth is disabled or whitelisted). Use inside a `@requires_login` (or `@requires_admin`) route, or handle `OAuthRequired` / `OAuthError` yourself.

- **`oauth.get_uid()`**  
  Returns the current user’s id from session, or `None`.

- **`oauth.clear_user()`**  
  Removes OAuth data from the session (e.g. for logout).

- **`oauth.get_user_by_id(uid)`**, **`oauth.get_user_by_name(name)`**, **`oauth.get_users()`**, **`oauth.get_group_by_id(gid)`**, **`oauth.get_groups()`**, **`oauth.get_users_in_group(gid)`**, **`oauth.add_group(name, description=None)`**  
  Admin API helpers; they use the access token and the server’s admin APIs. Use only when the server config includes the corresponding admin endpoints.

**User** has: `id`, `name`, `email`, `nickname`, `avatar`, `groups` (list of **Group**).  
**Group** has: `id`, `name`, `description`.

## Validation mode (optional pydantic)

- `POST /api/oauth/token` payload and response are schema-validated.
- Profile/admin API payloads are schema-validated before conversion to `User`/`Group`.
- Bound route config in `oauth.init_app(...)` is schema-validated/serialized.
- API error payloads (e.g. 401 JSON with `redirect_url`) are schema-serialized.

If validation fails, the library raises `OAuthResultError` with details.

## Frontend Zod schemas

This repo also includes a small frontend library at `frontend/` that exposes `zod` schemas for the Flask-bound OAuth surface routes configured in `oauth.init_app(...)`.

- `OAuthCallbackQuerySchema` (`token`, optional `state`, optional `original_path`)
- `OAuthErrorResponseSchema` (`msg`, optional `detail`, optional `redirect_url`)
- `AdminUserRouteParamsSchema` (`uid`)
- `AdminGroupRouteParamsSchema` (`gid`)
- `OAuthRouteBindingsSchema` (route binding object mirrored from backend validation)

Example:

```ts
import {
  OAuthCallbackQuerySchema,
  OAuthErrorResponseSchema,
  parseOAuthCallbackQuery,
} from "auth-connect-frontend";

const query = parseOAuthCallbackQuery(new URLSearchParams(window.location.search));
const err = OAuthErrorResponseSchema.parse(await response.json());
```

## 401 and `redirect_url`

When a request is not logged in and the client expects JSON (e.g. API or SPA), the library returns **401** with a JSON body containing `msg`, optional `detail`, and **`redirect_url`** (the OAuth authorization URL). A frontend can redirect the browser to `redirect_url` to start the login flow.

## Admin group

Admin checks use a group whose **name** is exactly `admin` (case-sensitive). The OAuth server must return the user’s groups (e.g. in the profile or a separate call); `requires_admin` looks for a group with `name == "admin"`.

## Mock OAuth server (development)

`mock_oauth_server.py` implements a minimal OAuth 2.0–compatible server for local testing. It provides:

- **GET** `/oauth/connect` — authorization page; redirects to the client callback with a token.
- **POST** `/api/oauth/token` — exchange that token for an `access_token`.
- **GET** `/api/account/me` — profile (query param `oauth_token`).
- **GET** `/api/admin/users`, `/api/admin/users/<uid>`, `/api/admin/user-by-name/<name>`, `/api/admin/groups`, `/api/admin/groups/<gid>`, `/api/admin/groups/<gid>/users` — admin APIs (with `oauth_token`).
- **GET** `/logout` — clears mock session and redirects.

### Mock config: `oauth.mock.config.json`

Do not commit this file if it contains test secrets; it is in `.gitignore`. Use `oauth.mock.config.example.json` as a template. It defines:

- **clients** — list of `{ "id", "secret", "redirect_url" }`.
- **users** — list of `{ "id", "name", "email", "nickname", "avatar", "groups": [ { "id" } ] }`.
- **groups** — list of `{ "id", "name", "description" }`.

Give at least one user the group whose `name` is `admin` if you need admin access in the app.

### Running the mock server

From the **parent** of `auth_connect` (so that `oauth.mock.config.json` at project root is found):

```bash
python auth_connect/mock_oauth_server.py
```

By default it listens on port **8077**. Optional environment variables:

| Variable | Description |
|----------|-------------|
| `MOCK_OAUTH_PORT` | Port (default `8077`). |
| `MOCK_OAUTH_CLIENT_ID` | Client id to accept. |
| `MOCK_OAUTH_CLIENT_SECRET` | Client secret. |
| `MOCK_OAUTH_REDIRECT_URL` | Default redirect URL for the client. |

In `oauth.config.json` for your app, set `server.url` to the mock server (e.g. `http://localhost:8077`) and ensure `client.url` and `client.callback_path` match where your app is served (e.g. `http://localhost:5173` and `/oauth-callback` for a Vite dev server).

## Init options

```python
oauth.init_app(app, config_file="oauth.config.json", login_callback=my_callback)
```

- **config_file** — path to the JSON config (server + client).
- **login_callback** — optional callable `(user) -> None` or return value; if it returns a non-`None` value, that value is returned instead of calling the wrapped view (e.g. to redirect or return a custom response after login).

## File layout

```
auth_connect/
├── __init__.py
├── README.md
├── oauth.py                      # Backward-compatible public facade
├── frontend/                     # Frontend Zod schema package
│   ├── package.json
│   └── src/
│       └── index.ts
├── core/                         # Internal implementation modules
│   ├── constants.py
│   ├── exceptions.py
│   ├── models.py
│   ├── schemas.py
│   ├── validation.py
│   ├── config.py
│   ├── parsers.py
│   ├── client.py
│   └── flask_integration.py
├── mock_oauth_server.py          # Dev mock OAuth server
├── oauth.config.example.json     # Example client config (safe to commit)
├── oauth.mock.config.example.json # Example mock data (safe to commit)
├── requirements.txt
└── .gitignore                    # oauth.config.json, oauth.mock.config.json
```

## Backward compatibility

- Existing imports like `from auth_connect import oauth` continue to work.
- Existing public APIs (`init_app`, decorators, user/group/admin helpers, exceptions) are preserved.
- Refactor changes internal structure only; behavior stays compatible with prior versions unless stricter optional validation is enabled via `pydantic`.
