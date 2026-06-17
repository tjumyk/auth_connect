"""Optional Pydantic v2 schemas for OAuth request/response validation."""

from __future__ import annotations

from typing import Any

try:
    from pydantic import BaseModel, ConfigDict, Field  # type: ignore[reportMissingImports]

    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover - exercised when optional dependency missing
    BaseModel = object  # type: ignore[assignment,misc]
    ConfigDict = None  # type: ignore[assignment]
    Field = None  # type: ignore[assignment]
    HAS_PYDANTIC = False


if HAS_PYDANTIC:
    class TokenExchangeRequest(BaseModel):
        """Outbound payload sent to token exchange endpoint."""

        model_config = ConfigDict(extra="ignore")

        client_id: int
        client_secret: str
        redirect_url: str
        token: str


    class TokenExchangeResponse(BaseModel):
        """Inbound payload returned by token exchange endpoint."""

        model_config = ConfigDict(extra="ignore")

        access_token: str


    class GroupPayload(BaseModel):
        """Normalized group payload from OAuth server APIs."""

        model_config = ConfigDict(extra="ignore")

        id: int
        name: str
        description: str | None = None


    class UserPayload(BaseModel):
        """Normalized user payload from OAuth server APIs."""

        model_config = ConfigDict(extra="ignore")

        id: int
        name: str
        email: str
        nickname: str | None = None
        avatar: str | None = None
        mobile: str | None = None
        real_name: str | None = None
        groups: list[GroupPayload] = Field(default_factory=list)
        group_ids: list[int] = Field(default_factory=list)


    class AdminUsersPayload(BaseModel):
        """Payload returned by `/api/admin/users`."""

        model_config = ConfigDict(extra="ignore")

        users: list[UserPayload]
        groups: list[GroupPayload]


    class AddGroupRequestPayload(BaseModel):
        """Outbound payload for creating a group."""

        model_config = ConfigDict(extra="ignore")

        name: str
        description: str | None = None


    class ErrorPayload(BaseModel):
        """Structured error payload returned to API clients."""

        model_config = ConfigDict(extra="ignore")

        msg: str
        detail: Any | None = None
        redirect_url: str | None = None


    class RedirectRoutesPayload(BaseModel):
        """Route templates and pages bound by `init_app`."""

        model_config = ConfigDict(extra="ignore")

        callback_path: str
        profile_path: str
        admin_user_path: str
        admin_group_path: str
        profile_page: str
        admin_user_page: str
        admin_group_page: str


    class OAuthClientConfigPayload(BaseModel):
        """Client-side OAuth config section."""

        model_config = ConfigDict(extra="ignore")

        id: int
        secret: str
        url: str
        callback_path: str
        profile_path: str
        admin_user_path: str
        admin_group_path: str


    class OAuthServerConfigPayload(BaseModel):
        """Server-side OAuth config section."""

        model_config = ConfigDict(extra="ignore")

        url: str
        public_url: str | None = None
        internal_url: str | None = None
        connect_page: str
        token_api: str
        profile_api: str
        admin_users_api: str
        admin_user_by_name_api: str
        admin_groups_api: str
        profile_page: str
        admin_user_page: str
        admin_group_page: str
        logout_page: str | None = None


    class OAuthConfigPayload(BaseModel):
        """Top-level oauth config payload loaded from JSON."""

        model_config = ConfigDict(extra="ignore")

        enabled: bool = True
        whitelist: list[str] | None = None
        resolve_real_ip: bool = False
        server: OAuthServerConfigPayload
        client: OAuthClientConfigPayload

else:
    TokenExchangeRequest = None
    TokenExchangeResponse = None
    GroupPayload = None
    UserPayload = None
    AdminUsersPayload = None
    AddGroupRequestPayload = None
    ErrorPayload = None
    RedirectRoutesPayload = None
    OAuthClientConfigPayload = None
    OAuthServerConfigPayload = None
    OAuthConfigPayload = None

