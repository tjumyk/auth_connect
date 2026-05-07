"""Validation and serialization helpers with optional Pydantic support."""

from __future__ import annotations

from typing import Any

from .exceptions import OAuthResultError
from .schemas import (
    HAS_PYDANTIC,
    AddGroupRequestPayload,
    AdminUsersPayload,
    ErrorPayload,
    OAuthConfigPayload,
    RedirectRoutesPayload,
    TokenExchangeRequest,
    TokenExchangeResponse,
    UserPayload,
)


def is_pydantic_enabled() -> bool:
    """Return True when optional Pydantic dependency is available."""
    return HAS_PYDANTIC


def _model_validate(schema, payload: Any):
    if not HAS_PYDANTIC:
        return payload
    try:
        return schema.model_validate(payload)
    except Exception as exc:
        raise OAuthResultError("invalid data format", detail=str(exc)) from exc


def validate_oauth_config(config: dict[str, Any]) -> dict[str, Any]:
    """Validate OAuth config payload when Pydantic is available."""
    if not HAS_PYDANTIC:
        return config
    model = _model_validate(OAuthConfigPayload, config)
    return model.model_dump(exclude_none=False)


def validate_token_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate token exchange request payload."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(TokenExchangeRequest, payload)
    return model.model_dump(exclude_none=False)


def validate_token_response(payload: Any) -> dict[str, Any]:
    """Validate token exchange response payload."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(TokenExchangeResponse, payload)
    return model.model_dump(exclude_none=False)


def validate_user_payload(payload: Any) -> dict[str, Any]:
    """Validate a user payload from OAuth/account/admin APIs."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(UserPayload, payload)
    return model.model_dump(exclude_none=False)


def validate_admin_users_payload(payload: Any) -> dict[str, Any]:
    """Validate aggregate users response from admin users API."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(AdminUsersPayload, payload)
    return model.model_dump(exclude_none=False)


def validate_add_group_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate outbound group create payload."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(AddGroupRequestPayload, payload)
    return model.model_dump(exclude_none=False)


def serialize_error_payload(msg: str, detail: Any = None, redirect_url: str | None = None) -> dict[str, Any]:
    """Serialize API error payload for app-bound JSON responses."""
    payload = {"msg": msg, "detail": detail}
    if redirect_url is not None:
        payload["redirect_url"] = redirect_url
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(ErrorPayload, payload)
    return model.model_dump(exclude_none=True)


def serialize_route_bindings(payload: dict[str, Any]) -> dict[str, Any]:
    """Serialize and validate route binding config used by `init_app`."""
    if not HAS_PYDANTIC:
        return payload
    model = _model_validate(RedirectRoutesPayload, payload)
    return model.model_dump(exclude_none=False)
