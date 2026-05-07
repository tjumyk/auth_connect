"""Domain exceptions used by the OAuth client library."""


class OAuthError(Exception):
    """Base class for all OAuth integration errors."""

    def __init__(self, msg, detail=None):
        self.msg = msg
        self.detail = detail
        super().__init__(msg)


class OAuthRequired(OAuthError):
    """Raised when an authenticated session is required but missing."""

    def __init__(self):
        super().__init__("authentication required")


class OAuthRequestError(OAuthError):
    """Raised when the remote OAuth server rejects a request (4xx)."""


class OAuthAPIError(OAuthError):
    """Raised when the OAuth server fails or cannot be reached."""


class OAuthResultError(OAuthError):
    """Raised when an OAuth response payload is malformed."""
