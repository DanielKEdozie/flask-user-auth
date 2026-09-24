"""flask-user-auth — Dual token & session authentication, User/UserAuth mixins, and Click CLI."""
from .extension import FlaskUserAuth
from .models import UserAuthMixin, UserMixin
from .decorators import (
    admin_required,
    current_user,
    login_required,
    roles_required,
    session_required,
    token_required,
)
from .tokens import (
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    create_token,
    decode_token,
)

__all__ = [
    "FlaskUserAuth",
    "UserMixin",
    "UserAuthMixin",
    "current_user",
    "login_required",
    "token_required",
    "session_required",
    "roles_required",
    "admin_required",
    "TokenError",
    "TokenExpiredError",
    "TokenRevokedError",
    "TokenInvalidError",
    "create_token",
    "decode_token",
]

__version__ = "1.1.0"