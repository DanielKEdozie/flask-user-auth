"""Authentication and authorization route decorators supporting session, token, or dual auth."""
from functools import wraps
from typing import Any, Callable, Optional
from flask import current_app, g, jsonify, request
from werkzeug.local import LocalProxy

from .tokens import TokenError, decode_token, verify_token_not_revoked


def _authenticate_token() -> Any:
    """Validate Bearer JWT from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:].strip()
    if not token:
        return None

    ext = current_app.extensions.get("flask_user_auth")
    if not ext:
        return None

    try:
        payload = decode_token(token, ext.jwt_secret, expected_type="access")
    except TokenError:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    user = ext.get_user(int(user_id))
    if not user:
        return None

    try:
        verify_token_not_revoked(payload, user)
    except TokenError:
        return None

    g.current_user = user
    return user


def _authenticate_session() -> Any:
    """Validate active Flask-Login session cookie."""
    try:
        from flask_login import current_user as fl_user
        if fl_user and getattr(fl_user, "is_authenticated", False):
            g.current_user = fl_user
            return fl_user
    except ImportError:
        pass
    return None


def _authenticate_request(auth_type: str = "both") -> Any:
    """Attempt authentication according to specified auth_type ('token', 'session', 'both')."""
    ext = current_app.extensions.get("flask_user_auth")
    effective_type = auth_type or (getattr(ext, "default_auth_type", "both") if ext else "both")

    if effective_type == "token":
        return _authenticate_token()
    elif effective_type == "session":
        return _authenticate_session()
    else:  # "both" (if Bearer header is sent, evaluate token only; otherwise session)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return _authenticate_token()
        return _authenticate_session()


def _get_current_user() -> Any:
    """Retrieve current authenticated user."""
    if hasattr(g, "current_user") and g.current_user is not None:
        return g.current_user
    return _authenticate_request("both")


current_user: Any = LocalProxy(_get_current_user)


def _build_login_required(fn: Callable, auth_type: str = "both") -> Callable:
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        user = _authenticate_request(auth_type)
        if not user:
            mode_desc = {
                "token": "Valid Bearer token required in Authorization header.",
                "session": "Active user session cookie required.",
                "both": "Valid Bearer token or session cookie required.",
            }.get(auth_type, "Authentication required.")
            return (
                jsonify({
                    "error": "Unauthorized",
                    "message": f"Authentication required. {mode_desc}",
                }),
                401,
            )
        return fn(*args, **kwargs)

    return decorated_function


def login_required(
    f: Optional[Callable] = None,
    *,
    auth_type: str = "both",
) -> Callable:
    """Protect route requiring authenticated user.

    Can be used with or without parameters:
    - ``@login_required`` (defaults to 'both' or FUA_DEFAULT_AUTH_TYPE)
    - ``@login_required(auth_type='session')``
    - ``@login_required(auth_type='token')``
    """
    if f is not None and callable(f):
        return _build_login_required(f, auth_type="both")

    def decorator(fn: Callable) -> Callable:
        return _build_login_required(fn, auth_type=auth_type)

    return decorator


def token_required(f: Optional[Callable] = None) -> Callable:
    """Strictly require Authorization: Bearer <token>."""
    if f is not None and callable(f):
        return _build_login_required(f, auth_type="token")

    def decorator(fn: Callable) -> Callable:
        return _build_login_required(fn, auth_type="token")

    return decorator


def session_required(f: Optional[Callable] = None) -> Callable:
    """Strictly require active Flask-Login session cookie."""
    if f is not None and callable(f):
        return _build_login_required(f, auth_type="session")

    def decorator(fn: Callable) -> Callable:
        return _build_login_required(fn, auth_type="session")

    return decorator


def roles_required(*allowed_roles: str, auth_type: str = "both") -> Callable:
    """Protect route requiring specific role(s) or admin status."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = _authenticate_request(auth_type)
            if not user:
                return (
                    jsonify({"error": "Unauthorized", "message": "Authentication required."}),
                    401,
                )

            # Admins automatically bypass role restrictions:
            if getattr(user, "is_admin", False):
                return f(*args, **kwargs)

            user_role = getattr(user, "role", None)
            if user_role not in allowed_roles:
                return (
                    jsonify({
                        "error": "Forbidden",
                        "message": f"Requires one of roles: {', '.join(allowed_roles)}",
                    }),
                    403,
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f: Optional[Callable] = None, *, auth_type: str = "both") -> Callable:
    """Protect route requiring user.is_admin is True."""
    if f is not None and callable(f):
        return roles_required("admin", auth_type="both")(f)

    def decorator(fn: Callable) -> Callable:
        return roles_required("admin", auth_type=auth_type)(fn)

    return decorator