"""Authentication and authorization route decorators."""
from functools import wraps
from typing import Any, Callable
from flask import current_app, g, jsonify, request
from werkzeug.local import LocalProxy

from .tokens import TokenError, decode_token, verify_token_not_revoked


def _authenticate_request() -> Any:
    """Attempt to authenticate via Bearer token or session cookie."""
    # 1. Bearer Token in Authorization header takes precedence:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if not token:
            return None

        ext = current_app.extensions.get("flask_user_auth")
        if not ext:
            return None

        secret_key = ext.jwt_secret
        try:
            payload = decode_token(token, secret_key, expected_type="access")
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

    # 2. Flask-Login session authentication if no Bearer header was sent:
    try:
        from flask_login import current_user as fl_user
        if fl_user and getattr(fl_user, "is_authenticated", False):
            g.current_user = fl_user
            return fl_user
    except ImportError:
        pass

    return None


def _get_current_user() -> Any:
    """Retrieve current authenticated user."""
    if hasattr(g, "current_user") and g.current_user is not None:
        return g.current_user
    return _authenticate_request()


current_user: Any = LocalProxy(_get_current_user)


def login_required(f: Callable) -> Callable:
    """Protect route requiring either active session or valid Bearer JWT."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _authenticate_request()
        if not user:
            return (
                jsonify({
                    "error": "Unauthorized",
                    "message": "Authentication required. Please provide a valid Bearer token or session.",
                }),
                401,
            )
        return f(*args, **kwargs)

    return decorated_function


def roles_required(*allowed_roles: str) -> Callable:
    """Protect route requiring specific role(s) or admin status."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = _authenticate_request()
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


def admin_required(f: Callable) -> Callable:
    """Protect route requiring user.is_admin is True."""
    return roles_required("admin")(f)