"""JWT Token utilities and HTTP-only cookie management."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from flask import Request, Response


class TokenError(Exception):
    """Base token exception."""
    pass


class TokenExpiredError(TokenError):
    """Raised when token is expired."""
    pass


class TokenRevokedError(TokenError):
    """Raised when token was issued before the user's last password reset."""
    pass


class TokenInvalidError(TokenError):
    """Raised when token signature or payload is invalid."""
    pass


def create_token(
    user_id: int,
    secret_key: str,
    token_type: str = "access",
    expires_in: int = 3600,
    extra_claims: Optional[Dict[str, Any]] = None,
    algorithm: str = "HS256",
) -> str:
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_token(
    token: str,
    secret_key: str,
    expected_type: Optional[str] = None,
    algorithms: Optional[list] = None,
) -> Dict[str, Any]:
    """Decode and validate a JWT token signature and expiration."""
    if algorithms is None:
        algorithms = ["HS256"]
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithms)
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Token has expired")
    except jwt.PyJWTError as e:
        raise TokenInvalidError(f"Invalid token: {e}")

    if expected_type and payload.get("type") != expected_type:
        raise TokenInvalidError(
            f"Expected token type '{expected_type}', got '{payload.get('type')}'"
        )
    return payload


def verify_token_not_revoked(payload: Dict[str, Any], user: Any) -> None:
    """Ensure token was issued at or after user's last_reset_date."""
    if not getattr(user, "is_active", True):
        raise TokenRevokedError("User account is inactive")

    auth = getattr(user, "auth", None)
    if not auth:
        return

    last_reset = getattr(auth, "last_reset_date", None)
    if not last_reset:
        return

    iat = payload.get("iat")
    if iat is None:
        raise TokenInvalidError("Missing 'iat' claim in token")

    if last_reset.tzinfo is None:
        reset_timestamp = int(last_reset.replace(tzinfo=timezone.utc).timestamp())
    else:
        reset_timestamp = int(last_reset.timestamp())

    # If token was issued before last_reset, revoke it:
    if iat < reset_timestamp:
        raise TokenRevokedError(
            "Token has been revoked by a password reset or security update"
        )


def set_refresh_cookie(
    response: Response,
    refresh_token: str,
    cookie_name: str = "refresh_token",
    max_age: int = 86400 * 30,
    path: str = "/",
    secure: bool = False,
    httponly: bool = True,
    samesite: str = "Lax",
) -> Response:
    """Attach HTTP-only refresh token cookie to response."""
    response.set_cookie(
        key=cookie_name,
        value=refresh_token,
        max_age=max_age,
        path=path,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
    )
    return response


def clear_refresh_cookie(
    response: Response,
    cookie_name: str = "refresh_token",
    path: str = "/",
) -> Response:
    """Clear HTTP-only refresh token cookie."""
    response.delete_cookie(key=cookie_name, path=path)
    return response


def extract_refresh_token(
    request: Request,
    cookie_name: str = "refresh_token",
) -> Optional[str]:
    """Extract refresh token from HTTP cookie or JSON payload."""
    token = request.cookies.get(cookie_name)
    if token:
        return token
    if request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get("refresh_token")
    return request.headers.get("X-Refresh-Token") or request.form.get("refresh_token")