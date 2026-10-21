from datetime import datetime, timedelta, timezone
import re
import uuid

from flask import current_app, request
import jwt


_DURATION_RE = re.compile(r'^\s*(\d+)\s*([smhdw]?)\s*$', re.IGNORECASE)
_UNIT_SECONDS = {
    '': 1,
    's': 1,
    'm': 60,
    'h': 3600,
    'd': 86400,
    'w': 604800,
}


def parse_expires(value, default_seconds):
    """Coerce an expiration config value into a ``timedelta``.

    Accepts ``timedelta``, ``int``/``float`` seconds, or a compact string
    such as ``'15m'``, ``'1h'``, ``'7d'``.
    """
    if value is None:
        return timedelta(seconds=default_seconds)
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    if isinstance(value, str):
        match = _DURATION_RE.match(value)
        if match:
            amount = int(match.group(1))
            unit = match.group(2).lower()
            return timedelta(seconds=amount * _UNIT_SECONDS[unit])
    raise ValueError(f'Invalid JWT expiration value: {value!r}')


class TokenError(Exception):
    """Raised when a JWT is missing, invalid, expired, or of the wrong type."""

    def __init__(self, message, status_code=401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class JWTManager:
    """Helper responsible for encoding, decoding, and cookie handling of JWTs."""

    DEFAULT_ACCESS_SECONDS = 900          # 15 minutes
    DEFAULT_REFRESH_SECONDS = 2592000     # 30 days

    def __init__(self, auth):
        self.auth = auth
        self._revoked_jtis = set()

    def _secret_key(self, app=None):
        app = app or current_app
        secret = (
            app.config.get('JWT_SECRET_KEY')
            or app.config.get('SECRET_KEY')
        )
        if not secret:
            raise RuntimeError(
                'JWT_SECRET_KEY (or SECRET_KEY) must be configured on the Flask app'
            )
        return secret

    def _algorithm(self, app=None):
        app = app or current_app
        return app.config.get('JWT_ALGORITHM', 'HS256')

    def access_expires_delta(self, app=None):
        app = app or current_app
        return parse_expires(
            app.config.get('JWT_ACCESS_EXPIRES'),
            self.DEFAULT_ACCESS_SECONDS,
        )

    def refresh_expires_delta(self, app=None):
        app = app or current_app
        return parse_expires(
            app.config.get('JWT_REFRESH_EXPIRES'),
            self.DEFAULT_REFRESH_SECONDS,
        )

    def cookie_name(self, app=None):
        app = app or current_app
        return app.config.get('JWT_COOKIE_NAME', 'refresh_token')

    def create_token(self, identity, token_type='access', expires_delta=None,
                     additional_claims=None, app=None):
        """Encode a signed JWT for ``identity``."""
        app = app or current_app
        now = datetime.now(timezone.utc)
        if expires_delta is None:
            expires_delta = (
                self.access_expires_delta(app)
                if token_type == 'access'
                else self.refresh_expires_delta(app)
            )
        payload = {
            'sub': str(identity),
            'type': token_type,
            'iat': now,
            'exp': now + expires_delta,
            'jti': uuid.uuid4().hex,
        }
        issuer = app.config.get('JWT_ISSUER')
        audience = app.config.get('JWT_AUDIENCE')
        if issuer:
            payload['iss'] = issuer
        if audience:
            payload['aud'] = audience
        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(
            payload,
            self._secret_key(app),
            algorithm=self._algorithm(app),
        )

    def create_access_token(self, identity, expires_delta=None,
                            additional_claims=None, app=None):
        return self.create_token(
            identity,
            token_type='access',
            expires_delta=expires_delta,
            additional_claims=additional_claims,
            app=app,
        )

    def create_refresh_token(self, identity, expires_delta=None,
                             additional_claims=None, app=None):
        return self.create_token(
            identity,
            token_type='refresh',
            expires_delta=expires_delta,
            additional_claims=additional_claims,
            app=app,
        )

    def decode_token(self, raw_token, expected_type=None, app=None):
        """Decode and validate ``raw_token``, optionally checking ``type``."""
        app = app or current_app
        if not raw_token:
            raise TokenError('Token is missing')
        decode_kwargs = {
            'key': self._secret_key(app),
            'algorithms': [self._algorithm(app)],
        }
        issuer = app.config.get('JWT_ISSUER')
        audience = app.config.get('JWT_AUDIENCE')
        if issuer:
            decode_kwargs['issuer'] = issuer
        if audience:
            decode_kwargs['audience'] = audience

        try:
            payload = jwt.decode(raw_token, **decode_kwargs)
        except jwt.ExpiredSignatureError as exc:
            raise TokenError('Token has expired') from exc
        except jwt.InvalidTokenError as exc:
            raise TokenError('Invalid token') from exc

        token_type = payload.get('type')
        if expected_type and token_type != expected_type:
            raise TokenError(f'Expected {expected_type} token')

        if self.is_token_revoked(payload):
            raise TokenError('Token has been revoked')

        return payload

    def revoke_payload(self, payload):
        """Record a token's ``jti`` in the in-memory blocklist (or custom hook)."""
        if not payload:
            return
        jti = payload.get('jti')
        if jti:
            self._revoked_jtis.add(jti)

    def is_token_revoked(self, payload):
        jti = payload.get('jti')
        if jti and jti in self._revoked_jtis:
            return True
        if self.auth._token_blocklist_loader is not None:
            return bool(self.auth._token_blocklist_loader(payload))
        return False

    def set_refresh_cookie(self, response, refresh_token, app=None):
        """Attach the refresh token cookie to ``response``."""
        app = app or current_app
        if not app.config.get('JWT_COOKIE_ENABLED', True):
            return response
        cookie_name = self.cookie_name(app)
        if not cookie_name:
            return response
        max_age = int(self.refresh_expires_delta(app).total_seconds())
        response.set_cookie(
            cookie_name,
            value=refresh_token,
            max_age=max_age,
            httponly=app.config.get('JWT_COOKIE_HTTPONLY', True),
            secure=app.config.get('JWT_COOKIE_SECURE', False),
            samesite=app.config.get('JWT_COOKIE_SAMESITE', 'Lax'),
            path=app.config.get('JWT_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN', None),
        )
        return response

    def clear_refresh_cookie(self, response, app=None):
        """Clear the refresh token cookie on ``response``."""
        app = app or current_app
        cookie_name = self.cookie_name(app)
        if not cookie_name:
            return response
        response.delete_cookie(
            cookie_name,
            path=app.config.get('JWT_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN', None),
            samesite=app.config.get('JWT_COOKIE_SAMESITE', 'Lax'),
            secure=app.config.get('JWT_COOKIE_SECURE', False),
            httponly=app.config.get('JWT_COOKIE_HTTPONLY', True),
        )
        return response

    def extract_refresh_token(self, data=None, app=None):
        """Extract a refresh token from cookie, JSON body, or Bearer header."""
        app = app or current_app
        cookie_name = self.cookie_name(app)
        if cookie_name and cookie_name in request.cookies:
            cookie_val = request.cookies.get(cookie_name)
            if cookie_val:
                return cookie_val

        if data is None and request.is_json:
            data = request.get_json(silent=True) or {}
        if isinstance(data, dict) and data.get('refresh_token'):
            return data['refresh_token']

        auth_header = request.headers.get(
            app.config.get('JWT_HEADER_NAME', 'Authorization'), ''
        )
        header_type = app.config.get('JWT_HEADER_TYPE', 'Bearer')
        prefix = f'{header_type} '
        if auth_header.startswith(prefix):
            return auth_header[len(prefix):].strip()
        return None

    def extract_bearer_token(self, app=None):
        """Extract a Bearer token from the Authorization header."""
        app = app or current_app
        auth_header = request.headers.get(
            app.config.get('JWT_HEADER_NAME', 'Authorization'), ''
        )
        header_type = app.config.get('JWT_HEADER_TYPE', 'Bearer')
        prefix = f'{header_type} '
        if auth_header.startswith(prefix):
            return auth_header[len(prefix):].strip()
        return None
