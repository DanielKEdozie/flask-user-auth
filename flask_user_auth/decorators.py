from functools import wraps

from flask import current_app, g, jsonify
from flask_login import current_user as flask_login_current_user
from werkzeug.local import LocalProxy


def get_auth_extension(app=None):
    """Retrieve the initialized ``Auth`` extension from ``current_app``."""
    app = app or current_app
    ext = getattr(app, 'extensions', {}).get('flask_user_auth')
    if ext is None:
        raise RuntimeError(
            'flask_user_auth is not initialized on the current Flask application. '
            'Call auth.init_app(app, model=User) first.'
        )
    return ext


def _resolve_current_user():
    """Resolve the active user from ``g``, ``flask-httpauth``, or ``flask-login``."""
    if hasattr(g, 'current_user') and g.current_user is not None:
        return g.current_user

    ext = getattr(current_app, 'extensions', {}).get('flask_user_auth')
    if ext is not None and ext.use_token and ext.http_auth is not None:
        token_user = ext.http_auth.current_user()
        if token_user is not None:
            return token_user

    if ext is None or ext.use_session:
        try:
            if getattr(flask_login_current_user, 'is_authenticated', False):
                return flask_login_current_user._get_current_object()
        except Exception:
            pass

    return None


#: Proxy resolving to the authenticated user (session or token), or ``None``.
current_user = LocalProxy(_resolve_current_user)

_AUTH_MODE_KEYWORDS = {'session', 'token', 'jwt', 'both', 'all'}


def _normalize_auth_modes(args, session, token, ext=None):
    """Resolve ``(allow_session, allow_token)`` from decorator arguments."""
    mode_strings = set()
    for arg in args:
        if isinstance(arg, str) and arg.lower().strip() in _AUTH_MODE_KEYWORDS:
            mode_strings.add(arg.lower().strip())
        elif isinstance(arg, (list, tuple, set)):
            for item in arg:
                if isinstance(item, str) and item.lower().strip() in _AUTH_MODE_KEYWORDS:
                    mode_strings.add(item.lower().strip())

    if mode_strings:
        if 'both' in mode_strings or 'all' in mode_strings:
            return True, True
        allow_session = 'session' in mode_strings
        allow_token = 'token' in mode_strings or 'jwt' in mode_strings
        if session is not None:
            allow_session = bool(session)
        if token is not None:
            allow_token = bool(token)
        return allow_session, allow_token

    if session is None and token is None:
        if ext is not None:
            return bool(ext.use_session), bool(ext.use_token)
        return True, True

    if session is not None and token is None:
        allow_session = bool(session)
        allow_token = not allow_session
        return allow_session, allow_token

    if token is not None and session is None:
        allow_token = bool(token)
        allow_session = not allow_token
        return allow_session, allow_token

    return bool(session), bool(token)


def auth_required(*args, session=None, token=None, admin=False,
                  redirect=None, auth_ext=None):
    """Protect an endpoint using session (Flask-Login), token (Flask-HTTPAuth), or both.

    Examples::

        @auth_required
        def api_profile(): ...

        @auth_required(redirect='/login')
        def dashboard(): ...

        @auth_required(redirect='admin.login')
        def admin_panel(): ...

    When ``redirect`` is provided (a URL path like ``'/login'``, a Flask endpoint name
    like ``'admin.login'``, or a callable like ``lambda: url_for('admin.login')``),
    unauthenticated requests are redirected to that URL with ``?next=<current_path>``.
    When ``redirect`` is omitted, a JSON 401 response is returned.
    """
    direct_fn = None
    if (
        len(args) == 1
        and callable(args[0])
        and session is None
        and token is None
        and not admin
        and redirect is None
    ):
        direct_fn = args[0]
        args = ()

    def decorator(fn):
        @wraps(fn)
        def wrapper(*fn_args, **fn_kwargs):
            ext = auth_ext or get_auth_extension()
            allow_session, allow_token = _normalize_auth_modes(
                args, session, token, ext=ext
            )

            user = None
            auth_via = None
            token_error_message = None

            # 1. Try token authentication via flask-httpauth if allowed & enabled
            if allow_token and ext.use_token:
                raw_token = ext.jwt.extract_bearer_token()
                if raw_token:
                    verified_user = ext._verify_token_with_http_auth(raw_token)
                    if verified_user is not None:
                        user = verified_user
                        auth_via = 'token'
                    else:
                        token_error_message = getattr(
                            g, '_auth_token_error', 'Invalid or expired token'
                        )

            # 2. Try session authentication via flask-login if allowed & enabled
            if user is None and allow_session and ext.use_session:
                if getattr(flask_login_current_user, 'is_authenticated', False):
                    candidate = flask_login_current_user._get_current_object()
                    if getattr(candidate, 'is_active', True):
                        user = candidate
                        auth_via = 'session'
                    else:
                        return jsonify({'message': 'Account is inactive'}), 403

            if user is None:
                if allow_token and not allow_session:
                    msg = token_error_message or 'Invalid or missing authentication token'
                elif allow_session and not allow_token:
                    msg = 'Session authentication required'
                else:
                    msg = token_error_message or 'Authentication required'
                return ext.unauthorized_response(msg, 401, redirect=redirect)

            if not getattr(user, 'is_active', True):
                return jsonify({'message': 'Account is inactive'}), 403

            if admin and not getattr(user, 'is_admin', False):
                return jsonify({'message': 'Admin privileges required'}), 403

            g.current_user = user
            g.auth_method = auth_via
            return fn(*fn_args, **fn_kwargs)

        return wrapper

    if direct_fn is not None:
        return decorator(direct_fn)
    return decorator


def login_required(*args, admin=False, redirect=None, auth_ext=None):
    """Require Flask-Login session authentication.

    Examples::

        @login_required
        def api_session_only(): ...

        @login_required(redirect='/login')
        def account_page(): ...

        @login_required('/login')
        def orders_page(): ...
    """
    if (
        len(args) == 1
        and callable(args[0])
        and not admin
        and redirect is None
    ):
        return auth_required(
            session=True,
            token=False,
            auth_ext=auth_ext,
        )(args[0])

    if len(args) == 1 and isinstance(args[0], str) and redirect is None:
        redirect = args[0]

    return auth_required(
        session=True,
        token=False,
        admin=admin,
        redirect=redirect,
        auth_ext=auth_ext,
    )


def token_required(*args, admin=False, redirect=None, auth_ext=None):
    """Require Flask-HTTPAuth Bearer JWT authentication.

    Can be used as ``@token_required`` or ``@token_required(admin=True, redirect='/login')``.
    """
    if (
        len(args) == 1
        and callable(args[0])
        and not admin
        and redirect is None
    ):
        return auth_required(
            session=False,
            token=True,
            auth_ext=auth_ext,
        )(args[0])

    if len(args) == 1 and isinstance(args[0], str) and redirect is None:
        redirect = args[0]

    return auth_required(
        session=False,
        token=True,
        admin=admin,
        redirect=redirect,
        auth_ext=auth_ext,
    )


def admin_required(*args, session=None, token=None, redirect=None, auth_ext=None):
    """Require an authenticated admin user (via session, token, or both)."""
    if (
        len(args) == 1
        and callable(args[0])
        and session is None
        and token is None
        and redirect is None
    ):
        return auth_required(admin=True, auth_ext=auth_ext)(args[0])

    return auth_required(
        *args,
        session=session,
        token=token,
        admin=True,
        redirect=redirect,
        auth_ext=auth_ext,
    )
