from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from flask import Blueprint, current_app, g, jsonify, redirect, request, url_for
from flask_httpauth import HTTPTokenAuth
from flask_login import LoginManager
import sqlalchemy as sa
from werkzeug.routing import BuildError
from werkzeug.security import generate_password_hash

from .cli import create_auth_cli
from .decorators import (
    admin_required as _admin_required,
    auth_required as _auth_required,
    current_user,
    login_required as _login_required,
    token_required as _token_required,
)
from .routes import create_auth_blueprint
from .tokens import JWTManager, TokenError


def _normalize_enable_redirect(value) -> set[str]:
    """Normalize ``enable_redirect`` into a set containing ``'session'`` and/or ``'token'``."""
    if not value:
        return set()
    if value is True:
        return {'session', 'token'}
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return set()

    modes: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        cleaned = item.strip().lower()
        if cleaned in ('both', 'all', '*'):
            modes.update({'session', 'token'})
        elif cleaned == 'session':
            modes.add('session')
        elif cleaned in ('token', 'jwt'):
            modes.add('token')
    return modes


def _normalize_bp_login_views(bp_login_views: dict | None) -> dict[str, str]:
    """Normalize ``{Blueprint | str: url_or_endpoint}`` keys to blueprint name strings."""
    if not bp_login_views or not isinstance(bp_login_views, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, target in bp_login_views.items():
        if not target:
            continue
        bp_name = key.name if isinstance(key, Blueprint) else str(key).strip()
        if bp_name:
            normalized[bp_name] = target
    return normalized


class Auth:
    """Flask authentication extension combining Flask-Login (session) and
    Flask-HTTPAuth + PyJWT (Bearer & cookie tokens) using SQLAlchemy 2.0+.

    Usage::

        from flask_user_auth import Auth

        auth = Auth()
        auth.init_app(
            app,
            model=User,
            use_session=True,
            use_token=True,
            login_view='/login',
            bp_login_views={'admin': '/admin/login', 'store': '/login'},
            enable_redirect=('session',),
        )
    """

    DEFAULT_CONFIG = {
        'JWT_ALGORITHM': 'HS256',
        'JWT_ACCESS_EXPIRES': 900,          # 15 minutes
        'JWT_REFRESH_EXPIRES': 2592000,     # 30 days
        'JWT_COOKIE_NAME': 'refresh_token',
        'JWT_COOKIE_ENABLED': True,
        'JWT_COOKIE_HTTPONLY': True,
        'JWT_COOKIE_SECURE': False,
        'JWT_COOKIE_SAMESITE': 'Lax',
        'JWT_COOKIE_PATH': '/',
        'JWT_COOKIE_DOMAIN': None,
        'JWT_HEADER_NAME': 'Authorization',
        'JWT_HEADER_TYPE': 'Bearer',
        'JWT_ROTATE_REFRESH_TOKENS': False,
        'AUTH_URL_PREFIX': '/auth',
        'AUTH_IDENTITY_FIELD': 'email',
        'AUTH_PK_FIELD': 'id',
        'AUTH_REQUIRE_MECHANISM_CHOICE': False,
        'AUTH_CLI_GROUPS': ('user', 'auth'),
        'AUTH_LOGIN_VIEW': None,
        'AUTH_BP_LOGIN_VIEWS': None,
        'AUTH_ENABLE_REDIRECT': ('session',),
        'AUTH_REDIRECT_NEXT_PARAM': 'next',
    }

    def __init__(self, app=None, model=None, use_session=True, use_token=True,
                 schema=None, serializer=None, url_prefix=None, db=None,
                 cli_group=None, login_view=None, bp_login_views=None,
                 enable_redirect=None):
        self.app = app
        self.model = model
        self.use_session = bool(use_session)
        self.use_token = bool(use_token)
        self.schema = schema
        self.serializer = serializer
        self.url_prefix = url_prefix
        self.db = db
        self.cli_group = cli_group
        self.login_view = login_view
        self.bp_login_views = _normalize_bp_login_views(bp_login_views)
        self.enable_redirect = (
            _normalize_enable_redirect(enable_redirect)
            if enable_redirect is not None
            else None
        )

        self.login_manager = None
        self.http_auth = None
        self.jwt = JWTManager(self)
        self.blueprint = None
        self.cli = None

        self._user_loader_callback = None
        self._authenticate_callback = None
        self._token_blocklist_loader = None

        if app is not None:
            self.init_app(
                app,
                model=model,
                use_session=use_session,
                use_token=use_token,
                schema=schema,
                serializer=serializer,
                url_prefix=url_prefix,
                db=db,
                cli_group=cli_group,
                login_view=login_view,
                bp_login_views=bp_login_views,
                enable_redirect=enable_redirect,
            )

    def init_app(self, app, model=None, use_session=None, use_token=None,
                 schema=None, serializer=None, url_prefix=None, db=None,
                 register_blueprint=True, register_cli=True, cli_group=None,
                 login_view=None, bp_login_views=None, enable_redirect=None):
        """Initialize the extension with a Flask application."""
        if model is not None:
            self.model = model
        if use_session is not None:
            self.use_session = bool(use_session)
        if use_token is not None:
            self.use_token = bool(use_token)
        if schema is not None:
            self.schema = schema
        if serializer is not None:
            self.serializer = serializer
        if url_prefix is not None:
            self.url_prefix = url_prefix
        if db is not None:
            self.db = db
        if cli_group is not None:
            self.cli_group = cli_group
        if login_view is not None:
            self.login_view = login_view
        if bp_login_views is not None:
            self.bp_login_views = _normalize_bp_login_views(bp_login_views)
        if enable_redirect is not None:
            self.enable_redirect = _normalize_enable_redirect(enable_redirect)

        if self.model is None:
            raise ValueError(
                "Auth.init_app() requires a 'model' argument (e.g. model=User)"
            )

        for key, default_val in self.DEFAULT_CONFIG.items():
            app.config.setdefault(key, default_val)

        if self.login_view is None and app.config.get('AUTH_LOGIN_VIEW'):
            self.login_view = app.config['AUTH_LOGIN_VIEW']
        if not self.bp_login_views and app.config.get('AUTH_BP_LOGIN_VIEWS'):
            self.bp_login_views = _normalize_bp_login_views(
                app.config['AUTH_BP_LOGIN_VIEWS']
            )
        if self.enable_redirect is None:
            self.enable_redirect = _normalize_enable_redirect(
                app.config.get('AUTH_ENABLE_REDIRECT', ('session',))
            )

        if not app.config.get('JWT_SECRET_KEY') and app.config.get('SECRET_KEY'):
            app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']

        app.extensions = getattr(app, 'extensions', {})
        app.extensions['flask_user_auth'] = self

        if self.use_session:
            self._setup_session_auth(app)

        if self.use_token:
            self._setup_token_auth(app)

        if register_blueprint:
            prefix = (
                self.url_prefix
                if self.url_prefix is not None
                else app.config.get('AUTH_URL_PREFIX', '/auth')
            )
            stripped = (prefix or '').strip('/')
            normalized_prefix = f'/{stripped}' if stripped else ''
            self.blueprint = create_auth_blueprint(
                self, url_prefix=normalized_prefix
            )
            app.register_blueprint(self.blueprint)

        if register_cli:
            self._setup_cli(app)

        return self

    def _setup_cli(self, app):
        """Register CLI command group(s) (``flask user ...`` and ``flask auth ...``)."""
        if self.cli_group:
            groups = (
                (self.cli_group,)
                if isinstance(self.cli_group, str)
                else tuple(self.cli_group)
            )
        else:
            raw_groups = app.config.get('AUTH_CLI_GROUPS', ('user', 'auth'))
            groups = (
                (raw_groups,)
                if isinstance(raw_groups, str)
                else tuple(raw_groups or ('user',))
            )

        for group_name in groups:
            if not group_name:
                continue
            cmd_group = create_auth_cli(self, name=group_name)
            if self.cli is None:
                self.cli = cmd_group
            if group_name not in app.cli.commands:
                app.cli.add_command(cmd_group)

    # --- Redirect & Unauthorized Handling ------------------------------

    def get_enabled_redirect_modes(self, override=None) -> set[str]:
        """Return active redirect modes (subset of ``{'session', 'token'}``)."""
        if override is not None:
            return _normalize_enable_redirect(override)
        if self.enable_redirect is not None:
            return set(self.enable_redirect)
        return _normalize_enable_redirect(
            current_app.config.get('AUTH_ENABLE_REDIRECT', ('session',))
        )

    def resolve_login_target(self, login_view=None, bp_name=None) -> str | None:
        """Resolve the login URL or endpoint for the active blueprint or app.

        Priority:
            1. Explicit ``login_view`` argument (e.g. per-decorator override)
            2. ``bp_login_views[request.blueprint]``
            3. ``self.login_view`` / ``app.config['AUTH_LOGIN_VIEW']``
            4. ``None`` (use JSON response)
        """
        if login_view:
            return login_view

        active_bp = bp_name if bp_name is not None else getattr(request, 'blueprint', None)
        bp_map = self.bp_login_views or _normalize_bp_login_views(
            current_app.config.get('AUTH_BP_LOGIN_VIEWS')
        )
        if active_bp and active_bp in bp_map:
            return bp_map[active_bp]

        return self.login_view or current_app.config.get('AUTH_LOGIN_VIEW')

    def build_login_redirect_url(self, target: str, include_next: bool = True) -> str:
        """Convert a URL path or Flask endpoint name into a redirect URL (with ``?next=...``)."""
        if target.startswith(('/', 'http://', 'https://')):
            base_url = target
        else:
            try:
                base_url = url_for(target)
            except BuildError:
                base_url = target

        next_param = current_app.config.get('AUTH_REDIRECT_NEXT_PARAM', 'next')
        if not include_next or not next_param:
            return base_url

        next_path = request.full_path.rstrip('?') if request.query_string else request.path
        if not next_path:
            return base_url

        parsed = urlparse(base_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.setdefault(next_param, next_path)
        new_query = urlencode(query)
        return urlunparse(parsed._replace(query=new_query))

    def should_redirect_unauthorized(
        self,
        *,
        allow_session: bool = False,
        allow_token: bool = False,
        enable_redirect=None,
    ) -> bool:
        """Check whether an unauthorized request should redirect based on ``enable_redirect``."""
        modes = self.get_enabled_redirect_modes(override=enable_redirect)
        if not modes:
            return False
        if allow_session and 'session' in modes:
            return True
        if allow_token and 'token' in modes:
            return True
        return False

    def unauthorized_response(
        self,
        message: str = 'Authentication required',
        status_code: int = 401,
        *,
        allow_session: bool = False,
        allow_token: bool = False,
        login_view: str | None = None,
        enable_redirect=None,
    ):
        """Return a redirect response if configured & enabled for the auth mode,
        otherwise return a JSON error response ``(jsonify({'message': message}), status_code)``.
        """
        target = self.resolve_login_target(login_view=login_view)
        if target and self.should_redirect_unauthorized(
            allow_session=allow_session,
            allow_token=allow_token,
            enable_redirect=enable_redirect,
        ):
            return redirect(self.build_login_redirect_url(target))
        return jsonify({'message': message}), status_code

    def _setup_session_auth(self, app):
        """Configure Flask-Login ``LoginManager`` on ``app``."""
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        if self.login_view:
            self.login_manager.login_view = self.login_view
        if self.bp_login_views:
            self.login_manager.blueprint_login_views.update(self.bp_login_views)

        @self.login_manager.user_loader
        def _load_user_from_session(user_id):
            return self.load_user(user_id)

        @self.login_manager.unauthorized_handler
        def _unauthorized():
            return self.unauthorized_response(
                'Session authentication required',
                401,
                allow_session=True,
                allow_token=False,
            )

    def _setup_token_auth(self, app):
        """Configure Flask-HTTPAuth ``HTTPTokenAuth`` on ``app``."""
        scheme = app.config.get('JWT_HEADER_TYPE', 'Bearer')
        header_name = app.config.get('JWT_HEADER_NAME', 'Authorization')
        header = None if header_name.lower() == 'authorization' else header_name
        self.http_auth = HTTPTokenAuth(scheme=scheme, header=header)

        @self.http_auth.verify_token
        def _verify_token(token):
            return self._verify_token_with_http_auth(token)

        @self.http_auth.error_handler
        def _token_error(status):
            msg = getattr(
                g, '_auth_token_error', 'Invalid or missing authentication token'
            )
            return self.unauthorized_response(
                msg,
                status or 401,
                allow_session=False,
                allow_token=True,
            )

    def _verify_token_with_http_auth(self, raw_token):
        """Verify ``raw_token`` as an access JWT and populate request context."""
        if not raw_token:
            g._auth_token_error = 'Invalid or missing authentication token'
            return None
        try:
            payload = self.jwt.decode_token(raw_token, expected_type='access')
        except TokenError as err:
            g._auth_token_error = err.message
            return None

        user = self.load_user(payload.get('sub'))
        if user is None:
            g._auth_token_error = 'User not found'
            return None
        if not getattr(user, 'is_active', True):
            g._auth_token_error = 'Account is inactive'
            return None

        g.jwt_payload = payload
        g.current_user = user
        g.flask_httpauth_user = user
        return user

    # --- SQLAlchemy 2.0+ session, lookup & user management helpers -----

    def _get_db_session(self):
        """Locate the active SQLAlchemy 2.0 ``Session`` from ``self.db`` or ``current_app``."""
        if self.db is not None and hasattr(self.db, 'session'):
            return self.db.session
        sa_ext = getattr(current_app, 'extensions', {}).get('sqlalchemy')
        if sa_ext is not None:
            if hasattr(sa_ext, 'session'):
                return sa_ext.session
            if hasattr(sa_ext, 'db') and hasattr(sa_ext.db, 'session'):
                return sa_ext.db.session
        raise RuntimeError(
            'SQLAlchemy extension is not registered on the current Flask app '
            'and no db instance was provided to Auth.'
        )

    def get_user_identity(self, user):
        """Return the primary key value of ``user``."""
        pk_field = current_app.config.get('AUTH_PK_FIELD', 'id')
        return getattr(user, pk_field)

    def get_user_by(self, field, value, fallback_pk=True):
        """Look up a user by any column ``field == value``.

        If ``fallback_pk=True`` and no match is found on ``field``, also checks
        the primary key column when ``value`` can be coerced to an integer.
        """
        if value is None:
            return None

        session = self._get_db_session()
        col = getattr(self.model, field, None)
        if col is not None:
            coerced = value
            try:
                col_type = getattr(col.property.columns[0], 'type', None)
                if isinstance(col_type, sa.Integer):
                    coerced = int(value)
            except (AttributeError, ValueError, TypeError, IndexError):
                coerced = None

            if coerced is not None:
                stmt = sa.select(self.model).where(col == coerced)
                user = session.scalar(stmt)
                if user is not None:
                    return user

        if fallback_pk:
            pk_field = current_app.config.get('AUTH_PK_FIELD', 'id')
            if field != pk_field and str(value).isdigit():
                return self.load_user(int(value))

        return None

    def set_user_password(self, user, raw_password, commit=True):
        """Set or reset ``user``'s password and optionally commit."""
        if not raw_password:
            raise ValueError('Password cannot be empty')
        setter = getattr(user, 'set_password', None)
        if callable(setter):
            setter(raw_password)
        elif hasattr(user.__class__, 'password'):
            setattr(user, 'password', raw_password)
        else:
            setattr(user, 'password_hash', generate_password_hash(raw_password))

        session = self._get_db_session()
        session.add(user)
        if commit:
            session.commit()
        return user

    def create_user(self, password=None, commit=True, **fields):
        """Create and persist a new user (or admin with ``is_admin=True``)."""
        raw_password = password or fields.pop('password', None)
        user = self.model(**fields)
        if raw_password is not None:
            self.set_user_password(user, raw_password, commit=False)
        session = self._get_db_session()
        session.add(user)
        if commit:
            session.commit()
        return user

    def update_user(self, user, password=None, commit=True, **fields):
        """Update attributes (and optionally password) on ``user`` and commit."""
        raw_password = password or fields.pop('password', None)
        for key, val in fields.items():
            setattr(user, key, val)
        if raw_password is not None:
            self.set_user_password(user, raw_password, commit=False)
        session = self._get_db_session()
        session.add(user)
        if commit:
            session.commit()
        return user

    def load_user(self, identity):
        """Look up a user instance by primary key ``identity`` using SQLAlchemy 2.0."""
        if identity is None:
            return None
        if self._user_loader_callback is not None:
            return self._user_loader_callback(identity)

        pk_field = current_app.config.get('AUTH_PK_FIELD', 'id')
        pk_col = getattr(self.model, pk_field, None)
        if pk_col is None:
            return None

        value = identity
        try:
            col_type = getattr(pk_col.property.columns[0], 'type', None)
            if isinstance(col_type, sa.Integer):
                value = int(identity)
        except (AttributeError, ValueError, TypeError, IndexError):
            return None

        session = self._get_db_session()
        stmt = sa.select(self.model).where(pk_col == value)
        return session.scalar(stmt)

    def authenticate(self, identity, password):
        """Verify credentials and return the matching user or ``None``."""
        if self._authenticate_callback is not None:
            return self._authenticate_callback(identity, password)

        identity_field = current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        col = getattr(self.model, identity_field, None)
        if col is None:
            return None

        session = self._get_db_session()
        stmt = sa.select(self.model).where(col == identity)
        user = session.scalar(stmt)
        if user is None:
            return None

        checker = getattr(user, 'check_password', None)
        if callable(checker):
            if not checker(password):
                return None
        else:
            from werkzeug.security import check_password_hash
            pwd_hash = getattr(user, 'password_hash', None)
            if not pwd_hash or not check_password_hash(pwd_hash, password):
                return None

        return user

    def serialize_user(self, user):
        """Serialize ``user`` using a configured serializer, schema, or ``to_dict()``."""
        if user is None:
            return None
        if self.serializer is not None:
            if hasattr(self.serializer, 'dump') or (
                isinstance(self.serializer, type) and hasattr(self.serializer, 'dump')
            ):
                schema_inst = (
                    self.serializer()
                    if isinstance(self.serializer, type)
                    else self.serializer
                )
                return schema_inst.dump(user)
            if callable(self.serializer):
                return self.serializer(user)
        if self.schema is not None:
            schema_inst = (
                self.schema() if isinstance(self.schema, type) else self.schema
            )
            return schema_inst.dump(user)
        to_dict = getattr(user, 'to_dict', None)
        if callable(to_dict):
            return to_dict()
        to_auth_dict = getattr(user, 'to_auth_dict', None)
        if callable(to_auth_dict):
            return to_auth_dict()
        return {
            'id': getattr(user, 'id', None),
            'email': getattr(user, 'email', None),
            'is_admin': bool(getattr(user, 'is_admin', False)),
            'is_active': bool(getattr(user, 'is_active', True)),
        }

    # --- callback registration hooks ----------------------------------

    def user_loader(self, fn):
        """Register a custom ``fn(identity) -> user`` lookup callback."""
        self._user_loader_callback = fn
        return fn

    def authenticate_handler(self, fn):
        """Register a custom ``fn(identity, password) -> user`` callback."""
        self._authenticate_callback = fn
        return fn

    def token_in_blocklist_loader(self, fn):
        """Register a custom ``fn(jwt_payload) -> bool`` revocation check."""
        self._token_blocklist_loader = fn
        return fn

    # --- bound decorators & helpers -----------------------------------

    @property
    def current_user(self):
        return current_user

    def auth_required(self, *args, session=None, token=None, admin=False,
                      login_view=None, enable_redirect=None):
        return _auth_required(
            *args,
            session=session,
            token=token,
            admin=admin,
            login_view=login_view,
            enable_redirect=enable_redirect,
            auth_ext=self,
        )

    def login_required(self, *args, admin=False, login_view=None,
                       enable_redirect=None):
        return _login_required(
            *args,
            admin=admin,
            login_view=login_view,
            enable_redirect=enable_redirect,
            auth_ext=self,
        )

    def token_required(self, *args, admin=False, login_view=None,
                       enable_redirect=None):
        return _token_required(
            *args,
            admin=admin,
            login_view=login_view,
            enable_redirect=enable_redirect,
            auth_ext=self,
        )

    def admin_required(self, *args, session=None, token=None,
                       login_view=None, enable_redirect=None):
        return _admin_required(
            *args,
            session=session,
            token=token,
            login_view=login_view,
            enable_redirect=enable_redirect,
            auth_ext=self,
        )
