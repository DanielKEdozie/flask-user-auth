from flask import current_app, g, jsonify
from flask_httpauth import HTTPTokenAuth
from flask_login import LoginManager
import sqlalchemy as sa

from .decorators import (
    admin_required as _admin_required,
    auth_required as _auth_required,
    current_user,
    login_required as _login_required,
    token_required as _token_required,
)
from .routes import create_auth_blueprint
from .tokens import JWTManager, TokenError


class Auth:
    """Flask authentication extension combining Flask-Login (session) and
    Flask-HTTPAuth + PyJWT (Bearer & cookie tokens) using SQLAlchemy 2.0+.

    Usage::

        from flask_user_auth import Auth

        auth = Auth()
        auth.init_app(app, model=User, use_session=True, use_token=True)
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
    }

    def __init__(self, app=None, model=None, use_session=True, use_token=True,
                 schema=None, serializer=None, url_prefix=None, db=None):
        self.app = app
        self.model = model
        self.use_session = bool(use_session)
        self.use_token = bool(use_token)
        self.schema = schema
        self.serializer = serializer
        self.url_prefix = url_prefix
        self.db = db

        self.login_manager = None
        self.http_auth = None
        self.jwt = JWTManager(self)
        self.blueprint = None

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
            )

    def init_app(self, app, model=None, use_session=None, use_token=None,
                 schema=None, serializer=None, url_prefix=None, db=None,
                 register_blueprint=True):
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

        if self.model is None:
            raise ValueError(
                "Auth.init_app() requires a 'model' argument (e.g. model=User)"
            )

        for key, default_val in self.DEFAULT_CONFIG.items():
            app.config.setdefault(key, default_val)

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

        return self

    def _setup_session_auth(self, app):
        """Configure Flask-Login ``LoginManager`` on ``app``."""
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)

        @self.login_manager.user_loader
        def _load_user_from_session(user_id):
            return self.load_user(user_id)

        @self.login_manager.unauthorized_handler
        def _unauthorized():
            return jsonify({'message': 'Session authentication required'}), 401

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
            return jsonify({'message': msg}), status or 401

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

    # --- SQLAlchemy 2.0+ session & model resolution --------------------

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

    def auth_required(self, *args, session=None, token=None, admin=False):
        return _auth_required(
            *args, session=session, token=token, admin=admin, auth_ext=self
        )

    def login_required(self, *args, admin=False):
        return _login_required(*args, admin=admin, auth_ext=self)

    def token_required(self, *args, admin=False):
        return _token_required(*args, admin=admin, auth_ext=self)

    def admin_required(self, *args, session=None, token=None):
        return _admin_required(
            *args, session=session, token=token, auth_ext=self
        )
