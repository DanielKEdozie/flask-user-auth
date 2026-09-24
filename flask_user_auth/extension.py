"""FlaskUserAuth extension class."""
from datetime import timedelta
from typing import Any, List, Optional, Type
from flask import Blueprint, Flask
from sqlalchemy import select

from .cli import create_user_cli
from .routes import create_auth_blueprint
from .tokens import create_token


class FlaskUserAuth:
    """Extension providing dual authentication, user mixins, CLI, and CRUD."""

    def __init__(
        self,
        app: Optional[Flask] = None,
        db: Any = None,
        ma: Any = None,
        user_model: Optional[Type] = None,
        auth_model: Optional[Type] = None,
        auth_prefix: Optional[str] = None,
        user_prefix: Optional[str] = None,
        flask_login: Optional[bool] = None,
        refresh_type: Optional[List[str]] = None,
        jwt_secret: Optional[str] = None,
        access_token_expires: Optional[Any] = None,
        refresh_token_expires: Optional[Any] = None,
        default_auth_type: Optional[str] = None,
        cli_group: Optional[str] = None,
    ):
        self.app = app
        self.db = db
        self.ma = ma
        self.user_model = user_model
        self.auth_model = auth_model
        self._auth_prefix = auth_prefix
        self._user_prefix = user_prefix
        self._use_flask_login = flask_login
        self._refresh_type = refresh_type
        self._jwt_secret = jwt_secret
        self._access_token_expires = access_token_expires
        self._refresh_token_expires = refresh_token_expires
        self._default_auth_type = default_auth_type
        self._cli_group = cli_group

        if app is not None and db is not None:
            self.init_app(
                app=app,
                db=db,
                ma=ma,
                user_model=user_model,
                auth_model=auth_model,
                auth_prefix=auth_prefix,
                user_prefix=user_prefix,
                flask_login=flask_login,
                refresh_type=refresh_type,
                jwt_secret=jwt_secret,
                access_token_expires=access_token_expires,
                refresh_token_expires=refresh_token_expires,
                default_auth_type=default_auth_type,
                cli_group=cli_group,
            )

    @property
    def session(self) -> Any:
        """Return SQLAlchemy database session."""
        return getattr(self.db, "session", None)

    def get_user(self, user_id: int) -> Any:
        """Fetch user instance by primary key."""
        if not self.user_model:
            return None
        return self.session.get(self.user_model, int(user_id))

    def find_user_by_email(self, email: str) -> Any:
        """Fetch user instance by email."""
        if not self.user_model:
            return None
        stmt = select(self.user_model).where(self.user_model.email == email.lower())
        return self.session.execute(stmt).scalars().first()

    def create_access_token(self, user: Any, extra_claims: Optional[dict] = None) -> str:
        """Generate JWT access token for user."""
        claims = dict(extra_claims or {})
        if hasattr(user, "is_admin"):
            claims.setdefault("is_admin", user.is_admin)
        if hasattr(user, "role"):
            claims.setdefault("role", getattr(user, "role"))
        return create_token(
            user_id=user.id,
            secret_key=self.jwt_secret,
            token_type="access",
            expires_in=self.access_token_expires,
            extra_claims=claims,
        )

    def create_refresh_token(self, user: Any) -> str:
        """Generate JWT refresh token for user."""
        return create_token(
            user_id=user.id,
            secret_key=self.jwt_secret,
            token_type="refresh",
            expires_in=self.refresh_token_expires,
        )

    def init_app(
        self,
        app: Flask,
        db: Any,
        ma: Any = None,
        user_model: Optional[Type] = None,
        auth_model: Optional[Type] = None,
        auth_prefix: Optional[str] = None,
        user_prefix: Optional[str] = None,
        flask_login: Optional[bool] = None,
        refresh_type: Optional[List[str]] = None,
        jwt_secret: Optional[str] = None,
        access_token_expires: Optional[Any] = None,
        refresh_token_expires: Optional[Any] = None,
        default_auth_type: Optional[str] = None,
        cli_group: Optional[str] = None,
    ) -> None:
        """Initialize extension reading from app.config (FUA_*) with parameter overrides."""
        cfg = app.config
        self.app = app
        self.db = db
        self.ma = ma
        self.user_model = user_model or getattr(self, "user_model", None)
        self.auth_model = auth_model or getattr(self, "auth_model", None)

        # 1. Route prefixes and integrations:
        self.auth_prefix = (
            auth_prefix
            if auth_prefix is not None
            else self._auth_prefix
            if self._auth_prefix is not None
            else cfg.get("FUA_AUTH_PREFIX", "/auth")
        )
        self.user_prefix = (
            user_prefix
            if user_prefix is not None
            else self._user_prefix
            if self._user_prefix is not None
            else cfg.get("FUA_USER_PREFIX", "/users")
        )
        self.use_flask_login = (
            flask_login
            if flask_login is not None
            else self._use_flask_login
            if self._use_flask_login is not None
            else cfg.get("FUA_FLASK_LOGIN", True)
        )
        self.refresh_type = (
            refresh_type
            or self._refresh_type
            or cfg.get("FUA_REFRESH_TYPE", ["http", "token"])
        )
        self.default_auth_type = (
            default_auth_type
            or self._default_auth_type
            or cfg.get("FUA_DEFAULT_AUTH_TYPE", "both")
        )
        self.cli_group = (
            cli_group
            if cli_group is not None
            else self._cli_group
            if self._cli_group is not None
            else cfg.get("FUA_CLI_GROUP", "user")
        )

        # 2. JWT Configuration (FUA_JWT_*):
        self.jwt_secret = (
            jwt_secret
            or self._jwt_secret
            or cfg.get("FUA_JWT_SECRET_KEY")
            or cfg.get("JWT_SECRET_KEY")
            or cfg.get("SECRET_KEY")
            or "flask-user-auth-secret-change-me"
        )

        acc_exp = (
            access_token_expires
            if access_token_expires is not None
            else self._access_token_expires
            if self._access_token_expires is not None
            else cfg.get("FUA_JWT_ACCESS_TOKEN_EXPIRES", 3600)
        )
        if isinstance(acc_exp, timedelta):
            acc_exp = int(acc_exp.total_seconds())
        self.access_token_expires = int(acc_exp)

        ref_exp = (
            refresh_token_expires
            if refresh_token_expires is not None
            else self._refresh_token_expires
            if self._refresh_token_expires is not None
            else cfg.get("FUA_JWT_REFRESH_TOKEN_EXPIRES", 86400 * 30)
        )
        if isinstance(ref_exp, timedelta):
            ref_exp = int(ref_exp.total_seconds())
        self.refresh_token_expires = int(ref_exp)

        # 3. Cookie Configuration (FUA_COOKIE_*):
        self.cookie_name = cfg.get("FUA_COOKIE_NAME", "refresh_token")
        self.cookie_samesite = cfg.get("FUA_COOKIE_SAMESITE", "Lax")
        self.cookie_secure = cfg.get("FUA_COOKIE_SECURE", False)
        self.cookie_httponly = cfg.get("FUA_COOKIE_HTTPONLY", True)
        self.cookie_path = cfg.get("FUA_COOKIE_PATH", "/")

        app.extensions = getattr(app, "extensions", {})
        app.extensions["flask_user_auth"] = self

        # Setup Flask-Login if requested:
        if self.use_flask_login:
            self._init_flask_login(app)

        # Register auth blueprint:
        if self.auth_prefix:
            auth_bp = create_auth_blueprint(self)
            app.register_blueprint(auth_bp, url_prefix=self.auth_prefix)

        # Register User CRUD routes via ApiBuilder if user_prefix is configured:
        if self.user_prefix and self.user_model:
            self._init_user_crud(app)

        # Register CLI commands:
        if self.cli_group and self.user_model:
            cli = create_user_cli(self, self.cli_group)
            app.cli.add_command(cli)

    def _init_flask_login(self, app: Flask) -> None:
        """Configure Flask-Login LoginManager and expose it on self.login_manager."""
        try:
            from flask_login import LoginManager
            login_manager = getattr(app, "login_manager", None)
            if not login_manager:
                login_manager = LoginManager()
                login_manager.init_app(app)

            self.login_manager = login_manager

            # Auto-configure from config if specified:
            cfg = app.config
            if "FUA_LOGIN_VIEW" in cfg:
                self.login_manager.login_view = cfg["FUA_LOGIN_VIEW"]
            if "FUA_LOGIN_MESSAGE" in cfg:
                self.login_manager.login_message = cfg["FUA_LOGIN_MESSAGE"]
            if "FUA_LOGIN_MESSAGE_CATEGORY" in cfg:
                self.login_manager.login_message_category = cfg["FUA_LOGIN_MESSAGE_CATEGORY"]

            @login_manager.user_loader
            def load_user(user_id):
                return self.get_user(int(user_id))

        except ImportError:
            self.login_manager = None

    def _init_user_crud(self, app: Flask) -> None:
        """Configure user CRUD endpoints with ApiBuilder if available."""
        try:
            from flask_api_builder import ApiBuilder, SchemaBuilder
            user_bp = Blueprint("users_api", __name__, url_prefix=self.user_prefix)
            schema = SchemaBuilder(
                self.user_model,
                exclude=("auth",),
            )
            search_cols = ["email"]
            if hasattr(self.user_model, "name"):
                search_cols.append("name")

            filter_cols = ["is_active", "is_admin"]
            if hasattr(self.user_model, "role"):
                filter_cols.append("role")

            ApiBuilder(
                user_bp,
                model=self.user_model,
                schema=schema,
                endpoint="users",
                search_fields=tuple(search_cols),
                filter_fields=tuple(filter_cols),
                sort_field="created_at",
                paginate=True,
            )
            app.register_blueprint(user_bp)
        except ImportError:
            pass