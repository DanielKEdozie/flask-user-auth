"""Comprehensive test suite for flask-user-auth."""
import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from flask_user_auth import (
    FlaskUserAuth,
    UserAuthMixin,
    UserMixin,
    current_user,
    login_required,
    roles_required,
)
from flask_user_auth.tokens import decode_token, TokenRevokedError, verify_token_not_revoked


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(50), default="user")


class UserAuth(db.Model, UserAuthMixin):
    __tablename__ = "user_auth"


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-12345"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    db.init_app(app)

    auth = FlaskUserAuth()
    auth.init_app(
        app,
        db=db,
        user_model=User,
        auth_model=UserAuth,
        auth_prefix="/auth",
        flask_login=True,
        refresh_type=["http", "token"],
    )

    @app.route("/protected")
    @login_required
    def protected():
        return {"email": current_user.email, "id": current_user.id}

    @app.route("/admin-only")
    @roles_required("admin")
    def admin_only():
        return {"admin": True}

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_user_and_auth_models(app):
    with app.app_context():
        user = User(email="test@example.com", name="Test User")
        user.set_password("mypassword")
        db.session.add(user)
        db.session.commit()

        assert user.id is not None
        assert user.auth is not None
        assert user.auth.user_id == user.id
        assert user.check_password("mypassword") is True
        assert user.check_password("wrong") is False
        assert user.auth.last_reset_date is not None


def test_register_and_token_login(client):
    # 1. Register:
    res = client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "Password123!",
        "name": "Alice Wonderland",
    })
    assert res.status_code == 201
    data = res.get_json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "alice@example.com"
    access_token = data["access_token"]

    # 2. Access protected route with Bearer token:
    res = client.get("/protected", headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == 200
    assert res.get_json()["email"] == "alice@example.com"

    # 3. Login with credentials:
    res = client.post("/auth/token", json={
        "email": "alice@example.com",
        "password": "Password123!",
    })
    assert res.status_code == 200
    assert "access_token" in res.get_json()


def test_password_change_revokes_old_tokens(client):
    # 1. Register:
    res = client.post("/auth/register", json={
        "email": "bob@example.com",
        "password": "InitialPassword!",
    })
    token = res.get_json()["access_token"]

    # Verify token works:
    res = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

    # 2. Change password:
    import time
    time.sleep(1)  # small pause to advance timestamp
    res = client.post(
        "/auth/change-password",
        json={"old_password": "InitialPassword!", "new_password": "NewSecretPassword!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200

    # 3. Old token MUST now be revoked!
    res = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_session_login_and_logout(client):
    # Register user:
    client.post("/auth/register", json={"email": "charlie@example.com", "password": "SecretPassword"})

    # Session login:
    res = client.post("/auth/session/login", json={
        "email": "charlie@example.com",
        "password": "SecretPassword",
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Access protected route via session cookie:
    res = client.get("/protected")
    assert res.status_code == 200
    assert res.get_json()["email"] == "charlie@example.com"

    # Logout:
    res = client.post("/auth/session/logout")
    assert res.status_code == 200

    # Protected route should now fail:
    res = client.get("/protected")
    assert res.status_code == 401


def test_cli_commands(app):
    runner = app.test_cli_runner()

    # 1. Create User:
    res = runner.invoke(args=["user", "create", "--email", "cli@example.com", "--password", "clipass", "--name", "CLI User"])
    assert "Success" in res.output

    # 2. Create Admin:
    res = runner.invoke(args=["user", "create-admin", "--email", "admin@example.com", "--password", "adminpass", "--name", "Admin User"])
    assert "Success" in res.output

    # 3. List Users:
    res = runner.invoke(args=["user", "list"])
    assert "cli@example.com" in res.output
    assert "admin@example.com" in res.output

    # 4. Set Password:
    res = runner.invoke(args=["user", "set-password", "--email", "cli@example.com", "--password", "newclipass"])
    assert "Success" in res.output

    # 5. Deactivate:
    res = runner.invoke(args=["user", "deactivate", "--email", "cli@example.com"])
    assert "deactivated" in res.output

    # 6. Delete:
    res = runner.invoke(args=["user", "delete", "--email", "cli@example.com", "--yes"])
    assert "deleted" in res.output

def test_auth_type_decorators(app, client):
    from flask_user_auth import token_required, session_required, login_required

    @app.route("/token-strict")
    @token_required
    def token_strict():
        return {"auth": "token"}

    @app.route("/session-strict")
    @session_required
    def session_strict():
        return {"auth": "session"}

    @app.route("/parameterized-session")
    @login_required(auth_type="session")
    def parameterized_session():
        return {"auth": "session"}

    # 1. Register & get token:
    res = client.post("/auth/register", json={"email": "dan@example.com", "password": "pass"})
    token = res.get_json()["access_token"]

    # 2. Token-strict route:
    # Works with Bearer header:
    res = client.get("/token-strict", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

    # Fails when trying to access without token (even if session exists):
    res = client.get("/token-strict")
    assert res.status_code == 401

    # 3. Session-strict route:
    # Works because client has session cookie:
    res = client.get("/session-strict")
    assert res.status_code == 200

    # Parameterized session route works:
    res = client.get("/parameterized-session")
    assert res.status_code == 200

    # Logout to clear session:
    client.post("/auth/session/logout")

    # Session routes must now fail:
    res = client.get("/session-strict")
    assert res.status_code == 401
    res = client.get("/parameterized-session")
    assert res.status_code == 401


def test_fua_config_settings():
    from flask import Flask
    from flask_user_auth import FlaskUserAuth
    from datetime import timedelta

    app = Flask(__name__)
    app.config["FUA_JWT_SECRET_KEY"] = "custom-jwt-secret-xyz"
    app.config["FUA_JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
    app.config["FUA_COOKIE_SAMESITE"] = "Strict"
    app.config["FUA_COOKIE_SECURE"] = True
    app.config["FUA_AUTH_PREFIX"] = "/api/v1/auth"
    app.config["FUA_CLI_GROUP"] = "accounts"

    ext = FlaskUserAuth()
    ext.init_app(app, db=db, user_model=User, auth_model=UserAuth)

    assert ext.jwt_secret == "custom-jwt-secret-xyz"
    assert ext.access_token_expires == 900
    assert ext.cookie_samesite == "Strict"
    assert ext.cookie_secure is True
    assert ext.auth_prefix == "/api/v1/auth"
    assert ext.cli_group == "accounts"