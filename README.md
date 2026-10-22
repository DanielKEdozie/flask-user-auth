# `flask_user_auth`

A lightweight Flask authentication package built for **SQLAlchemy 2.0+** that seamlessly combines **session authentication** ([`Flask-Login`](https://flask-login.readthedocs.io/)) and **JWT Bearer / cookie token authentication** ([`Flask-HTTPAuth`](https://flask-httpauth.readthedocs.io/) + [`PyJWT`](https://pyjwt.readthedocs.io/)).

Clients can choose at login time whether to authenticate via **session**, **token**, or **both simultaneously**.

---

## Features

- **SQLAlchemy 2.0+ Native**: Uses `Mapped[...]` and `mapped_column(...)` on [`AuthUserMixin`](file:///c:/Users/danni/OneDrive/Desktop/project-3/foodmart/packages/flask_user_auth/mixins.py#L7-L79) and `session.scalar(sa.select(...))` queries throughout.
- **Dual Auth Mechanics**: Enable session auth (`use_session=True`), token auth (`use_token=True`), or both on your Flask app.
- **Per-Login Selection**: `POST /auth/login` accepts `{"session": bool, "token": bool}` in its JSON payload so clients (web apps, mobile apps, SPAs, CLI tools) can pick one or both mechanics on the fly.
- **Built-in SQLAlchemy 2.0 Mixin (`UserMixin` / `AuthUserMixin`)**: Provides `id`, `email`, `password_hash`, `is_admin`, `is_active`, password hashing helpers (`password` setter, `set_password`, `check_password`), and `to_dict()` serialization.
- **Ready-to-Use Endpoints**: Mounts `/login`, `/logout`, `/refresh`, and `/me` under `AUTH_URL_PREFIX` (default `'/auth'`).
- **Flexible Route Decorators**: Exported `login_required`, `token_required`, `auth_required` (supports `@auth_required`, `@auth_required()`, `@auth_required('session')`, `@auth_required('token')`, `@auth_required(session=True, token=True)`), and `admin_required`.
- **Unified `current_user` Proxy**: Resolves the active user regardless of whether the request authenticated via Flask-Login session or Flask-HTTPAuth Bearer token.

---

## Quick Start

### 1. Define Your User Model (SQLAlchemy 2.0+)

Inherit from `UserMixin` (or `AuthUserMixin`) alongside `db.Model`:

```python
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask_user_auth import UserMixin


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    # Included automatically by UserMixin (SQLAlchemy 2.0 Mapped columns):
    # - id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    # - email: Mapped[str] = mapped_column(sa.String(255), unique=True, nullable=False, index=True)
    # - password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    # - is_admin: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    # - is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    # Add any extra custom columns using SQLAlchemy 2.0 syntax:
    full_name: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
```

Creating a user and setting a password:

```python
user = User(email='alice@example.com', password='secret-password', is_admin=False)
# Or explicitly:
user.set_password('secret-password')
assert user.check_password('secret-password') is True
```

### 2. Initialize `Auth` on Your Flask App

```python
from flask import Flask
from flask_user_auth import Auth

auth = Auth()


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY='your-session-secret',
        SQLALCHEMY_DATABASE_URI='sqlite:///app.db',
        JWT_SECRET_KEY='your-minimum-32-byte-jwt-secret-key',
        JWT_ACCESS_EXPIRES=900,            # 15 minutes (int seconds, timedelta, or '15m')
        JWT_REFRESH_EXPIRES=2592000,       # 30 days (int seconds, timedelta, or '30d')
        JWT_COOKIE_NAME='refresh_token',
        AUTH_URL_PREFIX='/auth',
    )

    db.init_app(app)
    auth.init_app(app, model=User, use_session=True, use_token=True)
    return app
```

You can also pass a custom Marshmallow `schema` or `serializer` function to `init_app`:

```python
auth.init_app(
    app,
    model=User,
    use_session=True,
    use_token=True,
    schema=UserSchema,                     # or serializer=lambda u: u.to_dict()
)
```

---

## Configuration Options

| Config Key | Default | Description |
| :--- | :--- | :--- |
| `JWT_SECRET_KEY` | `app.config['SECRET_KEY']` | Secret key used to sign and verify JWT tokens. |
| `JWT_ALGORITHM` | `'HS256'` | Signing algorithm used by PyJWT. |
| `JWT_ACCESS_EXPIRES` | `900` (15m) | Access token lifetime (`int` seconds, `timedelta`, or string like `'15m'`, `'1h'`). |
| `JWT_REFRESH_EXPIRES` | `2592000` (30d) | Refresh token lifetime (`int` seconds, `timedelta`, or string like `'7d'`, `'30d'`). |
| `JWT_COOKIE_NAME` | `'refresh_token'` | Cookie name used to store the refresh token. |
| `JWT_COOKIE_ENABLED` | `True` | Whether to attach the refresh token as an HTTP cookie on login/refresh. |
| `JWT_COOKIE_HTTPONLY` | `True` | Set `HttpOnly` flag on the refresh token cookie. |
| `JWT_COOKIE_SECURE` | `False` | Set `Secure` flag on the refresh token cookie (set `True` in production HTTPS). |
| `JWT_COOKIE_SAMESITE` | `'Lax'` | `SameSite` attribute for the refresh token cookie (`'Lax'`, `'Strict'`, `'None'`). |
| `JWT_COOKIE_PATH` | `'/'` | Cookie path for the refresh token cookie. |
| `JWT_COOKIE_DOMAIN` | `None` | Cookie domain for the refresh token cookie. |
| `JWT_HEADER_NAME` | `'Authorization'` | HTTP header read for Bearer tokens. |
| `JWT_HEADER_TYPE` | `'Bearer'` | Authorization scheme prefix used with `Flask-HTTPAuth`. |
| `JWT_ROTATE_REFRESH_TOKENS` | `False` | When `True`, `/auth/refresh` revokes the old refresh token and issues a new one. |
| `JWT_ISSUER` | `None` | Optional `iss` claim validated on decode. |
| `JWT_AUDIENCE` | `None` | Optional `aud` claim validated on decode. |
| `AUTH_URL_PREFIX` | `'/auth'` | URL prefix where `/login`, `/logout`, `/refresh`, and `/me` are mounted. |
| `AUTH_IDENTITY_FIELD` | `'email'` | Model attribute used to look up the user during login. |
| `AUTH_PK_FIELD` | `'id'` | Primary key attribute on the user model. |
| `AUTH_REQUIRE_MECHANISM_CHOICE` | `False` | When `True`, `/auth/login` requires `'session'` or `'token'` to be explicitly passed in request JSON. When `False`, omitting both defaults to the mechanisms enabled on `Auth`. |

---

## Built-in Endpoints

All routes are registered on the `flask_user_auth` blueprint under `AUTH_URL_PREFIX` (default `/auth`).

### 1. `POST /auth/login`

Authenticates a user and activates the requested auth mechanism(s).

**Request JSON:**
```json
{
  "email": "alice@example.com",
  "password": "secret-password",
  "session": true,
  "token": true,
  "remember": false
}
```
- `session` (`bool`): Logs the user in via `flask_login.login_user()`.
- `token` (`bool`): Generates `access_token` and `refresh_token` (returned in JSON and set in the `JWT_COOKIE_NAME` HTTP-only cookie).
- Both `session` and `token` can be `true` together, or either one individually. If neither key is included in the JSON body, it defaults to `use_session` / `use_token` configured on `Auth`.

**Response (`200 OK`):**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "is_admin": false,
    "is_active": true
  },
  "session": true,
  "token": true,
  "access_token": "<jwt-access-token>",
  "refresh_token": "<jwt-refresh-token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```
*(When `token: false`, `access_token`, `refresh_token`, `token_type`, and `expires_in` are omitted.)*

---

### 2. `POST /auth/logout`

Logs out the current session (via `flask_login.logout_user()`), revokes active Bearer access and refresh token `jti`s, and clears the `JWT_COOKIE_NAME` cookie.

**Response (`200 OK`):**
```json
{
  "message": "Logged out successfully"
}
```

---

### 3. `POST /auth/refresh`

Issues a fresh `access_token` using a valid refresh token. The refresh token is read automatically in the following order:
1. `JWT_COOKIE_NAME` cookie
2. Request JSON body: `{"refresh_token": "<jwt-refresh-token>"}`
3. `Authorization: Bearer <jwt-refresh-token>` header

**Response (`200 OK`):**
```json
{
  "access_token": "<new-jwt-access-token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "is_admin": false,
    "is_active": true
  }
}
```

---

### 4. `GET /auth/me`

Returns the currently authenticated user (accepts either session cookie or `Authorization: Bearer <access_token>`).

**Response (`200 OK`):**
```json
{
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "is_admin": false,
    "is_active": true
  },
  "auth_method": "token"
}
```

---

## Protecting Routes with Decorators

Import decorators directly from `flask_user_auth` (or access them on your `auth` instance as `auth.login_required`, `auth.token_required`, `auth.auth_required`, `auth.admin_required`):

```python
from flask import jsonify
from flask_user_auth import (
    admin_required,
    auth_required,
    current_user,
    login_required,
    token_required,
)


# 1. Accept EITHER session OR token (whichever is enabled on Auth)
@app.get('/profile')
@auth_required
def profile():
    return jsonify(current_user.to_dict())


@app.get('/profile-alt')
@auth_required()
def profile_alt():
    return jsonify(current_user.to_dict())


# 2. Require Flask-Login session only
@app.get('/dashboard')
@login_required
# Equivalent to: @auth_required('session') or @auth_required(session=True)
def dashboard():
    return jsonify({'user': current_user.email})


# 3. Require Bearer JWT token only (verified via Flask-HTTPAuth)
@app.get('/api/data')
@token_required
# Equivalent to: @auth_required('token') or @auth_required(token=True)
def api_data():
    return jsonify({'user': current_user.email})


# 4. Explicit dual-mode via positional or keyword args
@app.get('/hybrid')
@auth_required('session', 'token')
# Equivalent to: @auth_required(session=True, token=True)
def hybrid():
    return jsonify({'user': current_user.email})


# 5. Require Admin User (is_admin=True)
@app.delete('/users/<int:user_id>')
@admin_required
# Or restrict to token-only admin: @token_required(admin=True) / @auth_required('token', admin=True)
def delete_user(user_id):
    return jsonify({'deleted': user_id})
```

---

## Custom Callbacks (SQLAlchemy 2.0+)

You can override user lookup, credential verification, or token revocation checks using decorators on your `Auth` instance:

```python
import sqlalchemy as sa


@auth.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


@auth.authenticate_handler
def authenticate(identity: str, password: str):
    stmt = sa.select(User).where(User.email == identity.lower().strip())
    user = db.session.scalar(stmt)
    if user and user.check_password(password):
        return user
    return None


@auth.token_in_blocklist_loader
def check_if_token_revoked(jwt_payload: dict) -> bool:
    jti = jwt_payload['jti']
    stmt = sa.select(RevokedToken).where(RevokedToken.jti == jti)
    return db.session.scalar(stmt) is not None
```

---

## CLI Commands (`flask user` / `flask auth`)

When `auth.init_app(app, model=User)` is called, `flask_user_auth` automatically registers CLI command groups (`flask user` and `flask auth`, configurable via `AUTH_CLI_GROUPS` or `cli_group`):

```bash
# 1. Create a user (prompts for password if -p is omitted; accepts -f key=value or --<column> <value>)
flask user create alice@example.com -p secret123 --first-name Alice --last-name Obi -f phone=08030001111

# 2. Create an admin user (via --admin flag or dedicated create-admin command)
flask user create admin@example.com -p admin123 --admin
flask user create-admin boss@example.com -p admin123 --first-name Boss

# 3. Update a user by any field (--by defaults to email/id, or pass any model column)
flask user update alice@example.com --first-name Alicia --admin
flask user update 08030001111 --by phone -f first_name=Adaeze --inactive

# 4. Set or reset a user's password (explicit -p, interactive prompt, or --generate)
flask user set-password alice@example.com -p newsecret99
flask user reset-password alice@example.com
flask user reset-password boss@example.com --generate

# 5. Inspect users (outputs serialized to_dict() JSON)
flask user show alice@example.com
flask user list --admin
```

