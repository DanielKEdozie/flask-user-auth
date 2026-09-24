# flask-user-auth

Dual token (JWT) & session (cookie) authentication, User/UserAuth separation, built-in Click CLI, granular route decorators, and automatic CRUD for Flask + SQLAlchemy.

---

## Key Features

1. **Separation of Profile (`User`) and Credentials (`UserAuth`)**:
   - `User` table holds identity and profile information (`email`, `is_active`, `is_admin`, timestamps, relations).
   - `UserAuth` table holds security credentials (`user_id` PK/FK, `password_hash`, `last_reset_date`, `last_login_date`).
   - Profile queries (`GET /users`, `GET /auth/me`) **cannot leak password hashes**.
2. **Instant Token Invalidation via `last_reset_date`**:
   - Changing or resetting a password updates `last_reset_date`.
   - Older JWT tokens issued prior to that timestamp are **immediately revoked across all devices**.
3. **Dual Authentication**:
   - **Token Flow (SPAs & Mobile)**: `/auth/token`, `/auth/refresh`, `/auth/me`, `/auth/change-password`.
   - **Session Flow (Web & Admin)**: `/auth/session/login`, `/auth/session/logout`, `/auth/session/me` via Flask-Login.
4. **Granular Route Protection Decorators**:
   - `@login_required`: Dual auth by default (or configured default).
   - `@login_required(auth_type="session")` / `@session_required`: Strict session cookie only.
   - `@login_required(auth_type="token")` / `@token_required`: Strict `Authorization: Bearer <token>` only.
   - `@roles_required(*roles, auth_type="...")` and `@admin_required(auth_type="...")`.
5. **Standardized `config.py` Settings (`FUA_*`)**:
   - Configure everything cleanly in your Flask application config (`FUA_JWT_ACCESS_TOKEN_EXPIRES`, `FUA_COOKIE_SAMESITE`, etc.).
6. **Secure Refresh Strategy (`refresh_type`)**:
   - Supports both HTTP-only secure cookies (`'http'`) to mitigate XSS and JSON payload tokens (`'token'`).
7. **Built-in Click CLI (`flask user ...`)**:
   - Command-line operations: `list`, `create`, `create-admin`, `set-password`, `activate`, `deactivate`, `delete`.
8. **Automatic Admin CRUD**:
   - Seamlessly integrates with `flask-api-builder` for `/users` REST endpoints.

---

## Install

From GitHub:

```bash
pip install git+https://github.com/DanielKEdozie/flask-user-auth.git
```

Or in `requirements.txt`:

```text
flask-user-auth @ git+https://github.com/DanielKEdozie/flask-user-auth.git@v1.1.0
```

---

## Configuration (`config.py` / `app.config`)

Configure your settings directly via standard `FUA_*` keys in `config.py`:

```python
# config.py
from datetime import timedelta


class Config:
  SECRET_KEY = 'your-secret-key'

  # JWT & Tokens:
  FUA_JWT_SECRET_KEY = 'your-jwt-secret-key'  # Falls back to SECRET_KEY
  FUA_JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  # Or seconds (3600)
  FUA_JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)  # Or seconds (86400 * 30)

  # Cookie Settings for refresh token:
  FUA_COOKIE_NAME = 'refresh_token'
  FUA_COOKIE_SAMESITE = 'Lax'  # 'Lax', 'Strict', or 'None'
  FUA_COOKIE_SECURE = True  # True in production (HTTPS)
  FUA_COOKIE_HTTPONLY = True  # Prevent JS access (XSS defense)
  FUA_COOKIE_PATH = '/'

  # Flask-Login Session Settings:
  FUA_FLASK_LOGIN = True
  FUA_LOGIN_VIEW = 'auth.session_login'  # Redirect view for unauthenticated users
  FUA_LOGIN_MESSAGE = 'Please log in to access this page.'
  FUA_LOGIN_MESSAGE_CATEGORY = 'info'

  # Routing & Behaviors:
  FUA_AUTH_PREFIX = '/auth'
  FUA_USER_PREFIX = '/users'
  FUA_REFRESH_TYPE = ['http', 'token']
  FUA_DEFAULT_AUTH_TYPE = 'both'  # 'both', 'session', or 'token'
  FUA_CLI_GROUP = 'user'
```

---

## Quick Start

### 1. Define Your Models

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_user_auth import FlaskUserAuth, UserAuthMixin, UserMixin

app = Flask(__name__)
app.config.from_object("config.Config")

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
  __tablename__ = "users"

  # UserMixin supplies: id, email, is_active, is_admin, created_at, updated_at, auth relation
  name = db.Column(db.String(255), nullable=False)
  role = db.Column(db.String(50), default="user")

  # Add relations to future models:
  orders = db.relationship("Order", backref="user", lazy="select")


class UserAuth(db.Model, UserAuthMixin):
  __tablename__ = "user_auth"
  # UserAuthMixin supplies: user_id (PK & FK), password_hash, last_reset_date, etc.
```

### 2. Initialize the Extension

```python
user_auth = FlaskUserAuth()
user_auth.init_app(
    app,
    db=db,
    user_model=User,
    auth_model=UserAuth,
)

with app.app_context():
  db.create_all()
```

---


### Direct Flask-Login Customization

`user_auth.login_manager` directly exposes the `LoginManager` instance for custom configurations:

```python
user_auth.init_app(app, db=db, user_model=User, auth_model=UserAuth)

# Direct access to Flask-Login settings:
user_auth.login_manager.login_view = 'auth.session_login'
user_auth.login_manager.login_message = 'Please sign in to proceed.'
user_auth.login_manager.login_message_category = 'warning'
user_auth.login_manager.needs_refresh_message = 'Please re-authenticate.'
```
## Granular Route Protection Decorators

Choose the exact authentication mode for every route:

```python
from flask_user_auth import (
    admin_required,
    current_user,
    login_required,
    roles_required,
    session_required,
    token_required,
)


# 1. Dual Auth (Accepts either active session cookie OR Bearer token):
@app.route('/api/general')
@login_required
def general():
  return {'email': current_user.email}


# 2. Strict Session Cookie (For web pages & Jinja admin templates):
@app.route('/dashboard')
@session_required  # Equivalent to @login_required(auth_type="session")
def dashboard():
  return {'user': current_user.email}


# 3. Strict Bearer Token (For mobile & SPA REST APIs):
@app.route('/api/v1/orders')
@token_required  # Equivalent to @login_required(auth_type="token")
def list_orders():
  return {'user_id': current_user.id}


# 4. Role-based protection:
@app.route('/api/reports')
@roles_required('manager', 'director', auth_type='token')
def reports():
  return {'data': []}


# 5. Admin-only:
@app.route('/admin/metrics')
@admin_required(auth_type='session')
def admin_metrics():
  return {'metrics': {...}}
```

---

## Built-in CLI Commands (`flask user ...`)

```bash
# List all registered users
flask user list [--limit 50] [--role admin] [--active]

# Create a standard user (prompts securely for password if omitted)
flask user create --email user@example.com --name "John Doe"

# Create an administrator
flask user create-admin --email admin@example.com --name "Super Admin"

# Reset a user's password (auto-revokes all existing JWTs)
flask user set-password --email user@example.com

# Activate or deactivate accounts
flask user deactivate --email user@example.com
flask user activate --email user@example.com

# Delete user (cascades to user_auth)
flask user delete --email user@example.com [--yes]
```

---

## License

MIT