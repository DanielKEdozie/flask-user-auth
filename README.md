# flask-user-auth

Dual token (JWT) & session (cookie) authentication, User/UserAuth separation, built-in Click CLI, and automatic CRUD for Flask + SQLAlchemy.

---

## Key Features

1. **Separation of Profile (`User`) and Credentials (`UserAuth`)**:
   - `User` table holds identity and profile information (`email`, `is_active`, `is_admin`, timestamps, relations).
   - `UserAuth` table holds security credentials (`user_id` PK/FK, `password_hash`, `last_reset_date`, `last_login_date`).
   - Profile queries (`GET /users`, `GET /auth/me`) **cannot leak password hashes**.
2. **Instant Token Invalidation via `last_reset_date`**:
   - Changing or resetting a password updates `last_reset_date`.
   - Older JWT tokens issued prior to that timestamp are **immediately rejected across all devices**.
3. **Dual Authentication**:
   - **Token Flow (SPAs & Mobile)**: `/auth/token`, `/auth/refresh`, `/auth/me`, `/auth/change-password`.
   - **Session Flow (Web & Admin)**: `/auth/session/login`, `/auth/session/logout`, `/auth/session/me` via Flask-Login.
4. **Secure Refresh Strategy (`refresh_type`)**:
   - Supports both HTTP-only secure cookies (`'http'`) to mitigate XSS and JSON payload tokens (`'token'`).
5. **Built-in Click CLI (`flask user ...`)**:
   - Command-line operations: `list`, `create`, `create-admin`, `set-password`, `activate`, `deactivate`, `delete`.
6. **Automatic Admin CRUD**:
   - Seamlessly integrates with `flask-api-builder` for `/users` REST endpoints.

---

## Install

From GitHub:

```bash
pip install git+https://github.com/DanielKEdozie/flask-user-auth.git
```

Or in `requirements.txt`:

```text
flask-user-auth @ git+https://github.com/DanielKEdozie/flask-user-auth.git@v1.0.0
```

---

## Quick Start

### 1. Define Your Models

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_user_auth import FlaskUserAuth, UserAuthMixin, UserMixin

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"

db = SQLAlchemy(app)


# User profile model:
class User(db.Model, UserMixin):
  __tablename__ = "users"

  # UserMixin supplies: id, email, is_active, is_admin, created_at, updated_at, auth relation
  name = db.Column(db.String(255), nullable=False)
  role = db.Column(db.String(50), default="user")


# Authentication credentials model:
class UserAuth(db.Model, UserAuthMixin):
  __tablename__ = "user_auth"
  # UserAuthMixin supplies:
  # user_id (PK & FK -> users.id, cascade delete)
  # password_hash, last_reset_date, failed_attempts, last_login_date
```

### 2. Initialize the Extension

```python
user_auth = FlaskUserAuth()
user_auth.init_app(
    app,
    db=db,
    user_model=User,
    auth_model=UserAuth,
    auth_prefix="/auth",  # /auth/token, /auth/refresh, /auth/me
    user_prefix="/users",  # Admin CRUD endpoints via flask-api-builder
    flask_login=True,  # Enables session auth /auth/session/*
    refresh_type=["http", "token"],  # Dual refresh mechanism
    cli_group="user",  # Registers `flask user <cmd>` CLI
)

with app.app_context():
  db.create_all()
```

---

## CLI Commands (`flask user ...`)

`flask-user-auth` automatically binds full CLI management to your Flask app:

```bash
# List all registered users in a clean ASCII table
flask user list [--limit 50] [--role admin] [--active]

# Create a standard user (prompts for password securely if omitted)
flask user create --email user@example.com --name "John Doe"

# Create an administrator
flask user create-admin --email admin@example.com --name "Super Admin"

# Reset a user's password (auto-revokes all their active tokens)
flask user set-password --email user@example.com

# Activate or deactivate accounts
flask user deactivate --email user@example.com
flask user activate --email user@example.com

# Delete user and cascaded credentials
flask user delete --email user@example.com [--yes]
```

---

## Route Protection Decorators

Protect routes with dual support (accepts either active session cookie OR `Authorization: Bearer <token>`):

```python
from flask_user_auth import admin_required, current_user, login_required, roles_required


# Accepts either JWT or Flask-Login session:
@app.route('/api/profile')
@login_required
def get_profile():
  return {'email': current_user.email, 'name': current_user.name}


# Role-based protection:
@app.route('/api/manager-dashboard')
@roles_required('manager', 'director')
def manager_dashboard():
  return {'status': 'authorized'}


# Admin-only:
@app.route('/api/admin/metrics')
@admin_required
def admin_metrics():
  return {'metrics': {...}}
```

---

## REST Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/register` | Register new user + auth credentials (returns tokens) |
| `POST` | `/auth/token` | Login with email & password (returns tokens + sets HTTP cookie) |
| `POST` | `/auth/refresh` | Refresh access token using cookie or body |
| `GET` | `/auth/me` | Current authenticated user profile |
| `PUT/PATCH` | `/auth/me` | Update current user profile fields |
| `POST` | `/auth/change-password` | Update password and invalidate older tokens |
| `POST` | `/auth/session/login` | Session login (Flask-Login cookie) |
| `POST/GET`| `/auth/session/logout`| Session logout & cookie cleanup |
| `GET` | `/auth/session/me` | Current session status |
| `CRUD` | `/users` | Full pagination/filter/search CRUD via `flask-api-builder` |

---

## License

MIT