"""Authentication route blueprints for token and session flows."""
from datetime import datetime, timezone
from typing import Any
from flask import Blueprint, current_app, jsonify, request

from .decorators import current_user, login_required
from .tokens import (
    TokenError,
    clear_refresh_cookie,
    create_token,
    decode_token,
    extract_refresh_token,
    set_refresh_cookie,
    verify_token_not_revoked,
)


def create_auth_blueprint(extension: Any) -> Blueprint:
    """Create blueprint providing dual authentication routes."""
    bp = Blueprint("auth", __name__)

    @bp.route("/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Validation error", "message": "Email and password are required"}), 422

        if extension.find_user_by_email(email):
            return jsonify({"error": "Conflict", "message": "User with this email already exists"}), 409

        # Instantiate user:
        user_cls = extension.user_model
        user_kwargs = {"email": email}
        for col in user_cls.__table__.columns:
            if col.name in data and col.name not in ("id", "created_at", "updated_at"):
                user_kwargs[col.name] = data[col.name]

        user = user_cls(**user_kwargs)
        user.set_password(password)

        session = extension.session
        session.add(user)
        session.commit()

        # Session login if requested
        if extension.use_flask_login:
            try:
                from flask_login import login_user
                login_user(user)
            except ImportError:
                pass

        # Generate JWT tokens:
        access_token = extension.create_access_token(user)
        refresh_token = extension.create_refresh_token(user)

        response_data = {
            "message": "User registered successfully",
            "user": user.to_dict(),
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
        res = jsonify(response_data)
        if "http" in extension.refresh_type:
            set_refresh_cookie(res, refresh_token)
        return res, 201

    @bp.route("/token", methods=["POST"])
    @bp.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Validation error", "message": "Email and password are required"}), 422

        user = extension.find_user_by_email(email)
        if not user or not user.check_password(password):
            return jsonify({"error": "Unauthorized", "message": "Invalid email or password"}), 401

        if not getattr(user, "is_active", True):
            return jsonify({"error": "Forbidden", "message": "Account is inactive"}), 403

        # Update last login date
        if user.auth:
            user.auth.last_login_date = datetime.now(timezone.utc)
            extension.session.commit()

        if extension.use_flask_login:
            try:
                from flask_login import login_user
                login_user(user)
            except ImportError:
                pass

        access_token = extension.create_access_token(user)
        refresh_token = extension.create_refresh_token(user)

        res = jsonify({
            "user": user.to_dict(),
            "access_token": access_token,
            "refresh_token": refresh_token,
        })
        if "http" in extension.refresh_type:
            set_refresh_cookie(res, refresh_token)
        return res, 200

    @bp.route("/refresh", methods=["POST"])
    def refresh():
        token = extract_refresh_token(request)
        if not token:
            return jsonify({"error": "Unauthorized", "message": "Missing refresh token"}), 401

        try:
            payload = decode_token(token, extension.jwt_secret, expected_type="refresh")
        except TokenError as e:
            return jsonify({"error": "Unauthorized", "message": str(e)}), 401

        user_id = payload.get("sub")
        user = extension.get_user(int(user_id)) if user_id else None
        if not user:
            return jsonify({"error": "Unauthorized", "message": "User not found"}), 401

        try:
            verify_token_not_revoked(payload, user)
        except TokenError as e:
            return jsonify({"error": "Unauthorized", "message": str(e)}), 401

        new_access = extension.create_access_token(user)
        res = jsonify({"access_token": new_access})
        return res, 200

    @bp.route("/me", methods=["GET"])
    @login_required
    def me():
        return jsonify({"user": current_user.to_dict()}), 200

    @bp.route("/me", methods=["PUT", "PATCH"])
    @login_required
    def update_profile():
        data = request.get_json(silent=True) or {}
        # Exclude security-critical fields from profile update
        protected = {"id", "email", "password_hash", "is_admin", "created_at", "updated_at"}
        for key, value in data.items():
            if key not in protected and hasattr(current_user, key):
                setattr(current_user, key, value)
        current_user.updated_at = datetime.now(timezone.utc)
        extension.session.commit()
        return jsonify({"message": "Profile updated", "user": current_user.to_dict()}), 200

    @bp.route("/change-password", methods=["POST"])
    @login_required
    def change_password():
        data = request.get_json(silent=True) or {}
        old_password = data.get("old_password", "")
        new_password = data.get("new_password", "")

        if not old_password or not new_password:
            return jsonify({"error": "Validation error", "message": "Both old and new passwords are required"}), 422

        if not current_user.check_password(old_password):
            return jsonify({"error": "Unauthorized", "message": "Incorrect old password"}), 401

        current_user.set_password(new_password)
        extension.session.commit()

        # Invalidate existing refresh cookie if any:
        res = jsonify({"message": "Password changed successfully. Prior tokens have been revoked."})
        clear_refresh_cookie(res)
        return res, 200

    # Session-specific endpoints (Flask-Login):
    if extension.use_flask_login:
        @bp.route("/session/login", methods=["POST"])
        def session_login():
            data = request.get_json(silent=True) or {}
            email = data.get("email", "").strip().lower()
            password = data.get("password", "")
            remember = bool(data.get("remember", False))

            if not email or not password:
                return jsonify({"error": "Validation error", "message": "Email and password are required"}), 422

            user = extension.find_user_by_email(email)
            if not user or not user.check_password(password):
                return jsonify({"error": "Unauthorized", "message": "Invalid email or password"}), 401

            if not getattr(user, "is_active", True):
                return jsonify({"error": "Forbidden", "message": "Account is inactive"}), 403

            from flask_login import login_user
            login_user(user, remember=remember)

            if user.auth:
                user.auth.last_login_date = datetime.now(timezone.utc)
                extension.session.commit()

            return jsonify({"success": True, "user": user.to_dict()}), 200

        @bp.route("/session/logout", methods=["GET", "POST"])
        def session_logout():
            from flask_login import logout_user
            logout_user()
            res = jsonify({"success": True, "message": "Logged out successfully"})
            clear_refresh_cookie(res)
            return res, 200

        @bp.route("/session/me", methods=["GET"])
        def session_me():
            from flask_login import current_user as fl_user
            if not fl_user or not getattr(fl_user, "is_authenticated", False):
                return jsonify({"authenticated": False}), 401
            return jsonify({"authenticated": True, "user": fl_user.to_dict()}), 200

    return bp