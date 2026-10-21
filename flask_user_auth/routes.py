from flask import Blueprint, current_app, g, jsonify, make_response, request
from flask_login import (
    current_user as flask_login_current_user,
    login_user,
    logout_user,
)

from .decorators import auth_required, current_user
from .tokens import TokenError


def create_auth_blueprint(auth, name='flask_user_auth', url_prefix=None):
    """Create and configure the authentication Blueprint (`/login`, `/logout`, `/refresh`, `/me`)."""
    bp = Blueprint(name, __name__, url_prefix=url_prefix)

    @bp.route('/login', methods=['POST'])
    def login():
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json(silent=True) or {}
        identity_field = current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        identity = data.get(identity_field)
        password = data.get('password')

        if not identity or not password:
            return jsonify({
                'message': f'{identity_field} and password are required',
            }), 400

        has_session_key = 'session' in data
        has_token_key = 'token' in data

        if not has_session_key and not has_token_key:
            if current_app.config.get('AUTH_REQUIRE_MECHANISM_CHOICE', False):
                return jsonify({
                    'message': "Specify 'session' and/or 'token' boolean in request data",
                }), 400
            want_session = bool(auth.use_session)
            want_token = bool(auth.use_token)
        else:
            want_session = bool(data.get('session', False))
            want_token = bool(data.get('token', False))

        if not want_session and not want_token:
            return jsonify({
                'message': "At least one auth mechanism ('session' or 'token') must be true",
            }), 400

        if want_session and not auth.use_session:
            return jsonify({
                'message': 'Session authentication is not enabled on this server',
            }), 400

        if want_token and not auth.use_token:
            return jsonify({
                'message': 'Token authentication is not enabled on this server',
            }), 400

        user = auth.authenticate(identity, password)
        if user is None:
            return jsonify({'message': 'Invalid credentials'}), 401

        if not getattr(user, 'is_active', True):
            return jsonify({'message': 'Account is inactive'}), 403

        if want_session:
            remember = bool(data.get('remember', False))
            login_user(user, remember=remember)

        g.current_user = user

        payload = {
            'message': 'Login successful',
            'user': auth.serialize_user(user),
            'session': want_session,
            'token': want_token,
        }

        refresh_token = None
        if want_token:
            user_id = auth.get_user_identity(user)
            access_token = auth.jwt.create_access_token(user_id)
            refresh_token = auth.jwt.create_refresh_token(user_id)
            expires_in = int(auth.jwt.access_expires_delta().total_seconds())
            payload.update({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': current_app.config.get('JWT_HEADER_TYPE', 'Bearer'),
                'expires_in': expires_in,
            })

        response = make_response(jsonify(payload), 200)
        if want_token and refresh_token is not None:
            auth.jwt.set_refresh_cookie(response, refresh_token)
        return response

    @bp.route('/logout', methods=['POST'])
    def logout():
        data = request.get_json(silent=True) if request.is_json else {}
        data = data or {}

        # Logout Flask-Login session if enabled
        if auth.use_session:
            try:
                if getattr(flask_login_current_user, 'is_authenticated', False):
                    logout_user()
            except Exception:
                pass

        # Revoke active Bearer access token and/or refresh token if enabled
        if auth.use_token:
            bearer = auth.jwt.extract_bearer_token()
            if bearer:
                try:
                    access_payload = auth.jwt.decode_token(bearer)
                    auth.jwt.revoke_payload(access_payload)
                except TokenError:
                    pass

            raw_refresh = auth.jwt.extract_refresh_token(data=data)
            if raw_refresh:
                try:
                    refresh_payload = auth.jwt.decode_token(raw_refresh)
                    auth.jwt.revoke_payload(refresh_payload)
                except TokenError:
                    pass

        g.current_user = None
        response = make_response(
            jsonify({'message': 'Logged out successfully'}), 200
        )
        if auth.use_token:
            auth.jwt.clear_refresh_cookie(response)
        return response

    @bp.route('/refresh', methods=['POST'])
    def refresh():
        if not auth.use_token:
            return jsonify({
                'message': 'Token authentication is not enabled on this server',
            }), 400

        data = request.get_json(silent=True) if request.is_json else {}
        raw_refresh = auth.jwt.extract_refresh_token(data=data)
        if not raw_refresh:
            return jsonify({'message': 'Refresh token is required'}), 401

        try:
            payload = auth.jwt.decode_token(raw_refresh, expected_type='refresh')
        except TokenError as err:
            return jsonify({'message': err.message}), err.status_code

        user = auth.load_user(payload.get('sub'))
        if user is None:
            return jsonify({'message': 'User not found'}), 401

        if not getattr(user, 'is_active', True):
            return jsonify({'message': 'Account is inactive'}), 403

        user_id = auth.get_user_identity(user)
        access_token = auth.jwt.create_access_token(user_id)
        expires_in = int(auth.jwt.access_expires_delta().total_seconds())

        body = {
            'access_token': access_token,
            'token_type': current_app.config.get('JWT_HEADER_TYPE', 'Bearer'),
            'expires_in': expires_in,
            'user': auth.serialize_user(user),
        }

        new_refresh_token = None
        if current_app.config.get('JWT_ROTATE_REFRESH_TOKENS', False):
            auth.jwt.revoke_payload(payload)
            new_refresh_token = auth.jwt.create_refresh_token(user_id)
            body['refresh_token'] = new_refresh_token

        response = make_response(jsonify(body), 200)
        if new_refresh_token is not None:
            auth.jwt.set_refresh_cookie(response, new_refresh_token)
        return response

    @bp.route('/me', methods=['GET'])
    @auth_required(auth_ext=auth)
    def me():
        user = current_user._get_current_object()
        return jsonify({
            'user': auth.serialize_user(user),
            'auth_method': getattr(g, 'auth_method', None),
        }), 200

    return bp
