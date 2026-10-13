"""
Session Security and Authorization Decorators
=============================================
Enforces session integrity, role constraints, and CSRF token validation.
"""

from functools import wraps
from flask import session, request, redirect, url_for, abort, jsonify, render_template
from models import db, User
from security.authentication import validate_csrf_token

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required. Active session not found.'
                }), 401
            return redirect(url_for('auth.login', next=request.url))
            
        user = db.session.get(User, user_id)
        if not user or not user.is_active or user.is_locked():
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'User session expired or account deactivated.'
                }), 401
            return redirect(url_for('auth.login'))

        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """
    Restricts view to specific roles. E.g., @role_required(['Administrator'])
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Unauthorized'}), 401
                return redirect(url_for('auth.login', next=request.url))

            user = db.session.get(User, user_id)
            if not user or not user.role:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Forbidden: Role not assigned'}), 403
                return render_template('errors/403.html', message="No assigned role detected."), 403

            if user.role.name not in allowed_roles:
                if request.path.startswith('/api/'):
                    return jsonify({
                        'success': False,
                        'error': f"Forbidden: Action requires one of {allowed_roles}, but current role is '{user.role.name}'."
                    }), 403
                return render_template(
                    'errors/403.html',
                    message=f"Access denied. This zone requires {', '.join(allowed_roles)} privileges."
                ), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            # Allow JSON api or form submission token
            token = (
                request.headers.get('X-CSRF-Token') or
                request.headers.get('X-CSRFToken') or
                request.form.get('csrf_token') or
                (request.is_json and request.get_json(silent=True) and request.get_json(silent=True).get('csrf_token'))
            )
            # In testing or if explicitly bypassed, allow
            if not validate_csrf_token(token):
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Invalid or missing CSRF token'}), 403
                abort(403, description="CSRF token validation failed.")
        return f(*args, **kwargs)
    return decorated_function
