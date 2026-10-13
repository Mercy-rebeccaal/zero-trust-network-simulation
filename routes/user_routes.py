from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required, role_required
from models import db, User, Role, AuditLog

user_bp = Blueprint('user', __name__)

@user_bp.route('/users')
@login_required
@role_required(['Administrator'])
def index():
    users = User.query.order_by(User.id.asc()).all()
    roles = Role.query.order_by(Role.id.asc()).all()
    return render_template('users.html', users=users, roles=roles)

@user_bp.route('/api/users', methods=['GET'])
@login_required
@role_required(['Administrator'])
def api_list_users():
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({'success': True, 'users': [u.to_dict() for u in users]})

@user_bp.route('/api/users', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_create_user():
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    dept = data.get('department', 'Operations').strip()
    role_id = data.get('role_id')

    if not username or not email or not password or not role_id:
        return jsonify({'success': False, 'error': 'All mandatory fields (username, email, password, role) must be provided.'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'success': False, 'error': 'A user with this username or email already exists.'}), 400

    user = User(
        username=username,
        email=email,
        full_name=full_name or username,
        department=dept,
        role_id=int(role_id),
        is_active=True
    )
    user.set_password(password)
    db.session.add(user)
    db.session.flush()

    # Audit log
    audit = AuditLog(
        event_type='USER_MANAGEMENT_CREATE',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        action='CREATE_USER',
        status='SUCCESS',
        reason=f"Created user '{username}' with role ID {role_id}."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'user': user.to_dict()})

@user_bp.route('/api/users/<int:user_id>', methods=['PATCH'])
@login_required
@role_required(['Administrator'])
def api_update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    data = request.get_json(silent=True) or request.form

    # Check protection against deactivating the last active administrator
    is_active_input = data.get('is_active')
    if is_active_input is not None:
        target_active = bool(is_active_input)
        if not target_active and user.role and user.role.name == 'Administrator':
            admin_count = User.query.join(Role).filter(Role.name == 'Administrator', User.is_active == True).count()
            if admin_count <= 1:
                return jsonify({'success': False, 'error': 'Cannot deactivate the last remaining active Administrator.'}), 400
        user.is_active = target_active

    role_id_input = data.get('role_id')
    if role_id_input:
        user.role_id = int(role_id_input)

    dept_input = data.get('department')
    if dept_input:
        user.department = dept_input.strip()

    audit = AuditLog(
        event_type='USER_MANAGEMENT_UPDATE',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        action='UPDATE_USER',
        status='SUCCESS',
        reason=f"Updated profile or role for user '{user.username}'."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'user': user.to_dict()})

@user_bp.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_reset_password(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    data = request.get_json(silent=True) or request.form
    new_password = data.get('new_password', '')
    if not new_password or len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters long.'}), 400

    user.set_password(new_password)
    user.failed_login_attempts = 0
    user.locked_until = None

    audit = AuditLog(
        event_type='USER_MANAGEMENT_PASSWORD_RESET',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        action='RESET_PASSWORD',
        status='SUCCESS',
        reason=f"Administrative password reset performed for user '{user.username}'."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'message': f"Password for {user.username} has been securely reset."})
