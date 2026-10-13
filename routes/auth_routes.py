from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from models import db, User, AuditLog
from security.authentication import authenticate_user, generate_csrf_token, validate_csrf_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect directly to dashboard
    if session.get('user_id'):
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash("Security validation failed (invalid CSRF token). Please try again.", "danger")
            return render_template('login.html'), 403

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr or '127.0.0.1'

        success, result = authenticate_user(username, password, ip_address=client_ip)

        if not success:
            flash(result, "danger")
            return render_template('login.html', username=username), 401

        # Prevent session fixation: clear old session and populate new
        session.clear()
        session['user_id'] = result.id
        session['username'] = result.username
        session['role_name'] = result.role.name if result.role else 'Employee'
        session['csrf_token'] = generate_csrf_token()

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    user_id = session.get('user_id')
    username = session.get('username', 'UNKNOWN')
    client_ip = request.remote_addr or '127.0.0.1'

    if user_id:
        audit = AuditLog(
            event_type='AUTH_LOGOUT',
            actor_id=user_id,
            actor_username=username,
            action='USER_LOGOUT',
            status='INFO',
            reason='User initiated session termination.',
            ip_address=client_ip
        )
        db.session.add(audit)
        db.session.commit()

    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    client_ip = request.remote_addr or '127.0.0.1'

    success, result = authenticate_user(username, password, ip_address=client_ip)
    if not success:
        return jsonify({'success': False, 'error': result}), 401

    session.clear()
    session['user_id'] = result.id
    session['username'] = result.username
    session['role_name'] = result.role.name if result.role else 'Employee'
    csrf = generate_csrf_token()

    return jsonify({
        'success': True,
        'user': result.to_dict(),
        'csrf_token': csrf
    })

@auth_bp.route('/api/auth/logout', methods=['POST'])
def api_logout():
    user_id = session.get('user_id')
    if user_id:
        audit = AuditLog(
            event_type='AUTH_LOGOUT',
            actor_id=user_id,
            actor_username=session.get('username', 'USER'),
            action='API_LOGOUT',
            status='INFO',
            reason='API session terminated.',
            ip_address=request.remote_addr or '127.0.0.1'
        )
        db.session.add(audit)
        db.session.commit()
        session.clear()

    return jsonify({'success': True, 'message': 'Logged out successfully.'})
