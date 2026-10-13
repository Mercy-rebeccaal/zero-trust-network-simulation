from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required
from services.access_service import AccessService
from models import Resource, User

simulator_bp = Blueprint('simulator', __name__)

@simulator_bp.route('/simulator')
@login_required
def index():
    resources = Resource.query.filter_by(is_active=True).all()
    recent_requests = AccessService.get_recent_requests(
        user_id=session.get('user_id'),
        role_name=session.get('role_name'),
        limit=10
    )
    users = User.query.filter_by(is_active=True).all() if session.get('role_name') == 'Administrator' else []
    
    return render_template(
        'simulator.html',
        resources=resources,
        recent_requests=recent_requests,
        users=users
    )

@simulator_bp.route('/api/access/evaluate', methods=['POST'])
@login_required
def api_evaluate():
    data = request.get_json(silent=True) or request.form
    
    # Target User (Admin can simulate on behalf of another user if specified)
    current_user_id = session.get('user_id')
    user_id = current_user_id
    if session.get('role_name') == 'Administrator' and data.get('target_user_id'):
        try:
            user_id = int(data.get('target_user_id'))
        except (ValueError, TypeError):
            pass

    resource_code = data.get('resource_code', 'HR')
    operation = data.get('operation', 'READ')
    
    simulated_inputs = {
        'device': data.get('device_state', 'MANAGED_COMPLIANT'),
        'time': data.get('time_state', 'BUSINESS_HOURS'),
        'location': data.get('location_state', 'CORP_HQ'),
        'behaviour': data.get('behavior_state', 'NORMAL_FREQUENCY'),
        'threat': data.get('threat_state', 'CLEAN'),
        'history': data.get('history_state', 'NORMAL'),
        'identity': data.get('identity_state', 'VALID_SESSION'),
        'context': data.get('time_state', 'BUSINESS_HOURS')
    }

    client_ip = request.remote_addr or '127.0.0.1'
    result = AccessService.evaluate(
        user_id=user_id,
        resource_id_or_code=resource_code,
        operation=operation,
        simulated_inputs=simulated_inputs,
        is_mfa_verified=False,
        ip_address=client_ip
    )

    return jsonify(result)

@simulator_bp.route('/api/access/verify-mfa', methods=['POST'])
@login_required
def api_verify_mfa():
    data = request.get_json(silent=True) or request.form
    request_uuid = data.get('request_uuid')
    otp_code = data.get('otp_code', '')
    user_id = session.get('user_id')

    if not request_uuid or not otp_code:
        return jsonify({'success': False, 'error': 'Request UUID and OTP code are required.'}), 400

    result = AccessService.verify_step2_mfa(
        request_uuid=request_uuid,
        otp_code=otp_code,
        user_id=user_id,
        ip_address=request.remote_addr or '127.0.0.1'
    )
    return jsonify(result)

@simulator_bp.route('/api/access/requests', methods=['GET'])
@login_required
def api_requests():
    items = AccessService.get_recent_requests(
        user_id=session.get('user_id'),
        role_name=session.get('role_name'),
        limit=25
    )
    return jsonify({'success': True, 'requests': items})

@simulator_bp.route('/api/access/requests/<request_uuid>', methods=['GET'])
@login_required
def api_request_detail(request_uuid):
    item = AccessService.get_by_uuid(request_uuid)
    if not item:
        return jsonify({'success': False, 'error': 'Request not found.'}), 404
    return jsonify({'success': True, 'request': item})
