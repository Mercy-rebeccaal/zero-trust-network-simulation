from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required, role_required
from services.simulation_service import SimulationService
from models import db, AuditLog

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
@login_required
@role_required(['Administrator'])
def index():
    return render_template('settings.html')

@settings_bp.route('/api/settings/reset-demo', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_reset_demo():
    result = SimulationService.reset_runs()
    
    audit = AuditLog(
        event_type='SYSTEM_SIMULATION_RESET',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        action='RESET_SIMULATION_DATA',
        status='INFO',
        reason='Administrator cleared transient simulation run records.'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Simulation run records successfully cleared ({result['deleted_runs_count']} records removed). Baseline audit logs and policies preserved."
    })
