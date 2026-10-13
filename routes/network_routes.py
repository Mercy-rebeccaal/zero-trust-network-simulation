from flask import Blueprint, render_template, jsonify
from security.session_security import login_required
from models import Resource, AccessRequest

network_bp = Blueprint('network', __name__)

@network_bp.route('/network-map')
@login_required
def index():
    resources = Resource.query.filter_by(is_active=True).all()
    return render_template('network_map.html', resources=resources)

@network_bp.route('/api/network/topology')
@login_required
def api_topology():
    resources = Resource.query.filter_by(is_active=True).all()
    
    segments = []
    for res in resources:
        recent_count = AccessRequest.query.filter_by(resource_id=res.id).count()
        last_req = AccessRequest.query.filter_by(resource_id=res.id).order_by(AccessRequest.timestamp.desc()).first()
        
        segments.append({
            'code': res.code,
            'name': res.name,
            'category': res.category,
            'sensitivity': res.sensitivity_name,
            'subnet': res.subnet_segment,
            'request_count': recent_count,
            'last_decision': last_req.decision if last_req else 'NONE',
            'status': 'SECURED_ISOLATED'
        })

    return jsonify({
        'success': True,
        'control_plane': {
            'identity_provider': 'ZERO//TRUST Identity Gateway (Port 8443)',
            'rbac_policy_gate': 'Kernel RBAC Enforcer (Strict Least-Privilege)',
            'iacte_engine': 'IACTE 7-Factor Continuous Engine (v2.6)',
            'decision_matrix': 'Adaptive Micro-segmentation Controller'
        },
        'segments': segments
    })
