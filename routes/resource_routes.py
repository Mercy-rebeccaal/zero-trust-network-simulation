from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required, role_required
from models import db, Resource, AuditLog

resource_bp = Blueprint('resource', __name__)

@resource_bp.route('/resources')
@login_required
def index():
    resources = Resource.query.order_by(Resource.id.asc()).all()
    return render_template('resources.html', resources=resources)

@resource_bp.route('/api/resources', methods=['GET'])
@login_required
def api_list_resources():
    resources = Resource.query.order_by(Resource.id.asc()).all()
    return jsonify({'success': True, 'resources': [r.to_dict() for r in resources]})

@resource_bp.route('/api/resources', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_create_resource():
    data = request.get_json(silent=True) or request.form
    code = data.get('code', '').strip().upper()
    name = data.get('name', '').strip()
    category = data.get('category', 'Corporate').strip()
    sensitivity = int(data.get('sensitivity_level', 2))
    subnet = data.get('subnet_segment', '10.0.5.0/24')
    desc = data.get('description', '')

    if not code or not name:
        return jsonify({'success': False, 'error': 'Resource code and name are required.'}), 400

    if Resource.query.filter_by(code=code).first():
        return jsonify({'success': False, 'error': f"Resource with code '{code}' already exists."}), 400

    res = Resource(
        code=code,
        name=name,
        category=category,
        sensitivity_level=sensitivity,
        subnet_segment=subnet,
        description=desc,
        is_active=True
    )
    db.session.add(res)
    
    audit = AuditLog(
        event_type='RESOURCE_CREATED',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        resource_code=code,
        action='CREATE_RESOURCE',
        status='SUCCESS',
        reason=f"Created resource '{code}' ({name}) with sensitivity level {sensitivity}."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'resource': res.to_dict()})

@resource_bp.route('/api/resources/<int:resource_id>', methods=['PATCH'])
@login_required
@role_required(['Administrator'])
def api_update_resource(resource_id):
    res = Resource.query.get(resource_id)
    if not res:
        return jsonify({'success': False, 'error': 'Resource not found.'}), 404

    data = request.get_json(silent=True) or request.form
    if 'name' in data:
        res.name = data['name'].strip()
    if 'sensitivity_level' in data:
        res.sensitivity_level = int(data['sensitivity_level'])
    if 'is_active' in data:
        res.is_active = bool(data['is_active'])
    if 'description' in data:
        res.description = data['description']

    audit = AuditLog(
        event_type='RESOURCE_UPDATED',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        resource_code=res.code,
        action='UPDATE_RESOURCE',
        status='SUCCESS',
        reason=f"Updated configuration for resource '{res.code}'."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'resource': res.to_dict()})
