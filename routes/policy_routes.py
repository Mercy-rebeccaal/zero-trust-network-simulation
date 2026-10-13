from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required, role_required
from models import db, Policy, Role, Resource, AuditLog

policy_bp = Blueprint('policy', __name__)

@policy_bp.route('/policies')
@login_required
@role_required(['Administrator'])
def index():
    policies = Policy.query.order_by(Policy.id.asc()).all()
    roles = Role.query.order_by(Role.id.asc()).all()
    resources = Resource.query.filter_by(is_active=True).all()
    return render_template(
        'policies.html',
        policies=policies,
        roles=roles,
        resources=resources
    )

@policy_bp.route('/api/policies', methods=['GET'])
@login_required
@role_required(['Administrator'])
def api_list_policies():
    policies = Policy.query.order_by(Policy.id.asc()).all()
    return jsonify({'success': True, 'policies': [p.to_dict() for p in policies]})

@policy_bp.route('/api/policies', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_create_policy():
    data = request.get_json(silent=True) or request.form
    role_id = data.get('role_id')
    resource_id = data.get('resource_id')
    ops = data.get('allowed_operations', 'READ')
    min_trust = float(data.get('min_trust_score', 60.0))
    require_mfa = bool(data.get('require_mfa', False))
    notes = data.get('restriction_notes', '')

    if not role_id or not resource_id:
        return jsonify({'success': False, 'error': 'Role ID and Resource ID are required.'}), 400

    existing = Policy.query.filter_by(role_id=int(role_id), resource_id=int(resource_id)).first()
    if existing:
        # Update existing
        existing.allowed_operations = ops
        existing.min_trust_score = min_trust
        existing.require_mfa = require_mfa
        existing.restriction_notes = notes
        existing.is_active = True
        policy = existing
        action_name = 'UPDATE_POLICY'
    else:
        policy = Policy(
            role_id=int(role_id),
            resource_id=int(resource_id),
            allowed_operations=ops,
            min_trust_score=min_trust,
            require_mfa=require_mfa,
            restriction_notes=notes,
            is_active=True
        )
        db.session.add(policy)
        action_name = 'CREATE_POLICY'

    db.session.flush()

    audit = AuditLog(
        event_type='POLICY_MODIFICATION',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        resource_code=policy.resource.code if policy.resource else None,
        action=action_name,
        status='SUCCESS',
        reason=f"{action_name} for Role {policy.role.name} on Resource {policy.resource.code} (Ops: {ops}, Min Trust: {min_trust:.1f})."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'policy': policy.to_dict()})

@policy_bp.route('/api/policies/<int:policy_id>', methods=['PATCH'])
@login_required
@role_required(['Administrator'])
def api_update_policy(policy_id):
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({'success': False, 'error': 'Policy not found.'}), 404

    data = request.get_json(silent=True) or request.form
    if 'allowed_operations' in data:
        policy.allowed_operations = data['allowed_operations']
    if 'min_trust_score' in data:
        policy.min_trust_score = float(data['min_trust_score'])
    if 'require_mfa' in data:
        policy.require_mfa = bool(data['require_mfa'])
    if 'is_active' in data:
        policy.is_active = bool(data['is_active'])
    if 'restriction_notes' in data:
        policy.restriction_notes = data['restriction_notes']

    audit = AuditLog(
        event_type='POLICY_MODIFICATION',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        resource_code=policy.resource.code if policy.resource else None,
        action='UPDATE_POLICY',
        status='SUCCESS',
        reason=f"Updated policy #{policy.id} ({policy.role.name} -> {policy.resource.code})."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'policy': policy.to_dict()})

@policy_bp.route('/api/policies/<int:policy_id>', methods=['DELETE'])
@login_required
@role_required(['Administrator'])
def api_delete_policy(policy_id):
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({'success': False, 'error': 'Policy not found.'}), 404

    res_code = policy.resource.code if policy.resource else None
    role_name = policy.role.name if policy.role else None

    db.session.delete(policy)

    audit = AuditLog(
        event_type='POLICY_MODIFICATION',
        actor_id=session.get('user_id'),
        actor_username=session.get('username', 'ADMIN'),
        resource_code=res_code,
        action='DELETE_POLICY',
        status='SUCCESS',
        reason=f"Deleted access policy for Role {role_name} on Resource {res_code}."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Policy deleted successfully.'})
