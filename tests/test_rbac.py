"""
Role-Based Access Control (RBAC) Engine Tests
"""

import pytest
from security.rbac import evaluate_rbac
from security.decision_engine import evaluate_access_request, DECISION_BLOCK
from models import User, Resource

def test_admin_permitted_access(app):
    with app.app_context():
        allowed, reason, policy = evaluate_rbac('Administrator', 'SERVER', 'ADMIN')
        assert allowed is True
        assert "authorized" in reason.lower()

def test_employee_unauthorized_server_access(app):
    with app.app_context():
        # Employee has no policy for SERVER
        allowed, reason, policy = evaluate_rbac('Employee', 'SERVER', 'READ')
        assert allowed is False
        assert "no active access policy" in reason

def test_manager_unauthorized_server_access(app):
    with app.app_context():
        allowed, reason, policy = evaluate_rbac('Manager', 'SERVER', 'READ')
        assert allowed is False

def test_employee_permitted_records_read(app):
    with app.app_context():
        allowed, reason, policy = evaluate_rbac('Employee', 'EMPLOYEE_RECORDS', 'READ')
        assert allowed is True

def test_employee_disallowed_operation(app):
    with app.app_context():
        # Employee is allowed READ on EMPLOYEE_RECORDS, but NOT ADMIN
        allowed, reason, policy = evaluate_rbac('Employee', 'EMPLOYEE_RECORDS', 'ADMIN')
        assert allowed is False
        assert "disallowed" in reason

def test_high_trust_score_cannot_override_rbac_denial(app):
    with app.app_context():
        emp = User.query.filter_by(username='employee').first()
        server_res = Resource.query.filter_by(code='SERVER').first()
        
        # Even with pristine 100% factors yielding 100.0 trust score:
        sim_inputs = {
            'identity': 'VERIFIED_MFA',
            'device': 'MANAGED_COMPLIANT',
            'context': 'BUSINESS_HOURS',
            'behaviour': 'NORMAL_FREQUENCY',
            'resource_safety': 100.0,
            'history': 'HIGH_COMPLIANCE',
            'threat': 'CLEAN'
        }
        
        eval_result = evaluate_access_request(
            user_id=emp.id,
            resource_id_or_code=server_res.code,
            operation='READ',
            simulated_inputs=sim_inputs
        )

        # MUST BE BLOCKED BY RBAC!
        assert eval_result['rbac_result'] == 'FAIL'
        assert eval_result['decision'] == DECISION_BLOCK
        assert "RBAC" in eval_result['decision_reason']
