"""
Decision Engine Threshold & Boundary Edge Cases Tests
"""

import pytest
from models import User, Resource
from security.decision_engine import (
    evaluate_access_request,
    DECISION_ALLOW,
    DECISION_ADDITIONAL_VERIFICATION,
    DECISION_BLOCK
)
from services.access_service import AccessService

def get_sim_factors_for_target_score(target: float):
    """Returns an identical factor dict to yield exactly `target` trust score."""
    return {
        'identity': target,
        'device': target,
        'context': target,
        'behaviour': target,
        'resource_safety': target,
        'history': target,
        'threat': target
    }

def test_boundary_59_99_results_in_block(app):
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        hr_res = Resource.query.filter_by(code='HR').first()
        
        sim = get_sim_factors_for_target_score(59.99)
        res = evaluate_access_request(
            user_id=admin.id,
            resource_id_or_code=hr_res.code,
            operation='READ',
            simulated_inputs=sim,
            persist_records=False
        )
        assert res['trust_score'] == 59.99
        assert res['decision'] == DECISION_BLOCK
        assert "below" in res['decision_reason'].lower() and "threshold" in res['decision_reason'].lower()

def test_boundary_60_00_results_in_additional_verification(app):
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        hr_res = Resource.query.filter_by(code='HR').first()
        
        sim = get_sim_factors_for_target_score(60.00)
        res = evaluate_access_request(
            user_id=admin.id,
            resource_id_or_code=hr_res.code,
            operation='READ',
            simulated_inputs=sim,
            persist_records=False
        )
        assert res['trust_score'] == 60.00
        assert res['decision'] == DECISION_ADDITIONAL_VERIFICATION

def test_boundary_80_00_results_in_additional_verification(app):
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        hr_res = Resource.query.filter_by(code='HR').first()
        
        sim = get_sim_factors_for_target_score(80.00)
        res = evaluate_access_request(
            user_id=admin.id,
            resource_id_or_code=hr_res.code,
            operation='READ',
            simulated_inputs=sim,
            persist_records=False
        )
        assert res['trust_score'] == 80.00
        assert res['decision'] == DECISION_ADDITIONAL_VERIFICATION

def test_boundary_80_01_results_in_allow(app):
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        hr_res = Resource.query.filter_by(code='HR').first()
        
        sim = get_sim_factors_for_target_score(80.01)
        res = evaluate_access_request(
            user_id=admin.id,
            resource_id_or_code=hr_res.code,
            operation='READ',
            simulated_inputs=sim,
            persist_records=False
        )
        assert res['trust_score'] == 80.01
        assert res['decision'] == DECISION_ALLOW

def test_mfa_step_up_elevation(app):
    with app.app_context():
        manager = User.query.filter_by(username='manager').first()
        hr_res = Resource.query.filter_by(code='HR').first()
        
        # 70.0 score -> ADDITIONAL_VERIFICATION
        sim = get_sim_factors_for_target_score(70.0)
        res = evaluate_access_request(
            user_id=manager.id,
            resource_id_or_code=hr_res.code,
            operation='READ',
            simulated_inputs=sim,
            persist_records=True
        )
        assert res['decision'] == DECISION_ADDITIONAL_VERIFICATION
        
        # Verify with OTP
        mfa_res = AccessService.verify_step2_mfa(
            request_uuid=res['request_uuid'],
            otp_code='739201',
            user_id=manager.id
        )
        assert mfa_res['success'] is True
        assert mfa_res['request']['decision'] == DECISION_ALLOW
        assert mfa_res['request']['is_verified_mfa'] is True
