"""
ZERO//TRUST Unified Decision Engine
===================================
Orchestrates the 12-step Zero Trust verification pipeline:
Session -> User & Role -> RBAC -> IACTE -> Policy Matrix -> Adaptive Enforcement -> Audit Trail.
"""

import json
from typing import Dict, Any, Optional
from models import db, User, Resource, AccessRequest, TrustEvaluation, AuditLog, SecurityAlert
from security.iacte import calculate_iacte_trust_score
from security.rbac import evaluate_rbac
from security.policy_engine import evaluate_resource_policy

# Decision Constants
DECISION_ALLOW = 'ALLOW'
DECISION_ADDITIONAL_VERIFICATION = 'ADDITIONAL_VERIFICATION'
DECISION_RESTRICT = 'RESTRICT'
DECISION_BLOCK = 'BLOCK'

def evaluate_access_request(
    user_id: int,
    resource_id_or_code: Any,
    operation: str = 'READ',
    simulated_inputs: Optional[Dict[str, Any]] = None,
    is_mfa_verified: bool = False,
    ip_address: str = '127.0.0.1',
    persist_records: bool = True
) -> Dict[str, Any]:
    """
    Executes the authoritative Zero Trust access evaluation pipeline.
    
    Returns structured result for API and frontend display.
    """
    if simulated_inputs is None:
        simulated_inputs = {}

    # 1. Validate user and session
    user = db.session.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active or user.is_locked():
        reason = "Account is inactive, locked, or user session could not be verified."
        return {
            'success': False,
            'decision': DECISION_BLOCK,
            'rbac_result': 'FAIL',
            'trust_score': 0.0,
            'reason': reason,
            'request_uuid': None
        }

    # 2. Retrieve resource
    if isinstance(resource_id_or_code, int):
        resource = Resource.query.get(resource_id_or_code)
    else:
        resource = Resource.query.filter_by(code=str(resource_id_or_code).upper()).first()

    if not resource or not resource.is_active:
        return {
            'success': False,
            'decision': DECISION_BLOCK,
            'rbac_result': 'FAIL',
            'trust_score': 0.0,
            'reason': f"Resource '{resource_id_or_code}' is invalid or currently inactive.",
            'request_uuid': None
        }

    # 3. Check RBAC (Gate 1)
    user_role_name = user.role.name if user.role else 'None'
    is_rbac_allowed, rbac_reason, matching_policy = evaluate_rbac(
        user_role_name=user_role_name,
        resource_code=resource.code,
        operation=operation,
        role_id=user.role_id,
        resource_id=resource.id
    )

    # 4. Extract simulated inputs for IACTE
    device_input = simulated_inputs.get('device', 'MANAGED_COMPLIANT')
    time_input = simulated_inputs.get('time', 'BUSINESS_HOURS')
    location_input = simulated_inputs.get('location', 'CORP_HQ')
    behaviour_input = simulated_inputs.get('behaviour', 'NORMAL_FREQUENCY')
    threat_input = simulated_inputs.get('threat', 'CLEAN')
    identity_input = 'VERIFIED_MFA' if is_mfa_verified else simulated_inputs.get('identity', 'VALID_SESSION')
    history_input = simulated_inputs.get('history', 'NORMAL')

    # Convert context into single or blended score
    context_input = simulated_inputs.get('context', time_input)

    # Inherent resource safety score according to sensitivity
    resource_safety_input = simulated_inputs.get('resource_safety', resource.sensitivity_level)

    # 5. Calculate IACTE trust score
    iacte_result = calculate_iacte_trust_score(
        identity=identity_input,
        device=device_input,
        context=context_input,
        behaviour=behaviour_input,
        resource_safety=resource_safety_input,
        historical_trust=history_input,
        threat_safety=threat_input
    )

    trust_score = iacte_result['score']
    rounded_trust_score = iacte_result['rounded_score']

    # 6. Evaluate Decision Logic
    # CRITICAL RULE: If RBAC fails, the decision is ALWAYS BLOCK regardless of trust score!
    if not is_rbac_allowed:
        final_decision = DECISION_BLOCK
        final_reason = f"Access Denied by RBAC: {rbac_reason}"
        rbac_status = 'FAIL'
    else:
        rbac_status = 'PASS'
        
        # Evaluate Adaptive Thresholds
        # - Score < 60.00: BLOCK
        # - 60.00 <= Score <= 80.00: ADDITIONAL_VERIFICATION or RESTRICT
        # - Score > 80.00: ALLOW (if mandatory policies pass)
        
        # Policy engine evaluates restrictions and MFA
        policy_eval = evaluate_resource_policy(
            policy=matching_policy,
            resource=resource,
            trust_score=trust_score,
            operation=operation,
            is_mfa_verified=is_mfa_verified
        )

        # Mandatory Security Defenses: Active malicious threat vector or brute force bursts
        if iacte_result['factor_scores']['threat_safety'] <= 10.0:
            final_decision = DECISION_BLOCK
            final_reason = f"Access Blocked by Threat Intelligence Policy: Request source flagged as known malicious indicator ({threat_input})."
        elif iacte_result['factor_scores']['behaviour'] <= 10.0:
            final_decision = DECISION_BLOCK
            final_reason = f"Access Blocked by Behavioral Security Policy: Severe query burst / brute-force pattern detected ({behaviour_input})."
        elif iacte_result['factor_scores']['device'] == 0.0:
            final_decision = DECISION_BLOCK
            final_reason = f"Access Blocked by Endpoint Policy: Device integrity is severely compromised ({device_input})."
        elif not policy_eval['is_policy_compliant']:
            final_decision = DECISION_BLOCK
            final_reason = f"Access Blocked by Policy Engine: {policy_eval['notes']}"
        elif trust_score < 60.00:
            final_decision = DECISION_BLOCK
            final_reason = f"Access Blocked: Trust score ({rounded_trust_score:.2f}) is below minimum allowable threshold (60.00). {iacte_result['explanation']}"
        elif 60.00 <= trust_score <= 80.00:
            if policy_eval.get('is_restricted'):
                final_decision = DECISION_RESTRICT
                final_reason = f"Provisional Access: {policy_eval['notes']} Trust score is {rounded_trust_score:.2f}."
            elif not is_mfa_verified:
                final_decision = DECISION_ADDITIONAL_VERIFICATION
                final_reason = f"Additional Verification Required: Trust score ({rounded_trust_score:.2f}) falls within adaptive challenge zone (60.00 - 80.00). Multi-factor challenge triggered."
            else:
                final_decision = DECISION_ALLOW
                final_reason = f"Access Granted with Verified MFA: Trust score is {rounded_trust_score:.2f}."
        else: # trust_score > 80.00
            if policy_eval.get('requires_mfa') and not is_mfa_verified:
                final_decision = DECISION_ADDITIONAL_VERIFICATION
                final_reason = f"Mandatory Step-Up Required: {policy_eval['notes']}"
            else:
                final_decision = DECISION_ALLOW
                final_reason = f"Access Granted: Trust score ({rounded_trust_score:.2f}) exceeds high-trust threshold (>80.00). Least-privilege session established."

    # 7. Persist records if requested
    request_obj = None
    if persist_records:
        request_obj = AccessRequest(
            user_id=user.id,
            resource_id=resource.id,
            operation=operation.upper(),
            simulated_device_state=str(device_input),
            simulated_time_state=str(time_input),
            simulated_location_state=str(location_input),
            simulated_behavior_state=str(behaviour_input),
            simulated_threat_state=str(threat_input),
            rbac_result=rbac_status,
            trust_score=rounded_trust_score,
            decision=final_decision,
            decision_reason=final_reason,
            is_verified_mfa=is_mfa_verified
        )
        db.session.add(request_obj)
        db.session.flush() # obtain id

        # Persist Trust Evaluation breakdown
        trust_eval_obj = TrustEvaluation(
            access_request_id=request_obj.id,
            identity_score=iacte_result['factor_scores']['identity'],
            device_score=iacte_result['factor_scores']['device'],
            context_score=iacte_result['factor_scores']['context'],
            behavior_score=iacte_result['factor_scores']['behaviour'],
            resource_safety_score=iacte_result['factor_scores']['resource_safety'],
            history_score=iacte_result['factor_scores']['historical_trust'],
            threat_safety_score=iacte_result['factor_scores']['threat_safety'],
            raw_trust_score=trust_score,
            final_trust_score=rounded_trust_score,
            factor_breakdown_json=json.dumps({
                'contributions': iacte_result['contributions'],
                'weights': iacte_result['weights'],
                'explanation': iacte_result['explanation']
            })
        )
        db.session.add(trust_eval_obj)

        # Audit Log Event
        audit_status = 'SUCCESS' if final_decision == DECISION_ALLOW else ('WARNING' if final_decision == DECISION_ADDITIONAL_VERIFICATION else 'BLOCKED')
        audit_event = AuditLog(
            event_type='ACCESS_EVALUATION',
            actor_id=user.id,
            actor_username=user.username,
            resource_code=resource.code,
            action=f"REQUEST_{operation.upper()}",
            status=audit_status,
            trust_score=rounded_trust_score,
            decision=final_decision,
            reason=final_reason,
            ip_address=ip_address,
            details_json=json.dumps({
                'request_uuid': request_obj.request_uuid,
                'rbac_result': rbac_status,
                'device_state': str(device_input),
                'threat_state': str(threat_input)
            })
        )
        db.session.add(audit_event)

        # Raise SecurityAlert if low trust / brute force / malicious
        if final_decision == DECISION_BLOCK and (trust_score < 40.0 or str(threat_input) in ('KNOWN_TOR_EXIT_NODE', 'KNOWN_BOTNET_OR_MALICIOUS')):
            alert = SecurityAlert(
                alert_type='CRITICAL_ACCESS_ANOMALY',
                severity='HIGH' if trust_score >= 20.0 else 'CRITICAL',
                title=f"Blocked High-Risk Request to {resource.code} by {user.username}",
                description=f"Request blocked due to severe trust degradation (Score: {rounded_trust_score:.2f}). Reason: {final_reason}",
                source_ip=ip_address
            )
            db.session.add(alert)

        db.session.commit()

    return {
        'success': True,
        'request_id': request_obj.id if request_obj else None,
        'request_uuid': request_obj.request_uuid if request_obj else 'PREVIEW-SIM',
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user_role_name
        },
        'resource': {
            'id': resource.id,
            'code': resource.code,
            'name': resource.name,
            'category': resource.category,
            'sensitivity': resource.sensitivity_name,
            'subnet': resource.subnet_segment
        },
        'operation': operation.upper(),
        'rbac_result': rbac_status,
        'rbac_reason': rbac_reason,
        'trust_score': rounded_trust_score,
        'raw_trust_score': trust_score,
        'decision': final_decision,
        'decision_reason': final_reason,
        'is_verified_mfa': is_mfa_verified,
        'factor_scores': iacte_result['factor_scores'],
        'contributions': iacte_result['contributions'],
        'weights': iacte_result['weights'],
        'explanation': iacte_result['explanation']
    }
