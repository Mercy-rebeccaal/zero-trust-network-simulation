"""
Access Evaluation and MFA Step-up Service
=========================================
Manages request lifecycles, secondary MFA challenges, and access history.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from models import db, AccessRequest, TrustEvaluation, AuditLog, User
from security.decision_engine import evaluate_access_request, DECISION_ALLOW, DECISION_ADDITIONAL_VERIFICATION

class AccessService:
    @staticmethod
    def evaluate(
        user_id: int,
        resource_id_or_code: Any,
        operation: str = 'READ',
        simulated_inputs: Optional[Dict[str, Any]] = None,
        is_mfa_verified: bool = False,
        ip_address: str = '127.0.0.1'
    ) -> Dict[str, Any]:
        """Runs the unified decision engine and returns evaluated outcomes."""
        return evaluate_access_request(
            user_id=user_id,
            resource_id_or_code=resource_id_or_code,
            operation=operation,
            simulated_inputs=simulated_inputs,
            is_mfa_verified=is_mfa_verified,
            ip_address=ip_address,
            persist_records=True
        )

    @staticmethod
    def verify_step2_mfa(
        request_uuid: str,
        otp_code: str,
        user_id: int,
        ip_address: str = '127.0.0.1'
    ) -> Dict[str, Any]:
        """
        Processes secondary step-up verification for a request in ADDITIONAL_VERIFICATION.
        Accepts simulated 6-digit OTP codes (demonstration code: '739201' or any valid 6-digit token).
        """
        req = AccessRequest.query.filter_by(request_uuid=request_uuid).first()
        if not req:
            return {'success': False, 'error': 'Access request record not found.'}

        if req.user_id != user_id:
            # Only administrator or the requesting user can verify
            user = User.query.get(user_id)
            if not user or (user.role and user.role.name != 'Administrator'):
                return {'success': False, 'error': 'Unauthorized to verify this request.'}

        if req.decision != DECISION_ADDITIONAL_VERIFICATION:
            return {
                'success': False,
                'error': f"Request is currently in state '{req.decision}', not awaiting additional verification."
            }

        # Validate code (accept 6 digits)
        clean_code = str(otp_code).strip()
        if not clean_code.isdigit() or len(clean_code) != 6:
            return {
                'success': False,
                'error': 'Invalid verification code format. Please provide a 6-digit OTP.'
            }

        # Elevated to ALLOW
        req.is_verified_mfa = True
        req.decision = DECISION_ALLOW
        req.decision_reason = f"Access Granted: Step-Up Multi-Factor Verification verified successfully at {datetime.utcnow().strftime('%H:%M:%S UTC')}."
        
        # Log audit trail
        audit = AuditLog(
            event_type='MFA_VERIFICATION_SUCCESS',
            actor_id=user_id,
            actor_username=req.user.username if req.user else 'USER',
            resource_code=req.resource.code if req.resource else None,
            action='STEP_UP_VERIFICATION',
            status='SUCCESS',
            trust_score=req.trust_score,
            decision=DECISION_ALLOW,
            reason='MFA OTP challenge completed.',
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()

        return {
            'success': True,
            'message': 'Secondary verification successful. Access granted.',
            'request': req.to_dict()
        }

    @staticmethod
    def get_recent_requests(
        user_id: Optional[int] = None,
        role_name: Optional[str] = None,
        limit: int = 25,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        query = AccessRequest.query.order_by(AccessRequest.timestamp.desc())
        
        # Non-admins only see their own requests unless specified
        if role_name != 'Administrator' and user_id is not None:
            query = query.filter_by(user_id=user_id)

        items = query.limit(limit).offset(offset).all()
        return [item.to_dict() for item in items]

    @staticmethod
    def get_by_uuid(request_uuid: str) -> Optional[Dict[str, Any]]:
        req = AccessRequest.query.filter_by(request_uuid=request_uuid).first()
        return req.to_dict() if req else None
