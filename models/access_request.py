import uuid
from datetime import datetime
from models import db

class AccessRequest(db.Model):
    __tablename__ = 'access_requests'

    id = db.Column(db.Integer, primary_key=True)
    request_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False, index=True)
    
    operation = db.Column(db.String(50), nullable=False, default='READ')
    
    # Simulated input states for reproducibility
    simulated_device_state = db.Column(db.String(50), default='MANAGED_COMPLIANT')
    simulated_time_state = db.Column(db.String(50), default='BUSINESS_HOURS')
    simulated_location_state = db.Column(db.String(50), default='CORP_HQ')
    simulated_behavior_state = db.Column(db.String(50), default='NORMAL_FREQUENCY')
    simulated_threat_state = db.Column(db.String(50), default='CLEAN')
    
    # Decisions & Outcomes
    rbac_result = db.Column(db.String(20), nullable=False) # PASS or FAIL
    trust_score = db.Column(db.Float, nullable=False)
    decision = db.Column(db.String(30), nullable=False, index=True) # ALLOW, ADDITIONAL_VERIFICATION, RESTRICT, BLOCK
    decision_reason = db.Column(db.Text, nullable=False)
    is_verified_mfa = db.Column(db.Boolean, default=False)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = db.relationship('User', back_populates='access_requests')
    resource = db.relationship('Resource', back_populates='access_requests')
    trust_evaluation = db.relationship('TrustEvaluation', back_populates='access_request', uselist=False, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'request_uuid': self.request_uuid,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'role_name': self.user.role.name if (self.user and self.user.role) else None,
            'resource_id': self.resource_id,
            'resource_code': self.resource.code if self.resource else None,
            'resource_name': self.resource.name if self.resource else None,
            'operation': self.operation,
            'simulated_device_state': self.simulated_device_state,
            'simulated_time_state': self.simulated_time_state,
            'simulated_location_state': self.simulated_location_state,
            'simulated_behavior_state': self.simulated_behavior_state,
            'simulated_threat_state': self.simulated_threat_state,
            'rbac_result': self.rbac_result,
            'trust_score': round(self.trust_score, 2),
            'decision': self.decision,
            'decision_reason': self.decision_reason,
            'is_verified_mfa': self.is_verified_mfa,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'factor_breakdown': self.trust_evaluation.to_dict() if self.trust_evaluation else None
        }

    def __repr__(self):
        return f"<AccessRequest {self.request_uuid} -> {self.decision}>"
