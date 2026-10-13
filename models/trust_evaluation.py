import json
from datetime import datetime
from models import db

class TrustEvaluation(db.Model):
    __tablename__ = 'trust_evaluations'

    id = db.Column(db.Integer, primary_key=True)
    access_request_id = db.Column(db.Integer, db.ForeignKey('access_requests.id'), unique=True, nullable=False, index=True)
    
    # 7 IACTE factors (each normalized 0.0 to 100.0)
    identity_score = db.Column(db.Float, nullable=False)        # weight 0.20
    device_score = db.Column(db.Float, nullable=False)          # weight 0.15
    context_score = db.Column(db.Float, nullable=False)         # weight 0.15
    behavior_score = db.Column(db.Float, nullable=False)        # weight 0.15
    resource_safety_score = db.Column(db.Float, nullable=False) # weight 0.10
    history_score = db.Column(db.Float, nullable=False)         # weight 0.15
    threat_safety_score = db.Column(db.Float, nullable=False)   # weight 0.10
    
    raw_trust_score = db.Column(db.Float, nullable=False)
    final_trust_score = db.Column(db.Float, nullable=False)
    factor_breakdown_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    access_request = db.relationship('AccessRequest', back_populates='trust_evaluation')

    def to_dict(self):
        breakdown = {}
        if self.factor_breakdown_json:
            try:
                breakdown = json.loads(self.factor_breakdown_json)
            except Exception:
                pass
        
        return {
            'id': self.id,
            'access_request_id': self.access_request_id,
            'identity_score': round(self.identity_score, 2),
            'device_score': round(self.device_score, 2),
            'context_score': round(self.context_score, 2),
            'behavior_score': round(self.behavior_score, 2),
            'resource_safety_score': round(self.resource_safety_score, 2),
            'history_score': round(self.history_score, 2),
            'threat_safety_score': round(self.threat_safety_score, 2),
            'final_trust_score': round(self.final_trust_score, 2),
            'contributions': breakdown.get('contributions', {}),
            'weights': breakdown.get('weights', {}),
            'explanation': breakdown.get('explanation', '')
        }

    def __repr__(self):
        return f"<TrustEvaluation for Req {self.access_request_id}: Score={self.final_trust_score}>"
