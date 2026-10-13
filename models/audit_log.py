import json
import uuid
from datetime import datetime
from models import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: f"EVT-{uuid.uuid4().hex[:12].upper()}", index=True)
    event_type = db.Column(db.String(60), nullable=False, index=True)
    
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    actor_username = db.Column(db.String(80), nullable=False, default='SYSTEM')
    
    resource_code = db.Column(db.String(50), nullable=True, index=True)
    action = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(30), nullable=False, default='INFO') # SUCCESS, DENIED, WARNING, BLOCKED, INFO
    
    trust_score = db.Column(db.Float, nullable=True)
    decision = db.Column(db.String(40), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), default='127.0.0.1')
    
    details_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationship
    actor = db.relationship('User')

    def get_details(self):
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'event_type': self.event_type,
            'actor_id': self.actor_id,
            'actor_username': self.actor_username,
            'resource_code': self.resource_code,
            'action': self.action,
            'status': self.status,
            'trust_score': round(self.trust_score, 2) if self.trust_score is not None else None,
            'decision': self.decision,
            'reason': self.reason,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'details': self.get_details()
        }

    def __repr__(self):
        return f"<AuditLog {self.event_id}: {self.event_type} - {self.status}>"
