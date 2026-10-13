import uuid
from datetime import datetime
from models import db

class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_code = db.Column(db.String(36), unique=True, default=lambda: f"ALT-{uuid.uuid4().hex[:10].upper()}", index=True)
    alert_type = db.Column(db.String(80), nullable=False) # e.g. BRUTE_FORCE_SUSPECTED, ANOMALOUS_OFF_HOURS, REPEATED_RBAC_VIOLATION
    severity = db.Column(db.String(20), nullable=False, default='MEDIUM') # LOW, MEDIUM, HIGH, CRITICAL
    
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(45), default='127.0.0.1')
    
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'alert_code': self.alert_code,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'is_resolved': self.is_resolved,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        return f"<SecurityAlert {self.alert_code}: [{self.severity}] {self.title}>"
