from datetime import datetime
from models import db

class Policy(db.Model):
    __tablename__ = 'policies'

    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    
    # Comma-separated or structured operations: READ, WRITE, EXECUTE, ADMIN
    allowed_operations = db.Column(db.String(120), nullable=False, default='READ')
    
    # Minimum trust score required to even be considered for access
    min_trust_score = db.Column(db.Float, default=60.0, nullable=False)
    require_mfa = db.Column(db.Boolean, default=False)
    restriction_notes = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    role = db.relationship('Role', back_populates='policies')
    resource = db.relationship('Resource', back_populates='policies')

    # Unique constraint per role and resource
    __table_args__ = (
        db.UniqueConstraint('role_id', 'resource_id', name='uq_role_resource_policy'),
    )

    def allows_operation(self, op: str) -> bool:
        if not self.is_active or not self.allowed_operations:
            return False
        allowed_list = [x.strip().upper() for x in self.allowed_operations.split(',')]
        op_upper = op.strip().upper()
        return ('ALL' in allowed_list) or ('ADMIN' in allowed_list and op_upper != 'SUPER') or (op_upper in allowed_list)

    def to_dict(self):
        return {
            'id': self.id,
            'role_id': self.role_id,
            'role_name': self.role.name if self.role else None,
            'resource_id': self.resource_id,
            'resource_code': self.resource.code if self.resource else None,
            'resource_name': self.resource.name if self.resource else None,
            'allowed_operations': [x.strip() for x in self.allowed_operations.split(',')],
            'allowed_operations_str': self.allowed_operations,
            'min_trust_score': self.min_trust_score,
            'require_mfa': self.require_mfa,
            'restriction_notes': self.restriction_notes,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f"<Policy Role={self.role.name if self.role else self.role_id} -> Res={self.resource.code if self.resource else self.resource_id}>"
