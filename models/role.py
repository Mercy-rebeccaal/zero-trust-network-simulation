from datetime import datetime
from models import db

class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=True)
    is_system = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', back_populates='role', lazy='dynamic')
    policies = db.relationship('Policy', back_populates='role', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_count': self.users.count() if hasattr(self.users, 'count') else 0
        }

    def __repr__(self):
        return f"<Role {self.name}>"
