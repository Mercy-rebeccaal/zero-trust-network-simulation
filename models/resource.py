from datetime import datetime
from models import db

class Resource(db.Model):
    __tablename__ = 'resources'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False, index=True) # e.g. HR, FINANCE, SERVER, EMPLOYEE_RECORDS
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=False) # e.g. Corporate, Financial, Infrastructure, Personnel
    
    # Sensitivity: 1=Low, 2=Medium, 3=High, 4=Critical
    sensitivity_level = db.Column(db.Integer, default=2, nullable=False)
    subnet_segment = db.Column(db.String(80), nullable=False, default='10.0.1.0/24')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    policies = db.relationship('Policy', back_populates='resource', cascade='all, delete-orphan')
    access_requests = db.relationship('AccessRequest', back_populates='resource', lazy='dynamic')

    @property
    def sensitivity_name(self) -> str:
        mapping = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        return mapping.get(self.sensitivity_level, 'Medium')

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'sensitivity_level': self.sensitivity_level,
            'sensitivity_name': self.sensitivity_name,
            'subnet_segment': self.subnet_segment,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Resource {self.code}: {self.name}>"
