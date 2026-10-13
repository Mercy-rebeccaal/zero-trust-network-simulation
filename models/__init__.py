from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from models.role import Role
from models.user import User
from models.resource import Resource
from models.policy import Policy
from models.access_request import AccessRequest
from models.trust_evaluation import TrustEvaluation
from models.simulation import SimulationScenario, SimulationRun
from models.audit_log import AuditLog
from models.security_alert import SecurityAlert

__all__ = [
    'db',
    'Role',
    'User',
    'Resource',
    'Policy',
    'AccessRequest',
    'TrustEvaluation',
    'SimulationScenario',
    'SimulationRun',
    'AuditLog',
    'SecurityAlert'
]
