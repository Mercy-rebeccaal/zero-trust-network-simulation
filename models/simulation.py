import json
import uuid
from datetime import datetime
from models import db

class SimulationScenario(db.Model):
    __tablename__ = 'simulation_scenarios'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(80), nullable=False) # e.g. Access Control, Threat Vector, Context Anomaly
    objective = db.Column(db.Text, nullable=False)
    
    expected_decision = db.Column(db.String(30), nullable=False) # ALLOW, BLOCK, ADDITIONAL_VERIFICATION
    test_user_role = db.Column(db.String(50), nullable=False)
    test_resource_code = db.Column(db.String(50), nullable=False)
    
    # JSON encoded dictionary of input simulation parameters
    simulated_inputs_json = db.Column(db.Text, nullable=False)
    is_builtin = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    runs = db.relationship('SimulationRun', back_populates='scenario', cascade='all, delete-orphan')

    def get_inputs(self):
        try:
            return json.loads(self.simulated_inputs_json)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'category': self.category,
            'objective': self.objective,
            'expected_decision': self.expected_decision,
            'test_user_role': self.test_user_role,
            'test_resource_code': self.test_resource_code,
            'inputs': self.get_inputs(),
            'is_builtin': self.is_builtin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<SimulationScenario {self.code}: {self.name}>"

class SimulationRun(db.Model):
    __tablename__ = 'simulation_runs'

    id = db.Column(db.Integer, primary_key=True)
    run_uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), index=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('simulation_scenarios.id'), nullable=False)
    executed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    actual_decision = db.Column(db.String(30), nullable=False)
    trust_score = db.Column(db.Float, nullable=False)
    passed_expectation = db.Column(db.Boolean, nullable=False)
    execution_time_ms = db.Column(db.Float, default=0.0)
    
    details_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    scenario = db.relationship('SimulationScenario', back_populates='runs')
    executor = db.relationship('User')

    def get_details(self):
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'run_uuid': self.run_uuid,
            'scenario_id': self.scenario_id,
            'scenario_name': self.scenario.name if self.scenario else None,
            'scenario_code': self.scenario.code if self.scenario else None,
            'expected_decision': self.scenario.expected_decision if self.scenario else None,
            'actual_decision': self.actual_decision,
            'trust_score': round(self.trust_score, 2),
            'passed_expectation': self.passed_expectation,
            'execution_time_ms': round(self.execution_time_ms, 2),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'details': self.get_details()
        }

    def __repr__(self):
        return f"<SimulationRun {self.run_uuid}: Passed={self.passed_expectation}>"
