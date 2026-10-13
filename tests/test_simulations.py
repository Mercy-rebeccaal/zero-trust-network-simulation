"""
Attack and Threat Simulation Suite Automated Tests
"""

import pytest
from models import SimulationScenario, SimulationRun, AuditLog
from services.simulation_service import SimulationService

def test_run_single_scenario(app):
    with app.app_context():
        scn = SimulationScenario.query.filter_by(code='SCENARIO-01').first()
        res = SimulationService.run_scenario(scn.id)
        assert res['success'] is True
        assert res['actual_decision'] == 'ALLOW'
        assert res['passed_expectation'] is True
        assert res['execution_time_ms'] > 0

def test_run_lateral_movement_block_scenario(app):
    with app.app_context():
        scn = SimulationScenario.query.filter_by(code='SCENARIO-02').first()
        res = SimulationService.run_scenario(scn.id)
        assert res['success'] is True
        assert res['actual_decision'] == 'BLOCK'
        assert res['passed_expectation'] is True

def test_run_full_scenario_suite(app):
    with app.app_context():
        suite_res = SimulationService.run_suite()
        assert suite_res['success'] is True
        assert suite_res['total_scenarios'] == 10
        assert suite_res['passed_count'] == 10
        assert suite_res['pass_rate'] == 100.0

def test_reset_simulation_runs(app):
    with app.app_context():
        # Run a scenario first
        scn = SimulationScenario.query.first()
        SimulationService.run_scenario(scn.id)
        assert SimulationRun.query.count() > 0

        audit_count_before = AuditLog.query.count()
        reset_res = SimulationService.reset_runs()
        assert reset_res['success'] is True
        assert SimulationRun.query.count() == 0

        # Audit logs must NOT be deleted!
        assert AuditLog.query.count() >= audit_count_before
