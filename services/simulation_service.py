"""
Attack and Threat Simulation Service
====================================
Executes controlled security risk simulations against the Zero Trust pipeline,
verifying expected versus observed outcomes with execution metrics.
"""

import time
import json
from typing import Dict, Any, List, Optional
from models import db, SimulationScenario, SimulationRun, User, Resource, Role
from security.decision_engine import evaluate_access_request

class SimulationService:
    @staticmethod
    def run_scenario(scenario_id: int, executor_user_id: Optional[int] = None) -> Dict[str, Any]:
        """Runs a single simulation scenario and persists the outcome."""
        start_time = time.time()
        scenario = db.session.get(SimulationScenario, scenario_id)
        if not scenario:
            return {'success': False, 'error': f"Scenario #{scenario_id} not found."}

        # Find a test user matching the required role
        role = Role.query.filter_by(name=scenario.test_user_role).first()
        test_user = User.query.filter_by(role_id=role.id).first() if role else None
        
        if not test_user:
            # Fallback to executor user or any active user
            test_user = db.session.get(User, executor_user_id) if executor_user_id else User.query.first()

        inputs = scenario.get_inputs()
        operation = inputs.get('operation', 'READ')

        # Execute decision pipeline
        eval_result = evaluate_access_request(
            user_id=test_user.id,
            resource_id_or_code=scenario.test_resource_code,
            operation=operation,
            simulated_inputs=inputs,
            is_mfa_verified=inputs.get('is_mfa_verified', False),
            ip_address=inputs.get('simulated_ip', '192.168.10.55'),
            persist_records=True
        )

        elapsed_ms = (time.time() - start_time) * 1000.0
        actual_decision = eval_result['decision']
        expected_decision = scenario.expected_decision
        
        # Determine pass/fail based on security expectation matching observed outcome
        passed = (actual_decision == expected_decision)

        # Record simulation run
        run_record = SimulationRun(
            scenario_id=scenario.id,
            executed_by_user_id=executor_user_id,
            actual_decision=actual_decision,
            trust_score=eval_result['trust_score'],
            passed_expectation=passed,
            execution_time_ms=elapsed_ms,
            details_json=json.dumps({
                'rbac_result': eval_result['rbac_result'],
                'reason': eval_result['decision_reason'],
                'factor_scores': eval_result['factor_scores'],
                'contributions': eval_result['contributions'],
                'explanation': eval_result['explanation']
            })
        )
        db.session.add(run_record)
        db.session.commit()

        return {
            'success': True,
            'run_id': run_record.id,
            'scenario': scenario.to_dict(),
            'actual_decision': actual_decision,
            'expected_decision': expected_decision,
            'trust_score': eval_result['trust_score'],
            'passed_expectation': passed,
            'execution_time_ms': round(elapsed_ms, 2),
            'eval_details': eval_result
        }

    @staticmethod
    def run_suite(executor_user_id: Optional[int] = None) -> Dict[str, Any]:
        """Runs all configured simulation scenarios sequentially and aggregates results."""
        scenarios = SimulationScenario.query.order_by(SimulationScenario.id.asc()).all()
        results = []
        
        total_count = len(scenarios)
        passed_count = 0
        failed_count = 0
        
        decision_counts = {
            'ALLOW': 0,
            'ADDITIONAL_VERIFICATION': 0,
            'RESTRICT': 0,
            'BLOCK': 0
        }

        total_exec_time = 0.0

        for scn in scenarios:
            res = SimulationService.run_scenario(scn.id, executor_user_id=executor_user_id)
            if res.get('success'):
                results.append(res)
                if res['passed_expectation']:
                    passed_count += 1
                else:
                    failed_count += 1
                
                dec = res['actual_decision']
                decision_counts[dec] = decision_counts.get(dec, 0) + 1
                total_exec_time += res['execution_time_ms']

        return {
            'success': True,
            'total_scenarios': total_count,
            'passed_count': passed_count,
            'failed_count': failed_count,
            'pass_rate': round((passed_count / total_count * 100), 1) if total_count > 0 else 0.0,
            'decisions': decision_counts,
            'total_execution_time_ms': round(total_exec_time, 2),
            'results': results
        }

    @staticmethod
    def get_scenarios() -> List[Dict[str, Any]]:
        scenarios = SimulationScenario.query.order_by(SimulationScenario.id.asc()).all()
        return [s.to_dict() for s in scenarios]

    @staticmethod
    def get_runs(limit: int = 50) -> List[Dict[str, Any]]:
        runs = SimulationRun.query.order_by(SimulationRun.timestamp.desc()).limit(limit).all()
        return [r.to_dict() for r in runs]

    @staticmethod
    def reset_runs() -> Dict[str, Any]:
        """Resets disposable simulation run history without deleting audit or access records."""
        deleted = SimulationRun.query.delete()
        db.session.commit()
        return {'success': True, 'deleted_runs_count': deleted}
