from flask import Blueprint, render_template, request, jsonify, session
from security.session_security import login_required
from services.simulation_service import SimulationService

simulation_bp = Blueprint('simulation', __name__)

@simulation_bp.route('/simulation-lab')
@login_required
def index():
    scenarios = SimulationService.get_scenarios()
    runs = SimulationService.get_runs(20)
    return render_template(
        'simulation_lab.html',
        scenarios=scenarios,
        runs=runs
    )

@simulation_bp.route('/api/simulations/scenarios', methods=['GET'])
@login_required
def api_scenarios():
    return jsonify({'success': True, 'scenarios': SimulationService.get_scenarios()})

@simulation_bp.route('/api/simulations/run', methods=['POST'])
@login_required
def api_run_single():
    data = request.get_json(silent=True) or request.form
    scenario_id = data.get('scenario_id')
    if not scenario_id:
        return jsonify({'success': False, 'error': 'Scenario ID required.'}), 400

    result = SimulationService.run_scenario(
        scenario_id=int(scenario_id),
        executor_user_id=session.get('user_id')
    )
    return jsonify(result)

@simulation_bp.route('/api/simulations/run-suite', methods=['POST'])
@login_required
def api_run_suite():
    result = SimulationService.run_suite(executor_user_id=session.get('user_id'))
    return jsonify(result)

@simulation_bp.route('/api/simulations/results', methods=['GET'])
@login_required
def api_results():
    return jsonify({'success': True, 'runs': SimulationService.get_runs(50)})

@simulation_bp.route('/api/simulations/reset', methods=['POST'])
@login_required
def api_reset():
    result = SimulationService.reset_runs()
    return jsonify(result)
