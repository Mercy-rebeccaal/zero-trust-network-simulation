from flask import Blueprint, render_template, jsonify
from security.session_security import login_required
from services.dashboard_service import DashboardService

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    metrics = DashboardService.get_summary_metrics()
    distribution = DashboardService.get_decision_distribution()
    timeline = DashboardService.get_trust_timeline(15)
    factors = DashboardService.get_factor_averages()
    resources = DashboardService.get_resource_traffic()
    recent_activity = DashboardService.get_recent_activity(10)
    
    return render_template(
        'dashboard.html',
        metrics=metrics,
        distribution=distribution,
        timeline=timeline,
        factors=factors,
        resources=resources,
        recent_activity=recent_activity
    )

@dashboard_bp.route('/api/dashboard/summary')
@login_required
def api_summary():
    return jsonify({'success': True, 'data': DashboardService.get_summary_metrics()})

@dashboard_bp.route('/api/dashboard/distribution')
@login_required
def api_distribution():
    return jsonify({'success': True, 'data': DashboardService.get_decision_distribution()})

@dashboard_bp.route('/api/dashboard/timeline')
@login_required
def api_timeline():
    return jsonify({'success': True, 'data': DashboardService.get_trust_timeline()})

@dashboard_bp.route('/api/dashboard/factors')
@login_required
def api_factors():
    return jsonify({'success': True, 'data': DashboardService.get_factor_averages()})

@dashboard_bp.route('/api/dashboard/resources')
@login_required
def api_resources():
    return jsonify({'success': True, 'data': DashboardService.get_resource_traffic()})
