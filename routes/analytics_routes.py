from flask import Blueprint, render_template, Response
from security.session_security import login_required
from services.dashboard_service import DashboardService
from services.report_service import ReportService
from models import AccessRequest, SecurityAlert

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/analytics')
@login_required
def index():
    metrics = DashboardService.get_summary_metrics()
    factors = DashboardService.get_factor_averages()
    distribution = DashboardService.get_decision_distribution()
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(15).all()
    
    return render_template(
        'analytics.html',
        metrics=metrics,
        factors=factors,
        distribution=distribution,
        alerts=alerts
    )

@analytics_bp.route('/api/analytics/export', methods=['GET'])
@login_required
def export_evaluations_csv():
    csv_data = ReportService.export_access_requests_csv(limit=1000)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=zero_trust_access_evaluations.csv"}
    )
