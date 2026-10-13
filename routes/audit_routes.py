from flask import Blueprint, render_template, request, jsonify, Response
from security.session_security import login_required, role_required
from models import AuditLog
from services.report_service import ReportService

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/audit-logs')
@login_required
@role_required(['Administrator'])
def index():
    page = request.args.get('page', 1, type=int)
    event_type = request.args.get('event_type')
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    if status:
        query = query.filter(AuditLog.status == status)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (AuditLog.actor_username.ilike(search_fmt)) |
            (AuditLog.reason.ilike(search_fmt)) |
            (AuditLog.resource_code.ilike(search_fmt)) |
            (AuditLog.event_id.ilike(search_fmt))
        )

    pagination = query.paginate(page=page, per_page=20, error_out=False)
    
    # Distinct event types for dropdown filter
    distinct_types = [r[0] for r in AuditLog.query.with_entities(AuditLog.event_type).distinct().all()]

    return render_template(
        'audit_logs.html',
        logs=pagination.items,
        pagination=pagination,
        event_types=distinct_types,
        selected_type=event_type,
        selected_status=status,
        search_query=search
    )

@audit_bp.route('/api/audit-logs', methods=['GET'])
@login_required
@role_required(['Administrator'])
def api_list_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    event_type = request.args.get('event_type')
    status = request.args.get('status')

    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if event_type:
        query = query.filter_by(event_type=event_type)
    if status:
        query = query.filter_by(status=status)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'success': True,
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages
    })

@audit_bp.route('/api/audit-logs/export', methods=['GET'])
@login_required
@role_required(['Administrator'])
def export_csv():
    event_type = request.args.get('event_type')
    status = request.args.get('status')
    
    csv_data = ReportService.export_audit_logs_csv(event_type=event_type, status=status)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=zero_trust_audit_logs.csv"}
    )
