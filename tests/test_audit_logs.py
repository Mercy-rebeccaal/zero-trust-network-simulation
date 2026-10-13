"""
Security Event Logging & Compliance Audit Tests
"""

import pytest
from models import AuditLog
from security.authentication import authenticate_user
from services.report_service import ReportService

def test_audit_log_created_on_failed_login(app):
    with app.app_context():
        count_before = AuditLog.query.filter_by(event_type='AUTH_LOGIN_FAILED').count()
        authenticate_user('admin', 'BadPassword123!')
        count_after = AuditLog.query.filter_by(event_type='AUTH_LOGIN_FAILED').count()
        assert count_after == count_before + 1

def test_ordinary_employee_cannot_view_audit_logs(employee_client):
    res = employee_client.get('/audit-logs')
    assert res.status_code == 403

def test_admin_can_view_audit_logs(auth_client):
    res = auth_client.get('/audit-logs')
    assert res.status_code == 200
    assert b"Audit Trail" in res.data

def test_audit_logs_csv_export(app, auth_client):
    res = auth_client.get('/api/audit-logs/export')
    assert res.status_code == 200
    assert res.mimetype == 'text/csv'
    assert b"Event ID,Timestamp (UTC),Event Type" in res.data
