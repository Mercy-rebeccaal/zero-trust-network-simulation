"""
Report and Export Service
=========================
Generates CSV compliance reports and audit trail exports.
"""

import csv
import io
from typing import Optional
from models import AuditLog, AccessRequest

class ReportService:
    @staticmethod
    def export_audit_logs_csv(
        event_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 1000
    ) -> str:
        """Exports audit logs to CSV formatted string."""
        query = AuditLog.query.order_by(AuditLog.timestamp.desc())
        
        if event_type:
            query = query.filter_by(event_type=event_type)
        if status:
            query = query.filter_by(status=status)
            
        logs = query.limit(limit).all()

        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write CSV header
        writer.writerow([
            'Event ID',
            'Timestamp (UTC)',
            'Event Type',
            'Actor Username',
            'Resource',
            'Action',
            'Status',
            'Trust Score',
            'Decision',
            'Reason',
            'IP Address'
        ])

        for log in logs:
            writer.writerow([
                log.event_id,
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else '',
                log.event_type,
                log.actor_username,
                log.resource_code or 'N/A',
                log.action,
                log.status,
                f"{log.trust_score:.2f}" if log.trust_score is not None else 'N/A',
                log.decision or 'N/A',
                log.reason or '',
                log.ip_address or '127.0.0.1'
            ])

        return output.getvalue()

    @staticmethod
    def export_access_requests_csv(limit: int = 1000) -> str:
        """Exports evaluated access requests to CSV formatted string."""
        requests = AccessRequest.query.order_by(AccessRequest.timestamp.desc()).limit(limit).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'Request UUID',
            'Timestamp (UTC)',
            'Username',
            'Role',
            'Resource Code',
            'Operation',
            'RBAC Result',
            'Trust Score',
            'Decision',
            'Decision Reason',
            'MFA Verified'
        ])

        for req in requests:
            writer.writerow([
                req.request_uuid,
                req.timestamp.strftime('%Y-%m-%d %H:%M:%S') if req.timestamp else '',
                req.user.username if req.user else 'N/A',
                req.user.role.name if (req.user and req.user.role) else 'N/A',
                req.resource.code if req.resource else 'N/A',
                req.operation,
                req.rbac_result,
                f"{req.trust_score:.2f}",
                req.decision,
                req.decision_reason,
                'YES' if req.is_verified_mfa else 'NO'
            ])

        return output.getvalue()
