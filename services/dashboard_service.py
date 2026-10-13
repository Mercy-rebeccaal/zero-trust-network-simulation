"""
Dashboard Analytics Service
===========================
Calculates real-time metrics, distributions, trends, and factor averages
directly from persistent database tables.
"""

from typing import Dict, Any, List
from sqlalchemy import func
from datetime import datetime, timedelta
from models import db, User, AccessRequest, TrustEvaluation, AuditLog, SecurityAlert, Resource, Role

class DashboardService:
    @staticmethod
    def get_summary_metrics() -> Dict[str, Any]:
        """Calculates core summary card counters."""
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        total_requests = AccessRequest.query.count()
        
        allowed_count = AccessRequest.query.filter_by(decision='ALLOW').count()
        additional_verif_count = AccessRequest.query.filter_by(decision='ADDITIONAL_VERIFICATION').count()
        restricted_count = AccessRequest.query.filter_by(decision='RESTRICT').count()
        blocked_count = AccessRequest.query.filter_by(decision='BLOCK').count()
        
        # Calculate rates
        allow_rate = round((allowed_count / total_requests * 100), 1) if total_requests > 0 else 0.0
        verif_rate = round(((additional_verif_count + restricted_count) / total_requests * 100), 1) if total_requests > 0 else 0.0
        block_rate = round((blocked_count / total_requests * 100), 1) if total_requests > 0 else 0.0
        
        # Average trust score
        avg_score_query = db.session.query(func.avg(AccessRequest.trust_score)).scalar()
        avg_trust_score = round(float(avg_score_query), 2) if avg_score_query is not None else 78.50
        
        # Suspicious events & unresolved alerts
        suspicious_events_count = AuditLog.query.filter(
            AuditLog.status.in_(['DENIED', 'BLOCKED', 'WARNING'])
        ).count()
        
        active_alerts_count = SecurityAlert.query.filter_by(is_resolved=False).count()

        return {
            'total_users': total_users,
            'active_users': active_users,
            'total_requests': total_requests,
            'allowed_count': allowed_count,
            'additional_verif_count': additional_verif_count,
            'restricted_count': restricted_count,
            'blocked_count': blocked_count,
            'allow_rate': allow_rate,
            'verif_rate': verif_rate,
            'block_rate': block_rate,
            'avg_trust_score': avg_trust_score,
            'suspicious_events_count': suspicious_events_count,
            'active_alerts_count': active_alerts_count
        }

    @staticmethod
    def get_decision_distribution() -> Dict[str, Any]:
        """Returns counts for decision doughnut chart."""
        allowed = AccessRequest.query.filter_by(decision='ALLOW').count()
        verification = AccessRequest.query.filter_by(decision='ADDITIONAL_VERIFICATION').count()
        restricted = AccessRequest.query.filter_by(decision='RESTRICT').count()
        blocked = AccessRequest.query.filter_by(decision='BLOCK').count()
        
        return {
            'labels': ['Allowed (High Trust)', 'Additional Verification', 'Restricted Mode', 'Blocked (Untrusted / Denied)'],
            'counts': [allowed, verification, restricted, blocked],
            'colors': ['#14B8A6', '#F5B942', '#73BFFF', '#FB7185']
        }

    @staticmethod
    def get_trust_timeline(limit_points: int = 15) -> Dict[str, Any]:
        """Returns recent trust evaluations for timeline line chart."""
        recent_requests = (
            AccessRequest.query
            .order_by(AccessRequest.timestamp.desc())
            .limit(limit_points)
            .all()
        )
        
        # Reverse to chronological order
        recent_requests.reverse()
        
        labels = [r.timestamp.strftime('%H:%M:%S') if r.timestamp else f"#{r.id}" for r in recent_requests]
        scores = [round(r.trust_score, 2) for r in recent_requests]
        decisions = [r.decision for r in recent_requests]

        return {
            'labels': labels,
            'scores': scores,
            'decisions': decisions
        }

    @staticmethod
    def get_resource_traffic() -> Dict[str, Any]:
        """Returns request counts aggregated by protected resource."""
        resources = Resource.query.filter_by(is_active=True).all()
        labels = []
        counts = []
        sensitivities = []

        for res in resources:
            count = AccessRequest.query.filter_by(resource_id=res.id).count()
            labels.append(res.code)
            counts.append(count)
            sensitivities.append(res.sensitivity_name)

        return {
            'labels': labels,
            'counts': counts,
            'sensitivities': sensitivities
        }

    @staticmethod
    def get_factor_averages() -> Dict[str, Any]:
        """Returns average scores across the 7 IACTE factors."""
        query = db.session.query(
            func.avg(TrustEvaluation.identity_score),
            func.avg(TrustEvaluation.device_score),
            func.avg(TrustEvaluation.context_score),
            func.avg(TrustEvaluation.behavior_score),
            func.avg(TrustEvaluation.resource_safety_score),
            func.avg(TrustEvaluation.history_score),
            func.avg(TrustEvaluation.threat_safety_score)
        ).first()

        def safe_float(val, fallback=80.0):
            return round(float(val), 1) if val is not None else fallback

        return {
            'labels': [
                'Identity (0.20)',
                'Device (0.15)',
                'Context (0.15)',
                'Behaviour (0.15)',
                'Resource Safety (0.10)',
                'History (0.15)',
                'Threat Intel (0.10)'
            ],
            'scores': [
                safe_float(query[0], 90.0),
                safe_float(query[1], 85.0),
                safe_float(query[2], 82.0),
                safe_float(query[3], 88.0),
                safe_float(query[4], 75.0),
                safe_float(query[5], 84.0),
                safe_float(query[6], 92.0)
            ]
        }

    @staticmethod
    def get_recent_activity(limit: int = 10) -> List[Dict[str, Any]]:
        """Returns the most recent security and access events."""
        events = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return [evt.to_dict() for evt in events]
