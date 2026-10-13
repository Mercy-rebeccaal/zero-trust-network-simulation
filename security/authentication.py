"""
Authentication and Session Security Subsystem
=============================================
Handles server-side credential verification, account lockout protection,
audit logging of login events, and anti-CSRF token lifecycle.
"""

import secrets
from typing import Tuple, Optional, Any
from flask import session
from models import db, User, AuditLog

def generate_csrf_token() -> str:
    """Generates and stores a cryptographically secure anti-CSRF token in session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token: Optional[str]) -> bool:
    """Validates submitted token against session token in constant-time."""
    session_token = session.get('csrf_token')
    if not session_token or not token:
        return False
    return secrets.compare_digest(session_token, token)

def authenticate_user(
    username: str,
    password: str,
    ip_address: str = '127.0.0.1'
) -> Tuple[bool, Any]:
    """
    Validates user credentials against stored secure password hashes.
    
    Protections:
    - Account lockout after consecutive failed attempts
    - Uniform error messaging to prevent username enumeration
    - Detailed audit logging
    
    Returns:
        (True, User) on success
        (False, error_message) on failure
    """
    if not username or not password:
        return False, "Username and password are required."

    user = User.query.filter_by(username=username.strip()).first()

    # Generic error message to prevent enumeration attacks
    generic_error = "Invalid credentials. Please verify your username and password."

    if not user:
        # Record failed attempt audit log for unknown actor
        audit = AuditLog(
            event_type='AUTH_LOGIN_FAILED',
            actor_username=username.strip()[:50],
            action='LOGIN_ATTEMPT',
            status='DENIED',
            reason='Unknown username attempted.',
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()
        return False, generic_error

    # Check if account is currently locked
    if user.is_locked():
        lockout_expiry = user.locked_until.strftime('%H:%M:%S UTC') if user.locked_until else '15 minutes'
        audit = AuditLog(
            event_type='AUTH_LOCKED_ATTEMPT',
            actor_id=user.id,
            actor_username=user.username,
            action='LOGIN_ATTEMPT_LOCKED',
            status='BLOCKED',
            reason='Login attempted on locked account.',
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()
        return False, f"Account is temporarily locked due to repeated failed attempts. Please retry after {lockout_expiry}."

    # Check active status
    if not user.is_active:
        return False, "This account has been deactivated by the system administrator."

    # Verify password hash
    if not user.check_password(password):
        user.record_login_failure(max_attempts=5, lockout_minutes=15)
        
        audit = AuditLog(
            event_type='AUTH_LOGIN_FAILED',
            actor_id=user.id,
            actor_username=user.username,
            action='LOGIN_FAILED_PASSWORD',
            status='DENIED',
            reason=f"Failed password attempt ({user.failed_login_attempts}/5).",
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()

        if user.is_locked():
            return False, "Too many failed login attempts. Account has been temporarily locked for 15 minutes."
        return False, generic_error

    # Authentication Success
    user.record_login_success()
    audit = AuditLog(
        event_type='AUTH_LOGIN_SUCCESS',
        actor_id=user.id,
        actor_username=user.username,
        action='LOGIN_SUCCESS',
        status='SUCCESS',
        reason='Credential verification successful.',
        ip_address=ip_address
    )
    db.session.add(audit)
    db.session.commit()

    return True, user
