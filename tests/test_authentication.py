"""
Authentication & Session Protection Tests
"""

import pytest
from models import User
from security.authentication import authenticate_user

def test_valid_login(app):
    with app.app_context():
        success, user = authenticate_user('admin', 'AdminPassword123!')
        assert success is True
        assert user.username == 'admin'
        assert user.failed_login_attempts == 0

def test_invalid_password(app):
    with app.app_context():
        success, err = authenticate_user('admin', 'WrongPassword!')
        assert success is False
        assert "Invalid credentials" in err
        
        # Verify failed attempt recorded
        user = User.query.filter_by(username='admin').first()
        assert user.failed_login_attempts == 1

def test_unknown_user(app):
    with app.app_context():
        success, err = authenticate_user('nonexistent_user', 'AnyPassword123!')
        assert success is False
        assert "Invalid credentials" in err

def test_account_lockout(app):
    with app.app_context():
        user = User.query.filter_by(username='employee').first()
        user.failed_login_attempts = 0
        
        # Trigger 5 failed attempts
        for _ in range(5):
            authenticate_user('employee', 'WrongPassword!')
            
        assert user.is_locked() is True
        
        # 6th attempt blocked by lockout
        success, err = authenticate_user('employee', 'EmployeePassword123!')
        assert success is False
        assert "locked" in err.lower()

def test_protected_route_unauthenticated(client):
    res = client.get('/dashboard', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.location

def test_logout(auth_client):
    res = auth_client.get('/logout', follow_redirects=True)
    assert res.status_code == 200
    with auth_client.session_transaction() as sess:
        assert 'user_id' not in sess
