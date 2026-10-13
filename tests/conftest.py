"""
Pytest Fixtures for ZERO//TRUST Test Suite
"""

import pytest
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db, Role, User, Resource, Policy, SimulationScenario
from scripts.seed_demo_data import seed_data

@pytest.fixture
def app():
    """Creates a Flask application instance configured for testing."""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        # Seed test data
        seed_data(app)
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Provides a Flask test client."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Provides a CLI test runner."""
    return app.test_cli_runner()

@pytest.fixture
def auth_client(client, app):
    """Provides a test client pre-authenticated as the Administrator."""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'admin'
        sess['role_name'] = 'Administrator'
        sess['csrf_token'] = 'test-csrf-token'
    return client

@pytest.fixture
def employee_client(client, app):
    """Provides a test client pre-authenticated as the Employee."""
    with app.app_context():
        emp = User.query.filter_by(username='employee').first()
        emp_id = emp.id if emp else 3
    with client.session_transaction() as sess:
        sess['user_id'] = emp_id
        sess['username'] = 'employee'
        sess['role_name'] = 'Employee'
        sess['csrf_token'] = 'test-csrf-token'
    return client
