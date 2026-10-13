"""
ZERO//TRUST Application Route Blueprints
"""

from routes.landing_routes import landing_bp
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.simulator_routes import simulator_bp
from routes.network_routes import network_bp
from routes.simulation_routes import simulation_bp
from routes.user_routes import user_bp
from routes.resource_routes import resource_bp
from routes.policy_routes import policy_bp
from routes.audit_routes import audit_bp
from routes.analytics_routes import analytics_bp
from routes.settings_routes import settings_bp

__all__ = [
    'landing_bp',
    'auth_bp',
    'dashboard_bp',
    'simulator_bp',
    'network_bp',
    'simulation_bp',
    'user_bp',
    'resource_bp',
    'policy_bp',
    'audit_bp',
    'analytics_bp',
    'settings_bp'
]
