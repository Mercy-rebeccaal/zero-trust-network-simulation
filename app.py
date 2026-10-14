"""
ZERO//TRUST — Intelligent Security Command Center
=================================================
Final-Year Engineering Project & Demonstration Platform
Supported by Intelligent Adaptive Continuous Trust Engine (IACTE)

"NEVER TRUST. ALWAYS VERIFY."
"""

import os
from flask import Flask, render_template, session, request
from config import config_by_name
from models import db, User
from security.authentication import generate_csrf_token

def create_app(config_name=None):
    """Application factory for ZERO//TRUST platform."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))

    # Initialize extensions
    db.init_app(app)
    app.jinja_env.globals.update(zip=zip)

    # Inject global template variables
    @app.context_processor
    def inject_global_context():
        user = None
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            
        return {
            'current_user': user,
            'csrf_token': generate_csrf_token(),
            'app_name': 'ZERO//TRUST',
            'app_subtitle': 'Intelligent Security Command Center',
            'app_tagline': 'Never Trust. Always Verify.'
        }

    # Security Response Headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # Register Blueprints
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

    app.register_blueprint(landing_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(simulator_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(resource_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(settings_bp)

    # Register Error Handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith('/api/'):
            return {'success': False, 'error': 'Forbidden: Insufficient privileges.'}, 403
        return render_template('errors/403.html', error=error), 403

    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return {'success': False, 'error': 'Resource or endpoint not found.'}, 404
        return render_template('errors/404.html', error=error), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith('/api/'):
            return {'success': False, 'error': 'Internal server error occurred.'}, 500
        return render_template('errors/500.html', error=error), 500

    return app

# Vercel imports this module and looks for a top-level Flask instance.
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Ensure database tables exist on direct run
        db.create_all()
        
    print("[*] ZERO//TRUST Security Command Center starting...")
    print("[*] Access web console at: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
