from flask import Blueprint, render_template

landing_bp = Blueprint('landing', __name__)

@landing_bp.route('/')
def index():
    """Renders the public Zero Trust architectural landing page."""
    return render_template('landing.html')
