import os
import tempfile
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def get_database_uri():
    """Determine the appropriate database URI based on environment."""
    # 1. Custom external database URI (e.g., PostgreSQL on Supabase/Neon/Render)
    db_uri = os.environ.get('DATABASE_URI')
    if db_uri:
        if db_uri.startswith('postgres://'):
            db_uri = db_uri.replace('postgres://', 'postgresql://', 1)
        return db_uri

    # 2. Vercel serverless environment: only temp directory is writable
    if os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV'):
        temp_dir = tempfile.gettempdir()
        temp_db_path = os.path.join(temp_dir, 'zero_trust.db').replace('\\', '/')
        return f"sqlite:///{temp_db_path}"

    # 3. Local development environment: instance/zero_trust.db
    instance_dir = os.path.join(BASE_DIR, 'instance')
    os.makedirs(instance_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(instance_dir, 'zero_trust.db')}"

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-zero-trust-command-center-secret-key-2026')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get('PERMANENT_SESSION_LIFETIME_MINUTES', 60))
    )
    
    # Security Defaults
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get('LOCKOUT_DURATION_MINUTES', 15))
    
    # IACTE Default Thresholds
    IACTE_ALLOW_THRESHOLD = 80.0
    IACTE_VERIFICATION_THRESHOLD = 60.0

class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = get_database_uri()

class TestingConfig(Config):
    """Testing configuration with in-memory SQLite database."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key-for-zero-trust-tests'

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
    SQLALCHEMY_DATABASE_URI = get_database_uri()

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
