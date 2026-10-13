"""
Database Initialization Script
==============================
Initializes the SQLite database tables and schema.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db

def init_database(app=None):
    if app is None:
        app = create_app('development')
        
    with app.app_context():
        # Ensure instance directory exists
        instance_path = app.instance_path
        os.makedirs(instance_path, exist_ok=True)
        
        print(f"[*] Initializing database schema at: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.create_all()
        print("[+] Database tables initialized successfully.")

if __name__ == '__main__':
    init_database()
