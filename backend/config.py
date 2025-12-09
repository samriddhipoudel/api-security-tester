"""
Configuration Management
Author: Samriddhi Poudel (23047345)
Date: December 9, 2025
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Application Settings
    APP_NAME = "API Security Tester"
    VERSION = "0.1.0"
    DEBUG = True
    
    # Security Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'api_security_db')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    
    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Scanner Settings
    API_TIMEOUT = 10  # seconds
    MAX_SCAN_THREADS = 5
    SCAN_RETRY_COUNT = 3
    
    # Security Test Settings
    ENABLE_AUTH_TESTS = True
    ENABLE_INJECTION_TESTS = True
    ENABLE_RATE_LIMIT_TESTS = True
    
    # Report Settings
    REPORT_OUTPUT_DIR = "reports/"
    REPORT_FORMAT = "pdf"  # pdf, html, json
    
    # Logging
    LOG_LEVEL = "INFO"
    LOG_FILE = "logs/app.log"


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])