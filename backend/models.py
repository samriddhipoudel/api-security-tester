"""
Database Models - SQLAlchemy ORM
Author: Samriddhi Poudel (23047345)
Date: December 10, 2025
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    api_endpoints = db.relationship('APIEndpoint', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'


class APIEndpoint(db.Model):
    """API Endpoint model for storing saved APIs"""
    __tablename__ = 'api_endpoints'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), default='GET')
    headers = db.Column(db.Text)
    body = db.Column(db.Text)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    schedules = db.relationship('ScanSchedule', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<APIEndpoint {self.name}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'method': self.method,
            'created_at': self.created_at.isoformat()
        }


class Scan(db.Model):
    """Scan model for storing scan history"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'))
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='completed')
    total_tests = db.Column(db.Integer, default=0)
    passed_tests = db.Column(db.Integer, default=0)
    failed_tests = db.Column(db.Integer, default=0)
    warnings = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Scan {self.id} - {self.status}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'api_endpoint_id': self.api_endpoint_id,
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'status': self.status,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'warnings': self.warnings
        }


class Vulnerability(db.Model):
    """Vulnerability model for storing test results"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    test_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20))
    details = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Vulnerability {self.test_name} - {self.severity}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'test_name': self.test_name,
            'category': self.category,
            'severity': self.severity,
            'status': self.status,
            'details': self.details,
            'recommendation': self.recommendation
        }


class Alert(db.Model):
    """Alert model for notifications"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    alert_type = db.Column(db.String(50))
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Alert {self.alert_type}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'message': self.message,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat()
        }


class ScanSchedule(db.Model):
    """Scan Schedule model for automated scans"""
    __tablename__ = 'scan_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'), nullable=False)
    frequency = db.Column(db.String(50))
    next_scan_time = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanSchedule {self.frequency}>'