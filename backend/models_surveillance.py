"""
Enhanced Database Models with Surveillance Support
Author: Samriddhi Poudel (23047345)
Date: February 5, 2026
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# ========================================
# EXISTING MODELS 
# ========================================

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
    request_logs = db.relationship('APIRequestLog', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    baselines = db.relationship('BehavioralBaseline', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    anomaly_detections = db.relationship('AnomalyDetection', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    security_events = db.relationship('SecurityEvent', backref='api_endpoint', lazy=True, cascade='all, delete-orphan')
    
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
            'warnings': self.warnings,
            'passed': self.passed_tests,
            'failed': self.failed_tests,
            'api_url': self.api_endpoint.url if self.api_endpoint else None,
            'api_name': self.api_endpoint.name if self.api_endpoint else None,
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
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source = db.Column(db.String(50), default='manual')
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    anomaly_detection_id = db.Column(db.BigInteger, db.ForeignKey('anomaly_detections.id'), nullable=True)
    security_event_id = db.Column(db.Integer, db.ForeignKey('security_events.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Alert {self.alert_type}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source': self.source,
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


# ========================================
# NEW SURVEILLANCE MODELS
# ========================================

class APIRequestLog(db.Model):
    
    """Stores all API requests for behavior analysis"""
    __tablename__ = 'api_request_logs'
    
    id = db.Column(db.BigInteger, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'))
    request_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    http_method = db.Column(db.String(10))
    request_path = db.Column(db.String(500))
    request_headers = db.Column(db.Text)
    request_body = db.Column(db.Text)
    response_status = db.Column(db.Integer)
    response_time_ms = db.Column(db.Integer)
    response_size_bytes = db.Column(db.Integer)
    is_suspicious = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Numeric(5, 2), default=0.00)
    
    # Relationships
    anomaly_detections = db.relationship('AnomalyDetection', backref='request_log', lazy=True)
    
    def __repr__(self):
        return f'<APIRequestLog {self.id} - {self.source_ip}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'api_endpoint_id': self.api_endpoint_id,
            'timestamp': self.request_timestamp.isoformat(),
            'source_ip': self.source_ip,
            'method': self.http_method,
            'path': self.request_path,
            'status': self.response_status,
            'response_time_ms': self.response_time_ms,
            'is_suspicious': self.is_suspicious,
            'anomaly_score': float(self.anomaly_score) if self.anomaly_score else 0.0
        }


class BehavioralBaseline(db.Model):
    """Stores normal behavior patterns for each API endpoint"""
    __tablename__ = 'behavioral_baselines'
    
    id = db.Column(db.Integer, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'), nullable=False)
    metric_name = db.Column(db.String(100), nullable=False)
    avg_value = db.Column(db.Numeric(15, 2))
    min_value = db.Column(db.Numeric(15, 2))
    max_value = db.Column(db.Numeric(15, 2))
    std_deviation = db.Column(db.Numeric(15, 2))
    sample_size = db.Column(db.Integer)
    calculation_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<BehavioralBaseline {self.metric_name} - Endpoint {self.api_endpoint_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'metric_name': self.metric_name,
            'avg_value': float(self.avg_value) if self.avg_value else 0.0,
            'min_value': float(self.min_value) if self.min_value else 0.0,
            'max_value': float(self.max_value) if self.max_value else 0.0,
            'std_deviation': float(self.std_deviation) if self.std_deviation else 0.0,
            'sample_size': self.sample_size,
            'last_updated': self.last_updated.isoformat()
        }


class AnomalyDetection(db.Model):
    """Stores detected anomalies and suspicious patterns"""
    __tablename__ = 'anomaly_detections'
    
    id = db.Column(db.BigInteger, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'))
    request_log_id = db.Column(db.BigInteger, db.ForeignKey('api_request_logs.id'), nullable=True)
    detection_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    anomaly_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence_score = db.Column(db.Numeric(5, 2), nullable=False)
    description = db.Column(db.Text)
    detection_details = db.Column(db.Text)  # JSON
    is_false_positive = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.String(100))
    reviewed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='new')
    
    # Relationships
    alerts = db.relationship('Alert', backref='anomaly_detection', lazy=True)
    
    def __repr__(self):
        return f'<AnomalyDetection {self.anomaly_type} - {self.severity}>'
    
    def to_dict(self):
        import json
        return {
            'id': self.id,
            'api_endpoint_id': self.api_endpoint_id,
            'detection_timestamp': self.detection_timestamp.isoformat(),
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'confidence_score': float(self.confidence_score),
            'description': self.description,
            'detection_details': json.loads(self.detection_details) if self.detection_details else {},
            'is_false_positive': self.is_false_positive,
            'status': self.status
        }


class AttackPattern(db.Model):
    """Stores known attack signatures and patterns"""
    __tablename__ = 'attack_patterns'
    
    id = db.Column(db.Integer, primary_key=True)
    pattern_name = db.Column(db.String(255), nullable=False)
    pattern_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    pattern_regex = db.Column(db.Text)
    pattern_rules = db.Column(db.Text)  # JSON
    severity = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<AttackPattern {self.pattern_name}>'


class RateLimitTracking(db.Model):
    """Tracks request rates per IP/endpoint for rate limiting detection"""
    __tablename__ = 'rate_limit_tracking'
    
    id = db.Column(db.BigInteger, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'))
    source_ip = db.Column(db.String(45), nullable=False)
    time_window_start = db.Column(db.DateTime, nullable=False)
    time_window_end = db.Column(db.DateTime, nullable=False)
    request_count = db.Column(db.Integer, default=0)
    bytes_transferred = db.Column(db.BigInteger, default=0)
    error_count = db.Column(db.Integer, default=0)
    is_rate_limited = db.Column(db.Boolean, default=False)
    threshold_exceeded_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<RateLimitTracking {self.source_ip} - {self.request_count} requests>'


class ThreatIntelligence(db.Model):
    """Stores external threat intelligence data"""
    __tablename__ = 'threat_intelligence'
    
    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(50), nullable=False)
    indicator_value = db.Column(db.String(255), nullable=False)
    indicator_type = db.Column(db.String(50), nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(100))
    description = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    expiry_date = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<ThreatIntelligence {self.indicator_type}: {self.indicator_value}>'


class SecurityEvent(db.Model):
    """High-level security events aggregated from anomalies"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    api_endpoint_id = db.Column(db.Integer, db.ForeignKey('api_endpoints.id'))
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    event_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    affected_ips = db.Column(db.Text)
    attack_vector = db.Column(db.String(100))
    mitigation_status = db.Column(db.String(50), default='pending')
    mitigation_actions = db.Column(db.Text)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(100))
    
    # Relationships
    alerts = db.relationship('Alert', backref='security_event', lazy=True)
    
    def __repr__(self):
        return f'<SecurityEvent {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'api_endpoint_id': self.api_endpoint_id,
            'event_type': self.event_type,
            'severity': self.severity,
            'event_timestamp': self.event_timestamp.isoformat(),
            'title': self.title,
            'description': self.description,
            'mitigation_status': self.mitigation_status,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


class SurveillanceRule(db.Model):
    """Configurable rules for automated surveillance"""
    __tablename__ = 'surveillance_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), nullable=False)
    rule_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    condition_json = db.Column(db.Text, nullable=False)  # JSON
    threshold_value = db.Column(db.Numeric(15, 2))
    time_window_minutes = db.Column(db.Integer)
    severity = db.Column(db.String(20), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    notification_channels = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_triggered = db.Column(db.DateTime)
    trigger_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<SurveillanceRule {self.rule_name}>'
    
    def to_dict(self):
        import json
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'rule_type': self.rule_type,
            'description': self.description,
            'condition': json.loads(self.condition_json) if self.condition_json else {},
            'threshold_value': float(self.threshold_value) if self.threshold_value else None,
            'time_window_minutes': self.time_window_minutes,
            'severity': self.severity,
            'action_type': self.action_type,
            'is_active': self.is_active,
            'trigger_count': self.trigger_count
        }