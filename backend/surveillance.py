"""
Automated Surveillance Module - API Behavior Monitoring & Anomaly Detection
Author: Samriddhi Poudel (23047345)
Date: February 5, 2026
Description: Real-time monitoring and anomaly detection for API security
"""

import time
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import numpy as np
from models_surveillance import db, APIEndpoint, Scan
from sqlalchemy import text


class SurveillanceEngine:
    """
    Core surveillance engine for monitoring API behavior and detecting anomalies
    """
    
    def __init__(self, db_session):
        self.db = db_session
        self.anomaly_threshold = 2.5  # Standard deviations from mean
        self.rate_limit_window = 300  # 5 minutes in seconds
        self.rate_limit_threshold = 100  # Max requests per window
        
    # ========================================
    # REQUEST LOGGING
    # ========================================
    
    def log_request(self, endpoint_id: int, request_data: dict) -> int:
        """
        Log an API request for surveillance analysis
        
        Args:
            endpoint_id: API endpoint ID
            request_data: {
                'source_ip': str,
                'user_agent': str,
                'http_method': str,
                'request_path': str,
                'request_headers': dict,
                'request_body': str,
                'response_status': int,
                'response_time_ms': int,
                'response_size_bytes': int
            }
        
        Returns:
            request_log_id: ID of the logged request
        """
        query = text("""
            INSERT INTO api_request_logs 
            (api_endpoint_id, source_ip, user_agent, http_method, request_path,
             request_headers, request_body, response_status, response_time_ms, 
             response_size_bytes, is_suspicious, anomaly_score)
            VALUES 
            (:endpoint_id, :source_ip, :user_agent, :method, :path,
             :headers, :body, :status, :response_time, :response_size, 
             :suspicious, :anomaly_score)
        """)
        
        # Calculate initial anomaly score
        anomaly_score = self._calculate_initial_anomaly_score(request_data)
        is_suspicious = anomaly_score > 50.0
        
        result = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'source_ip': request_data.get('source_ip', '0.0.0.0'),
            'user_agent': request_data.get('user_agent', ''),
            'method': request_data.get('http_method', 'GET'),
            'path': request_data.get('request_path', ''),
            'headers': json.dumps(request_data.get('request_headers', {})),
            'body': request_data.get('request_body', ''),
            'status': request_data.get('response_status', 200),
            'response_time': request_data.get('response_time_ms', 0),
            'response_size': request_data.get('response_size_bytes', 0),
            'suspicious': is_suspicious,
            'anomaly_score': anomaly_score
        })
        self.db.commit()
        
        return result.lastrowid
    
    def _calculate_initial_anomaly_score(self, request_data: dict) -> float:
        """Calculate initial anomaly score based on request patterns"""
        score = 0.0
        
        # Check for attack patterns
        if self._check_sql_injection_patterns(request_data):
            score += 30.0
        if self._check_xss_patterns(request_data):
            score += 25.0
        if self._check_command_injection_patterns(request_data):
            score += 35.0
        if self._check_path_traversal_patterns(request_data):
            score += 20.0
        
        # Check response anomalies
        if request_data.get('response_status', 200) >= 500:
            score += 15.0
        elif request_data.get('response_status', 200) == 401:
            score += 10.0
        
        # Check response time anomaly
        if request_data.get('response_time_ms', 0) > 5000:
            score += 10.0
        
        return min(score, 100.0)
    
    # ========================================
    # ATTACK PATTERN DETECTION
    # ========================================
    
    def _check_sql_injection_patterns(self, request_data: dict) -> bool:
        """Check for SQL injection patterns"""
        patterns = [
            r"(\\'|\"|--|\;|\*|\/\*|\*\/)",
            r"(union|select|insert|update|delete|drop|create|alter|exec|execute)\s",
            r"(or|and)\s+[\w\d]+=[\w\d]+",
            r"(\'|\")(\s)*(or|and)(\s)*(\'|\")(\s)*=(\s)*(\'|\")",
        ]
        
        text_to_check = str(request_data.get('request_path', '')) + \
                       str(request_data.get('request_body', ''))
        
        for pattern in patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        return False
    
    def _check_xss_patterns(self, request_data: dict) -> bool:
        """Check for XSS patterns"""
        patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe",
            r"<img[^>]*onerror",
        ]
        
        text_to_check = str(request_data.get('request_path', '')) + \
                       str(request_data.get('request_body', ''))
        
        for pattern in patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        return False
    
    def _check_command_injection_patterns(self, request_data: dict) -> bool:
        """Check for command injection patterns"""
        patterns = [
            r"(;|\||&|`|\$\(|\$\{)",
            r"(cat|ls|pwd|whoami|id|uname|wget|curl)\s",
            r"(/bin/|/usr/bin/|/sbin/)",
        ]
        
        text_to_check = str(request_data.get('request_path', '')) + \
                       str(request_data.get('request_body', ''))
        
        for pattern in patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        return False
    
    def _check_path_traversal_patterns(self, request_data: dict) -> bool:
        """Check for path traversal patterns"""
        patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"%2e%2e\\",
        ]
        
        text_to_check = str(request_data.get('request_path', ''))
        
        for pattern in patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        return False
    
    # ========================================
    # BEHAVIORAL BASELINE ANALYSIS
    # ========================================
    
    def calculate_baseline(self, endpoint_id: int):
        """
        Calculate behavioral baseline for an API endpoint
        Uses past 7 days of data to establish normal patterns
        """
        # Call stored procedure
        self.db.execute(text("CALL calculate_baseline(:endpoint_id)"), 
                       {'endpoint_id': endpoint_id})
        self.db.commit()
        
        print(f"✅ Baseline calculated for endpoint {endpoint_id}")
    
    def get_baseline(self, endpoint_id: int, metric_name: str) -> Optional[dict]:
        """Get baseline metrics for an endpoint"""
        query = text("""
            SELECT avg_value, min_value, max_value, std_deviation, sample_size
            FROM behavioral_baselines
            WHERE api_endpoint_id = :endpoint_id 
            AND metric_name = :metric_name
            AND is_active = TRUE
            ORDER BY last_updated DESC
            LIMIT 1
        """)
        
        result = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'metric_name': metric_name
        }).fetchone()
        
        if result:
            return {
                'avg': float(result[0]) if result[0] else 0,
                'min': float(result[1]) if result[1] else 0,
                'max': float(result[2]) if result[2] else 0,
                'std': float(result[3]) if result[3] else 0,
                'samples': int(result[4]) if result[4] else 0
            }
        return None
    
    # ========================================
    # ANOMALY DETECTION
    # ========================================
    
    def detect_anomalies(self, endpoint_id: int, time_window_minutes: int = 60):
        """
        Detect anomalies in API behavior for the specified time window
        
        Returns list of detected anomalies
        """
        anomalies = []
        
        # 1. Detect rate limit violations
        rate_anomalies = self._detect_rate_anomalies(endpoint_id, time_window_minutes)
        anomalies.extend(rate_anomalies)
        
        # 2. Detect response time anomalies
        response_time_anomalies = self._detect_response_time_anomalies(
            endpoint_id, time_window_minutes
        )
        anomalies.extend(response_time_anomalies)
        
        # 3. Detect error rate spikes
        error_anomalies = self._detect_error_rate_anomalies(
            endpoint_id, time_window_minutes
        )
        anomalies.extend(error_anomalies)
        
        # 4. Detect geographic anomalies
        geo_anomalies = self._detect_geographic_anomalies(
            endpoint_id, time_window_minutes
        )
        anomalies.extend(geo_anomalies)
        
        # 5. Detect brute force attacks
        brute_force_anomalies = self._detect_brute_force(
            endpoint_id, time_window_minutes
        )
        anomalies.extend(brute_force_anomalies)
        
        # Save anomalies to database
        for anomaly in anomalies:
            self._save_anomaly(anomaly)
        
        return anomalies
    
    def _detect_rate_anomalies(self, endpoint_id: int, time_window: int) -> List[dict]:
        """Detect unusual request rates"""
        anomalies = []
        
        query = text("""
            SELECT source_ip, COUNT(*) as request_count
            FROM api_request_logs
            WHERE api_endpoint_id = :endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL :minutes MINUTE)
            GROUP BY source_ip
            HAVING COUNT(*) > :threshold
        """)
        
        results = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'minutes': time_window,
            'threshold': self.rate_limit_threshold
        }).fetchall()
        
        for row in results:
            anomalies.append({
                'api_endpoint_id': endpoint_id,
                'anomaly_type': 'rate_limit_exceeded',
                'severity': 'high',
                'confidence_score': 90.0,
                'description': f"IP {row[0]} made {row[1]} requests in {time_window} minutes (threshold: {self.rate_limit_threshold})",
                'detection_details': json.dumps({
                    'source_ip': row[0],
                    'request_count': row[1],
                    'time_window_minutes': time_window,
                    'threshold': self.rate_limit_threshold
                })
            })
        
        return anomalies
    
    def _detect_response_time_anomalies(self, endpoint_id: int, time_window: int) -> List[dict]:
        """Detect unusual response times"""
        baseline = self.get_baseline(endpoint_id, 'response_time_ms')
        if not baseline or baseline['samples'] < 100:
            return []
        
        anomalies = []
        threshold = baseline['avg'] + (self.anomaly_threshold * baseline['std'])
        
        query = text("""
            SELECT id, source_ip, response_time_ms, request_timestamp
            FROM api_request_logs
            WHERE api_endpoint_id = :endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL :minutes MINUTE)
            AND response_time_ms > :threshold
            AND response_status < 400
        """)
        
        results = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'minutes': time_window,
            'threshold': threshold
        }).fetchall()
        
        for row in results:
            deviation = (row[2] - baseline['avg']) / baseline['std'] if baseline['std'] > 0 else 0
            
            anomalies.append({
                'api_endpoint_id': endpoint_id,
                'request_log_id': row[0],
                'anomaly_type': 'response_time_anomaly',
                'severity': 'medium' if deviation < 4 else 'high',
                'confidence_score': min(50 + (deviation * 10), 95),
                'description': f"Unusual response time: {row[2]}ms (avg: {baseline['avg']:.0f}ms, {deviation:.1f}σ)",
                'detection_details': json.dumps({
                    'source_ip': row[1],
                    'response_time_ms': row[2],
                    'baseline_avg': baseline['avg'],
                    'std_deviation': deviation,
                    'timestamp': row[3].isoformat() if row[3] else None
                })
            })
        
        return anomalies
    
    def _detect_error_rate_anomalies(self, endpoint_id: int, time_window: int) -> List[dict]:
        """Detect spikes in error rates"""
        query = text("""
            SELECT 
                COUNT(*) as total_requests,
                SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END) as error_count
            FROM api_request_logs
            WHERE api_endpoint_id = :endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL :minutes MINUTE)
        """)
        
        result = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'minutes': time_window
        }).fetchone()
        
        if not result or result[0] < 10:
            return []
        
        total = result[0]
        errors = result[1]
        error_rate = errors / total if total > 0 else 0
        
        # Alert if error rate > 25%
        if error_rate > 0.25:
            return [{
                'api_endpoint_id': endpoint_id,
                'anomaly_type': 'error_rate_spike',
                'severity': 'critical' if error_rate > 0.5 else 'high',
                'confidence_score': min(60 + (error_rate * 100), 95),
                'description': f"High error rate: {error_rate*100:.1f}% ({errors}/{total} requests)",
                'detection_details': json.dumps({
                    'error_rate': error_rate,
                    'total_requests': total,
                    'error_count': errors,
                    'time_window_minutes': time_window
                })
            }]
        
        return []
    
    def _detect_geographic_anomalies(self, endpoint_id: int, time_window: int) -> List[dict]:
        """Detect requests from unusual geographic locations"""
        # This is a placeholder - would need GeoIP integration
        # For now, detect rapid IP changes
        query = text("""
            SELECT COUNT(DISTINCT source_ip) as unique_ips
            FROM api_request_logs
            WHERE api_endpoint_id = :endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL :minutes MINUTE)
        """)
        
        result = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'minutes': time_window
        }).fetchone()
        
        unique_ips = result[0] if result else 0
        
        # Alert if too many unique IPs in short window (possible distributed attack)
        if unique_ips > 50 and time_window <= 15:
            return [{
                'api_endpoint_id': endpoint_id,
                'anomaly_type': 'geographic_anomaly',
                'severity': 'medium',
                'confidence_score': 70.0,
                'description': f"Unusual IP diversity: {unique_ips} unique IPs in {time_window} minutes",
                'detection_details': json.dumps({
                    'unique_ip_count': unique_ips,
                    'time_window_minutes': time_window
                })
            }]
        
        return []
    
    def _detect_brute_force(self, endpoint_id: int, time_window: int) -> List[dict]:
        """Detect brute force authentication attacks"""
        query = text("""
            SELECT source_ip, COUNT(*) as failed_attempts
            FROM api_request_logs
            WHERE api_endpoint_id = :endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL :minutes MINUTE)
            AND response_status IN (401, 403)
            GROUP BY source_ip
            HAVING COUNT(*) > 10
        """)
        
        results = self.db.execute(query, {
            'endpoint_id': endpoint_id,
            'minutes': time_window
        }).fetchall()
        
        anomalies = []
        for row in results:
            anomalies.append({
                'api_endpoint_id': endpoint_id,
                'anomaly_type': 'brute_force_attack',
                'severity': 'critical',
                'confidence_score': 85.0,
                'description': f"Possible brute force: {row[1]} failed auth attempts from {row[0]}",
                'detection_details': json.dumps({
                    'source_ip': row[0],
                    'failed_attempts': row[1],
                    'time_window_minutes': time_window
                })
            })
        
        return anomalies
    
    def _save_anomaly(self, anomaly: dict):
        """Save detected anomaly to database"""
        query = text("""
            INSERT INTO anomaly_detections 
            (api_endpoint_id, request_log_id, anomaly_type, severity, 
             confidence_score, description, detection_details)
            VALUES 
            (:endpoint_id, :request_log_id, :anomaly_type, :severity,
             :confidence, :description, :details)
        """)
        
        self.db.execute(query, {
            'endpoint_id': anomaly['api_endpoint_id'],
            'request_log_id': anomaly.get('request_log_id'),
            'anomaly_type': anomaly['anomaly_type'],
            'severity': anomaly['severity'],
            'confidence': anomaly['confidence_score'],
            'description': anomaly['description'],
            'details': anomaly['detection_details']
        })
        self.db.commit()
    
    # ========================================
    # ALERT GENERATION
    # ========================================
    
    def generate_alerts(self, endpoint_id: int):
        """
        Generate alerts for unreviewed anomalies
        
        Returns list of generated alerts
        """
        query = text("""
            SELECT id, anomaly_type, severity, description, detection_details
            FROM anomaly_detections
            WHERE api_endpoint_id = :endpoint_id
            AND status = 'new'
            AND detection_timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ORDER BY severity DESC, confidence_score DESC
        """)
        
        results = self.db.execute(query, {'endpoint_id': endpoint_id}).fetchall()
        
        alerts = []
        for row in results:
            alert = self._create_alert(endpoint_id, row)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _create_alert(self, endpoint_id: int, anomaly_data: tuple) -> Optional[dict]:
        """Create alert from anomaly detection"""
        anomaly_id, anomaly_type, severity, description, details = anomaly_data
        
        # Determine alert type and message
        alert_mapping = {
            'rate_limit_exceeded': 'High Request Volume',
            'response_time_anomaly': 'Performance Degradation',
            'error_rate_spike': 'Error Rate Spike',
            'brute_force_attack': 'Brute Force Attack',
            'geographic_anomaly': 'Unusual Traffic Pattern'
        }
        
        alert_type = alert_mapping.get(anomaly_type, 'Security Alert')
        
        # Insert alert
        query = text("""
            INSERT INTO alerts 
            (scan_id, alert_type, severity, source, message, anomaly_detection_id)
            VALUES 
            (NULL, :alert_type, :severity, 'surveillance', :message, :anomaly_id)
        """)
        
        result = self.db.execute(query, {
            'alert_type': alert_type,
            'severity': severity,
            'message': description,
            'anomaly_id': anomaly_id
        })
        self.db.commit()
        
        return {
            'id': result.lastrowid,
            'type': alert_type,
            'severity': severity,
            'message': description,
            'timestamp': datetime.now()
        }
    
    # ========================================
    # MONITORING DASHBOARD DATA
    # ========================================
    
    def get_dashboard_summary(self, endpoint_id: Optional[int] = None) -> dict:
        """Get summary data for monitoring dashboard"""
        
        # Recent anomalies
        recent_anomalies_query = text("""
            SELECT anomaly_type, severity, COUNT(*) as count
            FROM anomaly_detections
            WHERE detection_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """ + ("AND api_endpoint_id = :endpoint_id" if endpoint_id else "") + """
            GROUP BY anomaly_type, severity
        """)
        
        params = {'endpoint_id': endpoint_id} if endpoint_id else {}
        recent_anomalies = self.db.execute(recent_anomalies_query, params).fetchall()
        
        # Active alerts
        active_alerts_query = text("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE is_read = FALSE
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY severity
        """)
        
        active_alerts = self.db.execute(active_alerts_query).fetchall()
        
        # Top suspicious IPs
        suspicious_ips_query = text("""
            SELECT source_ip, COUNT(*) as suspicious_count
            FROM api_request_logs
            WHERE is_suspicious = TRUE
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """ + ("AND api_endpoint_id = :endpoint_id" if endpoint_id else "") + """
            GROUP BY source_ip
            ORDER BY COUNT(*) DESC
            LIMIT 10
        """)
        
        suspicious_ips = self.db.execute(suspicious_ips_query, params).fetchall()
        
        return {
            'recent_anomalies': [
                {'type': row[0], 'severity': row[1], 'count': row[2]} 
                for row in recent_anomalies
            ],
            'active_alerts': [
                {'severity': row[0], 'count': row[1]} 
                for row in active_alerts
            ],
            'suspicious_ips': [
                {'ip': row[0], 'count': row[1]} 
                for row in suspicious_ips
            ]
        }