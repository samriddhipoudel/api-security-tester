"""
Surveillance API Routes
Author: Samriddhi Poudel (23047345)
Date: February 5, 2026
Description: API endpoints for automated surveillance and monitoring
"""

from flask import Blueprint, request, jsonify
from models_surveillance import db
from surveillance import SurveillanceEngine
from sqlalchemy import text
from datetime import datetime, timedelta
import json

# Create blueprint
surveillance_bp = Blueprint('surveillance', __name__, url_prefix='/api/surveillance')

# Initialize surveillance engine
surveillance = SurveillanceEngine(db.session)


# ========================================
# REQUEST LOGGING ENDPOINTS
# ========================================

@surveillance_bp.route('/log-request', methods=['POST'])
def log_request():
    """
    Log an API request for surveillance
    
    Body:
    {
        "endpoint_id": int,
        "source_ip": str,
        "user_agent": str,
        "http_method": str,
        "request_path": str,
        "request_headers": {},
        "request_body": str,
        "response_status": int,
        "response_time_ms": int,
        "response_size_bytes": int
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'endpoint_id' not in data:
            return jsonify({'error': 'endpoint_id is required'}), 400
        
        request_log_id = surveillance.log_request(
            data['endpoint_id'],
            data
        )
        
        return jsonify({
            'success': True,
            'request_log_id': request_log_id,
            'message': 'Request logged successfully'
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========================================
# BASELINE CALCULATION ENDPOINTS
# ========================================

@surveillance_bp.route('/baseline/<int:endpoint_id>', methods=['POST'])
def calculate_baseline(endpoint_id):
    """Calculate behavioral baseline for an endpoint"""
    try:
        surveillance.calculate_baseline(endpoint_id)
        
        return jsonify({
            'success': True,
            'message': f'Baseline calculated for endpoint {endpoint_id}'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/baseline/<int:endpoint_id>/<metric_name>', methods=['GET'])
def get_baseline(endpoint_id, metric_name):
    """Get baseline metrics for an endpoint"""
    try:
        baseline = surveillance.get_baseline(endpoint_id, metric_name)
        
        if not baseline:
            return jsonify({
                'success': False,
                'message': 'Baseline not found'
            }), 404
        
        return jsonify({
            'success': True,
            'baseline': baseline
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========================================
# ANOMALY DETECTION ENDPOINTS
# ========================================

@surveillance_bp.route('/detect-anomalies/<int:endpoint_id>', methods=['POST'])
def detect_anomalies(endpoint_id):
    """
    Detect anomalies for an endpoint
    
    Query params:
    - time_window: Time window in minutes (default: 60)
    """
    try:
        time_window = request.args.get('time_window', 60, type=int)
        
        anomalies = surveillance.detect_anomalies(endpoint_id, time_window)
        
        return jsonify({
            'success': True,
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/anomalies', methods=['GET'])
def get_anomalies():
    """
    Get detected anomalies with filtering
    
    Query params:
    - endpoint_id: Filter by endpoint
    - severity: Filter by severity (critical, high, medium, low)
    - status: Filter by status (new, reviewed, false_positive)
    - limit: Number of results (default: 50)
    """
    try:
        endpoint_id = request.args.get('endpoint_id', type=int)
        severity = request.args.get('severity')
        status = request.args.get('status', 'new')
        limit = request.args.get('limit', 50, type=int)
        
        query = """
            SELECT 
                ad.id, ad.api_endpoint_id, ae.name as endpoint_name,
                ad.detection_timestamp, ad.anomaly_type, ad.severity,
                ad.confidence_score, ad.description, ad.detection_details,
                ad.status, ad.is_false_positive
            FROM anomaly_detections ad
            JOIN api_endpoints ae ON ad.api_endpoint_id = ae.id
            WHERE 1=1
        """
        params = {}
        
        if endpoint_id:
            query += " AND ad.api_endpoint_id = :endpoint_id"
            params['endpoint_id'] = endpoint_id
        
        if severity:
            query += " AND ad.severity = :severity"
            params['severity'] = severity
        
        if status:
            query += " AND ad.status = :status"
            params['status'] = status
        
        query += " ORDER BY ad.detection_timestamp DESC LIMIT :limit"
        params['limit'] = limit
        
        results = db.session.execute(text(query), params).fetchall()
        
        anomalies = []
        for row in results:
            anomalies.append({
                'id': row[0],
                'api_endpoint_id': row[1],
                'endpoint_name': row[2],
                'detection_timestamp': row[3].isoformat() if row[3] else None,
                'anomaly_type': row[4],
                'severity': row[5],
                'confidence_score': float(row[6]) if row[6] else 0.0,
                'description': row[7],
                'detection_details': json.loads(row[8]) if row[8] else {},
                'status': row[9],
                'is_false_positive': bool(row[10])
            })
        
        return jsonify({
            'success': True,
            'count': len(anomalies),
            'anomalies': anomalies
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/anomalies/<int:anomaly_id>/review', methods=['PUT'])
def review_anomaly(anomaly_id):
    """
    Mark an anomaly as reviewed or false positive
    
    Body:
    {
        "is_false_positive": bool,
        "reviewed_by": str
    }
    """
    try:
        data = request.get_json()
        
        is_false_positive = data.get('is_false_positive', False)
        reviewed_by = data.get('reviewed_by', 'system')
        
        query = text("""
            UPDATE anomaly_detections
            SET is_false_positive = :is_false_positive,
                reviewed_by = :reviewed_by,
                reviewed_at = NOW(),
                status = 'reviewed'
            WHERE id = :anomaly_id
        """)
        
        db.session.execute(query, {
            'is_false_positive': is_false_positive,
            'reviewed_by': reviewed_by,
            'anomaly_id': anomaly_id
        })
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Anomaly reviewed successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ========================================
# ALERT GENERATION ENDPOINTS
# ========================================

@surveillance_bp.route('/alerts/generate/<int:endpoint_id>', methods=['POST'])
def generate_alerts(endpoint_id):
    """Generate alerts for unreviewed anomalies"""
    try:
        alerts = surveillance.generate_alerts(endpoint_id)
        
        return jsonify({
            'success': True,
            'alerts_generated': len(alerts),
            'alerts': alerts
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """
    Get surveillance alerts
    
    Query params:
    - unread_only: Show only unread alerts (default: false)
    - severity: Filter by severity
    - limit: Number of results (default: 50)
    """
    try:
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        severity = request.args.get('severity')
        limit = request.args.get('limit', 50, type=int)
        
        query = """
            SELECT id, alert_type, severity, source, message, 
                   is_read, created_at, anomaly_detection_id
            FROM alerts
            WHERE source = 'surveillance'
        """
        params = {}
        
        if unread_only:
            query += " AND is_read = FALSE"
        
        if severity:
            query += " AND severity = :severity"
            params['severity'] = severity
        
        query += " ORDER BY created_at DESC LIMIT :limit"
        params['limit'] = limit
        
        results = db.session.execute(text(query), params).fetchall()
        
        alerts = []
        for row in results:
            alerts.append({
                'id': row[0],
                'alert_type': row[1],
                'severity': row[2],
                'source': row[3],
                'message': row[4],
                'is_read': bool(row[5]),
                'created_at': row[6].isoformat() if row[6] else None,
                'anomaly_detection_id': row[7]
            })
        
        return jsonify({
            'success': True,
            'count': len(alerts),
            'alerts': alerts
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/alerts/<int:alert_id>/mark-read', methods=['PUT'])
def mark_alert_read(alert_id):
    """Mark an alert as read"""
    try:
        query = text("""
            UPDATE alerts
            SET is_read = TRUE
            WHERE id = :alert_id
        """)
        
        db.session.execute(query, {'alert_id': alert_id})
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alert marked as read'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ========================================
# DASHBOARD & MONITORING ENDPOINTS
# ========================================

@surveillance_bp.route('/dashboard', methods=['GET'])
def get_dashboard():
    """
    Get surveillance dashboard summary
    
    Query params:
    - endpoint_id: Filter by endpoint (optional)
    """
    try:
        endpoint_id = request.args.get('endpoint_id', type=int)
        
        summary = surveillance.get_dashboard_summary(endpoint_id)
        
        return jsonify({
            'success': True,
            'summary': summary
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/stats/realtime', methods=['GET'])
def get_realtime_stats():
    """Get real-time surveillance statistics"""
    try:
        # Last 24 hours stats
        query = text("""
            SELECT 
                COUNT(*) as total_requests,
                SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_requests,
                AVG(response_time_ms) as avg_response_time,
                COUNT(DISTINCT source_ip) as unique_ips,
                SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END) as error_count
            FROM api_request_logs
            WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        
        result = db.session.execute(query).fetchone()
        
        stats = {
            'total_requests': result[0] or 0,
            'suspicious_requests': result[1] or 0,
            'avg_response_time_ms': float(result[2]) if result[2] else 0.0,
            'unique_ips': result[3] or 0,
            'error_count': result[4] or 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add anomaly counts
        anomaly_query = text("""
            SELECT severity, COUNT(*) as count
            FROM anomaly_detections
            WHERE detection_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY severity
        """)
        
        anomaly_results = db.session.execute(anomaly_query).fetchall()
        stats['anomalies_by_severity'] = {
            row[0]: row[1] for row in anomaly_results
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/stats/trends', methods=['GET'])
def get_trends():
    """
    Get surveillance trends over time
    
    Query params:
    - days: Number of days to analyze (default: 7)
    - endpoint_id: Filter by endpoint (optional)
    """
    try:
        days = request.args.get('days', 7, type=int)
        endpoint_id = request.args.get('endpoint_id', type=int)
        
        query = """
            SELECT 
                DATE(request_timestamp) as date,
                COUNT(*) as total_requests,
                SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_count,
                AVG(response_time_ms) as avg_response_time,
                COUNT(DISTINCT source_ip) as unique_ips
            FROM api_request_logs
            WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL :days DAY)
        """
        params = {'days': days}
        
        if endpoint_id:
            query += " AND api_endpoint_id = :endpoint_id"
            params['endpoint_id'] = endpoint_id
        
        query += " GROUP BY DATE(request_timestamp) ORDER BY date"
        
        results = db.session.execute(text(query), params).fetchall()
        
        trends = []
        for row in results:
            trends.append({
                'date': row[0].isoformat() if row[0] else None,
                'total_requests': row[1] or 0,
                'suspicious_count': row[2] or 0,
                'avg_response_time_ms': float(row[3]) if row[3] else 0.0,
                'unique_ips': row[4] or 0
            })
        
        return jsonify({
            'success': True,
            'trends': trends
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/suspicious-ips', methods=['GET'])
def get_suspicious_ips():
    """
    Get list of suspicious IP addresses
    
    Query params:
    - limit: Number of results (default: 20)
    - time_window: Hours to look back (default: 24)
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        time_window = request.args.get('time_window', 24, type=int)
        
        query = text("""
            SELECT 
                source_ip,
                COUNT(*) as total_requests,
                SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_count,
                AVG(anomaly_score) as avg_anomaly_score,
                MAX(request_timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT http_method) as methods_used
            FROM api_request_logs
            WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL :hours HOUR)
            AND is_suspicious = TRUE
            GROUP BY source_ip
            ORDER BY suspicious_count DESC, avg_anomaly_score DESC
            LIMIT :limit
        """)
        
        results = db.session.execute(query, {
            'hours': time_window,
            'limit': limit
        }).fetchall()
        
        suspicious_ips = []
        for row in results:
            suspicious_ips.append({
                'ip': row[0],
                'total_requests': row[1],
                'suspicious_count': row[2],
                'avg_anomaly_score': float(row[3]) if row[3] else 0.0,
                'last_seen': row[4].isoformat() if row[4] else None,
                'methods_used': row[5].split(',') if row[5] else []
            })
        
        return jsonify({
            'success': True,
            'count': len(suspicious_ips),
            'suspicious_ips': suspicious_ips
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========================================
# SURVEILLANCE RULES ENDPOINTS
# ========================================

@surveillance_bp.route('/rules', methods=['GET'])
def get_rules():
    """Get all surveillance rules"""
    try:
        query = text("""
            SELECT id, rule_name, rule_type, description, threshold_value,
                   time_window_minutes, severity, action_type, is_active,
                   trigger_count, last_triggered
            FROM surveillance_rules
            ORDER BY severity DESC, rule_name
        """)
        
        results = db.session.execute(query).fetchall()
        
        rules = []
        for row in results:
            rules.append({
                'id': row[0],
                'rule_name': row[1],
                'rule_type': row[2],
                'description': row[3],
                'threshold_value': float(row[4]) if row[4] else None,
                'time_window_minutes': row[5],
                'severity': row[6],
                'action_type': row[7],
                'is_active': bool(row[8]),
                'trigger_count': row[9],
                'last_triggered': row[10].isoformat() if row[10] else None
            })
        
        return jsonify({
            'success': True,
            'count': len(rules),
            'rules': rules
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@surveillance_bp.route('/rules/<int:rule_id>/toggle', methods=['PUT'])
def toggle_rule(rule_id):
    """Enable or disable a surveillance rule"""
    try:
        query = text("""
            UPDATE surveillance_rules
            SET is_active = NOT is_active
            WHERE id = :rule_id
        """)
        
        db.session.execute(query, {'rule_id': rule_id})
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Rule toggled successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Error handler
@surveillance_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@surveillance_bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500