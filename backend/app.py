"""
API Security Tester - Main Application
Author: Samriddhi Poudel (23047345)
Date: December 10, 2025
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
from scanner import APIScanner
from config import get_config
from models import db, APIEndpoint, Scan, Vulnerability

# Initialize Flask app
app = Flask(__name__)

# Load configuration
app.config.from_object(get_config())

# Enable CORS
CORS(app)

# Initialize database
db.init_app(app)


@app.route('/')
def home():
    """Serve the main HTML page"""
    from flask import send_from_directory
    return send_from_directory('../frontend', 'index.html')


@app.route('/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files"""
    from flask import send_from_directory
    return send_from_directory('../frontend/css', filename)


@app.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files"""
    from flask import send_from_directory
    return send_from_directory('../frontend/js', filename)


@app.route('/api/')
def api_home():
    """API root - JSON response"""
    return jsonify({
        'message': 'API Security Tester - Running with Database',
        'version': app.config['VERSION'],
        'status': 'active',
        'database': 'connected',
        'developer': 'Samriddhi Poudel (23047345)'
    })


@app.route('/api/info')
def api_info():
    """API information endpoint"""
    return jsonify({
        'name': app.config['APP_NAME'],
        'version': app.config['VERSION'],
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'developer': 'Samriddhi Poudel (23047345)',
        'database': 'MySQL connected',
        'features': [
            'Vulnerability Scanning',
            'HTTPS Enforcement Check',
            'Security Headers Analysis',
            'HTTP Methods Testing',
            'Database Storage',
            'Scan History'
        ]
    })


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_status = 'connected'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/endpoints', methods=['GET'])
def get_endpoints():
    """Get all saved API endpoints"""
    try:
        endpoints = APIEndpoint.query.all()
        return jsonify({
            'status': 'success',
            'total': len(endpoints),
            'endpoints': [ep.to_dict() for ep in endpoints]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/endpoints', methods=['POST'])
def save_endpoint():
    """Save a new API endpoint"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'error': 'URL is required',
            'status': 'failed'
        }), 400
    
    try:
        endpoint = APIEndpoint(
            name=data.get('name', 'Unnamed API'),
            url=data['url'],
            method=data.get('method', 'GET'),
            headers=data.get('headers', ''),
            body=data.get('body', ''),
            description=data.get('description', '')
        )
        
        db.session.add(endpoint)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'API endpoint saved',
            'endpoint': endpoint.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/scan', methods=['POST'])
def scan_api():
    """Scan an API endpoint for vulnerabilities"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'error': 'URL is required',
            'status': 'failed'
        }), 400
    
    target_url = data['url']
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({
            'error': 'Invalid URL format',
            'status': 'failed'
        }), 400
    
    try:
        # Find or create endpoint
        endpoint = APIEndpoint.query.filter_by(url=target_url).first()
        if not endpoint:
            endpoint = APIEndpoint(
                name=data.get('name', 'Quick Scan'),
                url=target_url,
                method=data.get('method', 'GET')
            )
            db.session.add(endpoint)
            db.session.commit()
        
        # Run scanner
        scanner = APIScanner(target_url)
        scan_results = scanner.scan_api()
        
        # Create scan record
        scan = Scan(
            api_endpoint_id=endpoint.id,
            total_tests=len(scan_results['tests']),
            passed_tests=sum(1 for t in scan_results['tests'] if t['status'] == 'PASS'),
            failed_tests=sum(1 for t in scan_results['tests'] if t['status'] == 'FAIL'),
            warnings=sum(1 for t in scan_results['tests'] if t['status'] == 'WARNING')
        )
        db.session.add(scan)
        db.session.commit()
        
        # Save vulnerabilities
        for test in scan_results['tests']:
            vuln = Vulnerability(
                scan_id=scan.id,
                test_name=test['name'],
                category=test.get('category', 'General'),
                severity=test['status'],
                status=test['status'],
                details=test['details']
            )
            db.session.add(vuln)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Scan completed and saved',
            'scan_id': scan.id,
            'results': scan_results
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': str(e),
            'status': 'failed'
        }), 500


@app.route('/api/scans')
def get_scans():
    """Get scan history"""
    try:
        scans = Scan.query.order_by(Scan.scan_timestamp.desc()).limit(10).all()
        return jsonify({
            'status': 'success',
            'total': len(scans),
            'scans': [scan.to_dict() for scan in scans]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/stats')
def get_stats():
    """Get application statistics"""
    try:
        total_scans = Scan.query.count()
        total_endpoints = APIEndpoint.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        return jsonify({
            'total_scans': total_scans,
            'total_endpoints': total_endpoints,
            'total_vulnerabilities': total_vulnerabilities
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    print("="*60)
    print(f"🔒 {app.config['APP_NAME']} v{app.config['VERSION']}")
    print("="*60)
    print(f"👨‍💻 Developer: Samriddhi Poudel (23047345)")
    print(f"📅 Week 1: Foundation & Setup Phase")
    print(f"🗄️  Database: MySQL Connected")
    print(f"🌐 Server: http://localhost:8000")
    print(f"📊 API Docs: http://localhost:8000/api/info")
    print("="*60)
    print("\n✅ Server starting...\n")
    
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=app.config['DEBUG']
    )