"""
API Security Tester - Main Application
Author: Samriddhi Poudel (23047345)
Date: December 9, 2025
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
from scanner import APIScanner
from config import get_config

# Initialize Flask app
app = Flask(__name__)

# Load configuration
app.config.from_object(get_config())

# Enable CORS
CORS(app)

# Store scan history (temporary - will use database later)
scan_history = []


@app.route('/')
def home():
    """Home endpoint"""
    return jsonify({
        'message': 'API Security Tester - Running',
        'version': app.config['VERSION'],
        'status': 'active',
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
        'features': [
            'Vulnerability Scanning',
            'HTTPS Enforcement Check',
            'Security Headers Analysis',
            'HTTP Methods Testing'
        ]
    })


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': 'active'
    })


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
            'error': 'Invalid URL format. Must start with http:// or https://',
            'status': 'failed'
        }), 400
    
    try:
        # Create scanner and run scan
        scanner = APIScanner(target_url)
        results = scanner.scan_api()
        
        # Add to history
        scan_history.append(results)
        
        return jsonify({
            'status': 'success',
            'message': 'Scan completed',
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'failed'
        }), 500


@app.route('/api/history')
def get_scan_history():
    """Get scan history"""
    return jsonify({
        'status': 'success',
        'total_scans': len(scan_history),
        'scans': scan_history[-10:]  # Last 10 scans
    })


@app.route('/api/stats')
def get_stats():
    """Get application statistics"""
    total_scans = len(scan_history)
    
    if total_scans == 0:
        return jsonify({
            'total_scans': 0,
            'message': 'No scans performed yet'
        })
    
    # Calculate basic stats
    total_tests = sum(len(scan['tests']) for scan in scan_history)
    passed_tests = sum(
        sum(1 for test in scan['tests'] if test['status'] == 'PASS')
        for scan in scan_history
    )
    
    return jsonify({
        'total_scans': total_scans,
        'total_tests': total_tests,
        'passed_tests': passed_tests,
        'pass_rate': f"{(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "0%"
    })


if __name__ == '__main__':
    print("="*60)
    print(f"🔒 {app.config['APP_NAME']} v{app.config['VERSION']}")
    print("="*60)
    print(f"👨‍💻 Developer: Samriddhi Poudel (23047345)")
    print(f"📅 Week 1: Foundation & Setup Phase")
    print(f"🌐 Server: http://localhost:5000")
    print(f"📊 API Docs: http://localhost:5000/api/info")
    print("="*60)
    print("\n✅ Server starting...\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config['DEBUG']
    )