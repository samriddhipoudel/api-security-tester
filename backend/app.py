"""
API Security Tester - Main Application
Author: Samriddhi Poudel (23047345)
Date: December 10, 2025
"""

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from datetime import datetime
from scanner import APIScanner
from config import get_config
from models_surveillance import db, APIEndpoint, Scan, Vulnerability
from report_generator import SecurityReportGenerator
import json
import csv
import io


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
    return send_from_directory('../frontend', 'index.html')


@app.route('/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files"""
    return send_from_directory('../frontend/css', filename)


@app.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files"""
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
            'Scan History',
            'PDF Report Generation',
            'JSON/CSV Export'
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


# COMBINED ROUTE - Get all scans (FIXED: removed duplicate)
@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    """Get list of all completed scans"""
    try:
        scans = Scan.query.order_by(Scan.scan_timestamp.desc()).all()
        
        scan_list = [
            {
                'id': scan.id,
                'api_url': scan.api_endpoint.url if scan.api_endpoint else 'Unknown',
                'api_name': scan.api_endpoint.name if scan.api_endpoint else 'Unknown',
                'scan_timestamp': scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'status': scan.status,
                'total_tests': Vulnerability.query.filter_by(scan_id=scan.id).count(),
                'passed': Vulnerability.query.filter_by(scan_id=scan.id, status='PASS').count(),
                'failed': Vulnerability.query.filter_by(scan_id=scan.id, status='FAIL').count()
            }
            for scan in scans
        ]
        
        return jsonify({
            'success': True,
            'scans': scan_list,
            'total': len(scan_list)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get detailed scan results for a specific scan
@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """Get detailed results for a specific scan"""
    try:
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        scan_details = {
            'id': scan.id,
            'api_endpoint': {
                'name': scan.api_endpoint.name if scan.api_endpoint else 'Unknown',
                'url': scan.api_endpoint.url if scan.api_endpoint else 'Unknown',
                'method': scan.api_endpoint.method if scan.api_endpoint else 'GET'
            },
            'scan_timestamp': scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'summary': {
                'total_tests': len(vulnerabilities),
                'passed': sum(1 for v in vulnerabilities if v.status == 'PASS'),
                'failed': sum(1 for v in vulnerabilities if v.status == 'FAIL'),
                'warnings': sum(1 for v in vulnerabilities if v.status == 'WARNING')
            },
            'vulnerabilities': [
                {
                    'test_name': v.test_name,
                    'status': v.status,
                    'severity': v.severity,
                    'details': v.details
                }
                for v in vulnerabilities
            ]
        }
        
        return jsonify({
            'success': True,
            'scan': scan_details
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


# ============ REPORT GENERATION ROUTES ============

@app.route('/api/reports/pdf/<int:scan_id>', methods=['GET'])
def generate_pdf_report(scan_id):
    """Generate and download PDF report for a scan"""
    try:
        # Fetch scan data
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        # Prepare scan data
        scan_data = {
            'api_url': scan.api_endpoint.url if scan.api_endpoint else 'Unknown',
            'scan_timestamp': scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'total_tests': len(vulnerabilities),
            'passed': sum(1 for v in vulnerabilities if v.status == 'PASS'),
            'failed': sum(1 for v in vulnerabilities if v.status == 'FAIL'),
            'warnings': sum(1 for v in vulnerabilities if v.status == 'WARNING'),
            'vulnerabilities': [
                {
                    'test_name': v.test_name,
                    'status': v.status,
                    'severity': v.severity,
                    'details': v.details
                }
                for v in vulnerabilities
            ]
        }
        
        # Generate PDF
        generator = SecurityReportGenerator()
        pdf_buffer = generator.generate_report(scan_data)
        
        # Send file
        filename = f"security_report_scan_{scan_id}.pdf"
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        print(f"PDF Generation Error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/json/<int:scan_id>', methods=['GET'])
def export_json_report(scan_id):
    """Export scan results as JSON"""
    try:
        # Fetch scan data
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        # Prepare JSON data
        report_data = {
            'scan_id': scan.id,
            'api_endpoint': {
                'name': scan.api_endpoint.name if scan.api_endpoint else None,
                'url': scan.api_endpoint.url if scan.api_endpoint else 'Unknown',
                'method': scan.api_endpoint.method if scan.api_endpoint else 'GET'
            },
            'scan_timestamp': scan.scan_timestamp.isoformat(),
            'status': scan.status,
            'summary': {
                'total_tests': len(vulnerabilities),
                'passed': sum(1 for v in vulnerabilities if v.status == 'PASS'),
                'failed': sum(1 for v in vulnerabilities if v.status == 'FAIL'),
                'warnings': sum(1 for v in vulnerabilities if v.status == 'WARNING')
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'test_name': v.test_name,
                    'status': v.status,
                    'severity': v.severity,
                    'details': v.details,
                    'timestamp': v.created_at.isoformat() if hasattr(v, 'created_at') and v.created_at else None
                }
                for v in vulnerabilities
            ]
        }
        
        # Create JSON buffer
        json_buffer = io.BytesIO()
        json_buffer.write(json.dumps(report_data, indent=2).encode('utf-8'))
        json_buffer.seek(0)
        
        filename = f"security_report_scan_{scan_id}.json"
        return send_file(
            json_buffer,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        print(f"JSON Export Error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/csv/<int:scan_id>', methods=['GET'])
def export_csv_report(scan_id):
    """Export scan results as CSV"""
    try:
        # Fetch scan data
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        # Create CSV buffer
        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)
        
        # Write header
        csv_writer.writerow([
            'Test Name',
            'Status',
            'Severity',
            'Details',
            'API URL',
            'Scan Date'
        ])
        
        # Write vulnerability data
        for v in vulnerabilities:
            csv_writer.writerow([
                v.test_name,
                v.status,
                v.severity,
                v.details,
                scan.api_endpoint.url if scan.api_endpoint else 'Unknown',
                scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Convert to bytes
        csv_buffer.seek(0)
        bytes_buffer = io.BytesIO(csv_buffer.getvalue().encode('utf-8'))
        
        filename = f"security_report_scan_{scan_id}.csv"
        return send_file(
            bytes_buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        print(f"CSV Export Error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("="*60)
    print(f" {app.config['APP_NAME']} v{app.config['VERSION']}")
    print("="*60)
    print(f" Developer: Samriddhi Poudel (23047345)")
    print(f" Database: MySQL Connected")
    print(f" Server: http://localhost:8000")
    print(f" API Docs: http://localhost:8000/api/info")
    print("="*60)
    print("\n Server starting...\n")
    
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=app.config['DEBUG']
    )
    