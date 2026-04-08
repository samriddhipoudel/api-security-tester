"""
Flask Application
Author: Samriddhi Poudel (23047345)
Date: February 5, 2026
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from models_surveillance import db
from config import get_config
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__, static_folder='../frontend', static_url_path='')

config = get_config()
app.config.from_object(config)
app.config['SECRET_KEY'] = config.SECRET_KEY

db.init_app(app)
CORS(app, supports_credentials=True)

# ── Page routes ───────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return send_from_directory('../frontend', 'login.html')

@app.route('/login.html')
def login_page():
    return send_from_directory('../frontend', 'login.html')

@app.route('/dashboard.html')
def dashboard_page():
    return send_from_directory('../frontend', 'dashboard.html')

@app.route('/index.html')
def index_page():
    return send_from_directory('../frontend', 'index.html')

@app.route('/surveillance.html')
def surveillance_page():
    return send_from_directory('../frontend', 'surveillance.html')

# ── API routes ────────────────────────────────────────────────────────────────

@app.route('/api/info')
def api_info():
    return jsonify({'name': config.APP_NAME, 'version': config.VERSION, 'status': 'running'})

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/scan', methods=['POST'])
def scan_api():
    from scanner import APIScanner
    from models_surveillance import Scan, Vulnerability, APIEndpoint
    from datetime import datetime

    data = request.get_json()
    api_url = data.get('api_url') if data else None

    if not api_url:
        return jsonify({'error': 'API URL is required'}), 400

    try:
        scanner = APIScanner(api_url)
        results = scanner.scan_api()

        endpoint = APIEndpoint.query.filter_by(url=api_url).first()
        if not endpoint:
            endpoint = APIEndpoint(
                name=data.get('api_name') or f"API Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                url=api_url,
                method=data.get('http_method', 'GET'),
                description=data.get('description', '')
            )
            db.session.add(endpoint)
            db.session.flush()

        scan = Scan(
            api_endpoint_id=endpoint.id,
            scan_timestamp=datetime.now(),
            status='completed',
            total_tests=len(results['tests']),
            passed_tests=sum(1 for t in results['tests'] if t['status'] == 'PASS'),
            failed_tests=sum(1 for t in results['tests'] if t['status'] == 'FAIL'),
            warnings=sum(1 for t in results['tests'] if t['status'] == 'WARNING')
        )
        db.session.add(scan)
        db.session.flush()

        for test in results['tests']:
            vulnerability = Vulnerability(
                scan_id=scan.id,
                test_name=test['name'],
                status=test['status'],
                severity=test.get('severity', 'medium'),
                details=test['details']
            )
            db.session.add(vulnerability)

        db.session.commit()

        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'api_url': api_url,
            'timestamp': results['timestamp'],
            'total_tests': len(results['tests']),
            'passed':   sum(1 for t in results['tests'] if t['status'] == 'PASS'),
            'failed':   sum(1 for t in results['tests'] if t['status'] == 'FAIL'),
            'warnings': sum(1 for t in results['tests'] if t['status'] == 'WARNING'),
            'tests': results['tests']
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/endpoints', methods=['GET', 'POST'])
def manage_endpoints():
    from models_surveillance import APIEndpoint

    if request.method == 'GET':
        endpoints = APIEndpoint.query.all()
        return jsonify({'success': True, 'endpoints': [ep.to_dict() for ep in endpoints]})

    data = request.get_json()
    endpoint = APIEndpoint(
        name=data.get('name'),
        url=data.get('url'),
        method=data.get('method', 'GET'),
        headers=data.get('headers', ''),
        body=data.get('body', ''),
        description=data.get('description', '')
    )
    db.session.add(endpoint)
    db.session.commit()
    return jsonify({'success': True, 'endpoint': endpoint.to_dict()}), 201


@app.route('/api/scans', methods=['GET'])
def get_scans():
    from models_surveillance import Scan
    scans = Scan.query.order_by(Scan.scan_timestamp.desc()).limit(10).all()
    result = []
    for scan in scans:
        endpoint = scan.api_endpoint if hasattr(scan, 'api_endpoint') else None
        result.append({
            'id':             scan.id,
            'api_url':        endpoint.url  if endpoint else '',
            'api_name':       endpoint.name if endpoint else 'Unknown API',
            'scan_timestamp': scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S') if scan.scan_timestamp else '',
            'status':         scan.status or 'completed',
            'total_tests':    scan.total_tests  or 0,
            'passed':         scan.passed_tests or 0,
            'failed':         scan.failed_tests or 0,
            'warnings':       scan.warnings     or 0,
            'passed_tests':   scan.passed_tests or 0,
            'failed_tests':   scan.failed_tests or 0,
        })
    return jsonify({'success': True, 'scans': result})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    from models_surveillance import Scan, APIEndpoint
    from sqlalchemy import func
    total_scans     = db.session.query(func.count(Scan.id)).scalar()
    total_endpoints = db.session.query(func.count(APIEndpoint.id)).scalar()
    last_scan       = Scan.query.order_by(Scan.scan_timestamp.desc()).first()
    return jsonify({
        'total_scans':     total_scans or 0,
        'total_endpoints': total_endpoints or 0,
        'last_scan': last_scan.scan_timestamp.isoformat() if last_scan else None
    })


@app.route('/api/reports/<fmt>/<int:scan_id>')
def download_report(fmt, scan_id):
    from report_generator import ReportGenerator
    from models_surveillance import Scan
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    try:
        gen = ReportGenerator(scan)
        if fmt == 'pdf':
            return gen.generate_pdf()
        elif fmt == 'json':
            return gen.generate_json()
        elif fmt == 'csv':
            return gen.generate_csv()
        else:
            return jsonify({'error': 'Invalid format'}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/surveillance/alert-email', methods=['POST'])
def send_alert_email():
    """
    Send email alert. Flowchart: Vulnerability Detected -> send alert / approve deployment
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    recipient   = data.get('email', '').strip()
    if not recipient or '@' not in recipient:
        return jsonify({'error': 'Invalid email address'}), 400

    severity    = data.get('severity', 'unknown').upper()
    alert_type  = data.get('type', 'Security Alert')
    description = data.get('description', '')
    target      = data.get('target', '')
    timestamp   = data.get('timestamp', '')

    if severity in ('CRITICAL', 'HIGH'):
        subject_prefix = '[CRITICAL ISSUE]'
    elif severity in ('MEDIUM', 'LOW'):
        subject_prefix = '[MEDIUM/LOW ISSUE]'
    elif severity == 'NONE':
        subject_prefix = '[NO ISSUES - APPROVED]'
    else:
        subject_prefix = '[SECURITY ALERT]'

    subject = '{} {} - API Security Tester'.format(subject_prefix, alert_type)

    body = """API Security Tester - Automated Surveillance Alert
=====================================================

Alert Type:  {alert_type}
Severity:    {severity}
Target API:  {target}
Detected At: {timestamp}

Description:
{description}

-----------------------------------------------------
This alert was generated automatically by your API Security Tester
surveillance engine. Open your dashboard to review the full anomaly log.

http://127.0.0.1:8000/surveillance.html
""".format(
        alert_type=alert_type, severity=severity,
        target=target, timestamp=timestamp, description=description
    )

    smtp_host = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = 'apisecuritytester@gmail.com'
    smtp_pass = 'eant hafj viai pxvw'

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = smtp_user
        msg['To']      = recipient
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipient, msg.as_string())

        return jsonify({'success': True, 'message': 'Alert email sent to {}'.format(recipient)})

    except Exception as e:
        print('[ALERT EMAIL] Failed: {}'.format(str(e)))
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

    print("\n" + "=" * 60)
    print("API Security Tester - Server Starting")
    print("=" * 60)
    print(f"Server:    http://127.0.0.1:8000")
    print(f"Dashboard: http://127.0.0.1:8000/dashboard.html")
    print(f"Scanner:   http://127.0.0.1:8000/index.html")
    print("=" * 60 + "\n")

    app.run(host='127.0.0.1', port=8000, debug=True)