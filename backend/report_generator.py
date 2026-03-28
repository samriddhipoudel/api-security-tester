"""
Report Generator - PDF, JSON, CSV export
Author: Samriddhi Poudel (23047345)
Date: December 2025
"""

import io
import json
import csv
from datetime import datetime
from flask import Response

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


# Severity colour map
SEV_COLORS = {
    'critical': colors.HexColor('#ef4444'),
    'high':     colors.HexColor('#f59e0b'),
    'medium':   colors.HexColor('#667eea'),
    'low':      colors.HexColor('#10b981'),
    'info':     colors.HexColor('#3b82f6'),
}
STATUS_COLORS = {
    'PASS':    colors.HexColor('#10b981'),
    'FAIL':    colors.HexColor('#ef4444'),
    'WARNING': colors.HexColor('#f59e0b'),
    'ERROR':   colors.HexColor('#9ca3af'),
}


class ReportGenerator:
    """
    Generates PDF, JSON and CSV reports from a Scan model instance.
    Usage:
        gen = ReportGenerator(scan)
        return gen.generate_pdf()   # Flask Response
        return gen.generate_json()  # Flask Response
        return gen.generate_csv()   # Flask Response
    """

    def __init__(self, scan):
        self.scan = scan
        self.scan_data = self._build_scan_data(scan)

    # ── Data builder ──────────────────────────────────────────────────────────

    def _build_scan_data(self, scan):
        vuln_list = []
        try:
            for v in scan.vulnerabilities:
                vuln_list.append({
                    'test_name': v.test_name or '',
                    'status':    v.status    or '',
                    'severity':  v.severity  or 'medium',
                    'details':   v.details   or '',
                })
        except Exception:
            pass

        passed   = sum(1 for v in vuln_list if v['status'] == 'PASS')
        failed   = sum(1 for v in vuln_list if v['status'] == 'FAIL')
        warnings = sum(1 for v in vuln_list if v['status'] == 'WARNING')
        total    = len(vuln_list) or getattr(scan, 'total_tests', 0)

        # Risk score 0-100
        risk = 0
        if total:
            risk = min(100, int((failed * 10 + warnings * 3) / total * 10))

        if risk == 0:       risk_label = 'LOW'
        elif risk <= 30:    risk_label = 'MEDIUM'
        elif risk <= 60:    risk_label = 'HIGH'
        else:               risk_label = 'CRITICAL'

        endpoint = getattr(scan, 'api_endpoint', None)
        api_url  = ''
        api_name = ''
        if endpoint:
            api_url  = getattr(endpoint, 'url',  '') or ''
            api_name = getattr(endpoint, 'name', '') or ''

        ts = getattr(scan, 'scan_timestamp', None)
        timestamp = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return {
            'scan_id':        getattr(scan, 'id', 'N/A'),
            'api_url':        api_url,
            'api_name':       api_name,
            'scan_timestamp': timestamp,
            'status':         getattr(scan, 'status', 'completed'),
            'total_tests':    total,
            'passed':         passed,
            'failed':         failed,
            'warnings':       warnings,
            'risk_score':     risk,
            'risk_label':     risk_label,
            'vulnerabilities': vuln_list,
        }

    # ── PDF ───────────────────────────────────────────────────────────────────

    def generate_pdf(self):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
            title='API Security Scan Report'
        )

        styles = getSampleStyleSheet()
        PURPLE = colors.HexColor('#667eea')
        DARK   = colors.HexColor('#1e1b4b')
        MUTED  = colors.HexColor('#6b7280')
        WHITE  = colors.white

        h1 = ParagraphStyle('h1', fontSize=22, textColor=WHITE,     fontName='Helvetica-Bold', spaceAfter=4)
        h2 = ParagraphStyle('h2', fontSize=13, textColor=DARK,      fontName='Helvetica-Bold', spaceAfter=6, spaceBefore=10)
        h3 = ParagraphStyle('h3', fontSize=10, textColor=DARK,      fontName='Helvetica-Bold', spaceAfter=4)
        normal = ParagraphStyle('n', fontSize=9,  textColor=DARK,   fontName='Helvetica',      spaceAfter=3, leading=13)
        small  = ParagraphStyle('s', fontSize=8,  textColor=MUTED,  fontName='Helvetica',      spaceAfter=2)
        right  = ParagraphStyle('r', fontSize=9,  textColor=WHITE,  fontName='Helvetica',      alignment=TA_RIGHT)

        d = self.scan_data
        story = []

        # ── Header banner ────────────────────────────────────────────────────
        risk_color = SEV_COLORS.get(d['risk_label'].lower(), PURPLE)
        header_table = Table([
            [
                Paragraph('API Security Scan Report', h1),
                Paragraph(d['risk_label'] + ' RISK', right)
            ]
        ], colWidths=[120*mm, 60*mm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,-1), PURPLE),
            ('BACKGROUND',  (1,0), (1,0),   risk_color),
            ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING',(0,0), (-1,-1), 10),
            ('TOPPADDING',  (0,0), (-1,-1), 12),
            ('BOTTOMPADDING',(0,0),(-1,-1), 12),
            ('ROUNDEDCORNERS', [6]),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 8*mm))

        # ── Scan info table ──────────────────────────────────────────────────
        story.append(Paragraph('Scan Information', h2))
        info_data = [
            ['Scan ID',       str(d['scan_id'])],
            ['API Name',      d['api_name'] or 'N/A'],
            ['API URL',       d['api_url']  or 'N/A'],
            ['Scan Date',     d['scan_timestamp']],
            ['Status',        d['status'].upper()],
            ['Generated By',  'API Security Tester v1.0.0 — Samriddhi Poudel (23047345)'],
            ['Institution',   'London Metropolitan University'],
        ]
        info_table = Table(info_data, colWidths=[45*mm, 135*mm])
        info_table.setStyle(TableStyle([
            ('FONTNAME',      (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME',      (1,0), (1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 9),
            ('TEXTCOLOR',     (0,0), (0,-1), MUTED),
            ('TEXTCOLOR',     (1,0), (1,-1), DARK),
            ('ROWBACKGROUNDS',(0,0), (-1,-1), [colors.HexColor('#f9fafb'), WHITE]),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
            ('ROUNDEDCORNERS', [4]),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 6*mm))

        # ── Summary stats ────────────────────────────────────────────────────
        story.append(Paragraph('Executive Summary', h2))

        def stat_cell(label, value, color):
            return Table([[
                Paragraph('<font color="white"><b>' + str(value) + '</b></font>',
                          ParagraphStyle('sv', fontSize=24, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph('<font color="white">' + label + '</font>',
                          ParagraphStyle('sl', fontSize=9,  fontName='Helvetica',      alignment=TA_CENTER)),
            ]], colWidths=[40*mm])

        total_t = str(d['total_tests'])
        pass_t  = str(d['passed'])
        fail_t  = str(d['failed'])
        warn_t  = str(d['warnings'])
        risk_t  = str(d['risk_score']) + '%'

        stats_data = [[
            Paragraph(total_t,  ParagraphStyle('bv', fontSize=26, fontName='Helvetica-Bold', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph(pass_t,   ParagraphStyle('bv', fontSize=26, fontName='Helvetica-Bold', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph(fail_t,   ParagraphStyle('bv', fontSize=26, fontName='Helvetica-Bold', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph(warn_t,   ParagraphStyle('bv', fontSize=26, fontName='Helvetica-Bold', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph(risk_t,   ParagraphStyle('bv', fontSize=26, fontName='Helvetica-Bold', alignment=TA_CENTER, textColor=WHITE)),
        ],[
            Paragraph('Total Tests', ParagraphStyle('bl', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph('Passed',      ParagraphStyle('bl', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph('Failed',      ParagraphStyle('bl', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph('Warnings',    ParagraphStyle('bl', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=WHITE)),
            Paragraph('Risk Score',  ParagraphStyle('bl', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=WHITE)),
        ]]

        stats_table = Table(stats_data, colWidths=[36*mm]*5)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (0,1), colors.HexColor('#667eea')),
            ('BACKGROUND',   (1,0), (1,1), colors.HexColor('#10b981')),
            ('BACKGROUND',   (2,0), (2,1), colors.HexColor('#ef4444')),
            ('BACKGROUND',   (3,0), (3,1), colors.HexColor('#f59e0b')),
            ('BACKGROUND',   (4,0), (4,1), risk_color),
            ('ALIGN',        (0,0), (-1,-1), 'CENTER'),
            ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING',   (0,0), (-1,-1), 8),
            ('BOTTOMPADDING',(0,0), (-1,-1), 8),
            ('ROUNDEDCORNERS', [6]),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 6*mm))

        # ── Risk assessment ──────────────────────────────────────────────────
        story.append(Paragraph('Risk Assessment', h2))
        risk_descriptions = {
            'LOW':      'The API passed most security tests. Minor issues may exist but pose limited risk. Regular monitoring recommended.',
            'MEDIUM':   'The API has some security weaknesses that should be addressed. Review warnings and consider remediation.',
            'HIGH':     'Significant security issues detected. Immediate review and remediation strongly recommended before production use.',
            'CRITICAL': 'Critical vulnerabilities found. This API should NOT be used in production until issues are resolved.',
        }
        risk_bg = {
            'LOW':      colors.HexColor('#d1fae5'),
            'MEDIUM':   colors.HexColor('#fef3c7'),
            'HIGH':     colors.HexColor('#fee2e2'),
            'CRITICAL': colors.HexColor('#fee2e2'),
        }
        risk_desc = risk_descriptions.get(d['risk_label'], '')
        risk_para = Table([[
            Paragraph('<b>Risk Level: ' + d['risk_label'] + '</b><br/>' + risk_desc,
                      ParagraphStyle('rp', fontSize=9, fontName='Helvetica', textColor=DARK, leading=14))
        ]], colWidths=[180*mm])
        risk_para.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (-1,-1), risk_bg.get(d['risk_label'], colors.HexColor('#f9fafb'))),
            ('LEFTPADDING',  (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING',   (0,0), (-1,-1), 8),
            ('BOTTOMPADDING',(0,0), (-1,-1), 8),
            ('BOX',          (0,0), (-1,-1), 1, risk_color),
            ('ROUNDEDCORNERS', [4]),
        ]))
        story.append(risk_para)
        story.append(Spacer(1, 6*mm))

        # ── Detailed findings ────────────────────────────────────────────────
        story.append(Paragraph('Detailed Test Findings', h2))

        vuln_header = [
            Paragraph('#',         ParagraphStyle('th', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER)),
            Paragraph('Test Name', ParagraphStyle('th', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
            Paragraph('Status',    ParagraphStyle('th', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER)),
            Paragraph('Severity',  ParagraphStyle('th', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER)),
            Paragraph('Details',   ParagraphStyle('th', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
        ]
        vuln_rows = [vuln_header]

        for i, v in enumerate(d['vulnerabilities'], 1):
            st  = v['status']
            sev = v['severity'].lower()
            st_color  = STATUS_COLORS.get(st,  MUTED)
            sev_color = SEV_COLORS.get(sev, MUTED)

            row = [
                Paragraph(str(i), ParagraphStyle('n', fontSize=8, fontName='Helvetica', alignment=TA_CENTER, textColor=MUTED)),
                Paragraph(v['test_name'], ParagraphStyle('n', fontSize=8, fontName='Helvetica-Bold', textColor=DARK)),
                Paragraph(st,  ParagraphStyle('n', fontSize=8, fontName='Helvetica-Bold', textColor=st_color,  alignment=TA_CENTER)),
                Paragraph(sev.upper(), ParagraphStyle('n', fontSize=8, fontName='Helvetica-Bold', textColor=sev_color, alignment=TA_CENTER)),
                Paragraph(v['details'][:200] if v['details'] else '', ParagraphStyle('n', fontSize=7.5, fontName='Helvetica', textColor=DARK, leading=11)),
            ]
            vuln_rows.append(row)

        vuln_table = Table(vuln_rows, colWidths=[8*mm, 42*mm, 16*mm, 18*mm, 96*mm], repeatRows=1)
        row_colors = []
        for i in range(1, len(vuln_rows)):
            bg = colors.HexColor('#f9fafb') if i % 2 == 0 else WHITE
            row_colors.append(('BACKGROUND', (0,i), (-1,i), bg))

        vuln_table.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (-1,0),  PURPLE),
            ('TOPPADDING',   (0,0), (-1,-1), 5),
            ('BOTTOMPADDING',(0,0), (-1,-1), 5),
            ('LEFTPADDING',  (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('GRID',         (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
            ('VALIGN',       (0,0), (-1,-1), 'TOP'),
        ] + row_colors))
        story.append(vuln_table)
        story.append(Spacer(1, 6*mm))

        # ── Recommendations ──────────────────────────────────────────────────
        story.append(Paragraph('Recommendations', h2))
        recs = self._build_recommendations(d['vulnerabilities'])
        if recs:
            for rec in recs:
                story.append(Paragraph('• ' + rec, normal))
        else:
            story.append(Paragraph('No critical issues found. Continue regular security monitoring.', normal))
        story.append(Spacer(1, 6*mm))

        # ── Footer ───────────────────────────────────────────────────────────
        story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#e5e7eb')))
        story.append(Spacer(1, 3*mm))
        footer_text = (
            'Generated by API Security Tester v1.0.0 | '
            'Author: Samriddhi Poudel (23047345) | '
            'London Metropolitan University | '
            'Final Year Project 2025 | '
            + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        story.append(Paragraph(footer_text, ParagraphStyle('ft', fontSize=7, textColor=MUTED, alignment=TA_CENTER)))

        doc.build(story)
        buf.seek(0)

        filename = 'security_report_scan_{}.pdf'.format(d['scan_id'])
        return Response(
            buf.read(),
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename="{}"'.format(filename)}
        )

    # ── JSON ──────────────────────────────────────────────────────────────────

    def generate_json(self):
        d = self.scan_data
        output = {
            'report_metadata': {
                'generated_at':  datetime.now().isoformat(),
                'generated_by':  'API Security Tester v1.0.0',
                'author':        'Samriddhi Poudel (23047345)',
                'institution':   'London Metropolitan University',
            },
            'scan_info': {
                'scan_id':        d['scan_id'],
                'api_name':       d['api_name'],
                'api_url':        d['api_url'],
                'scan_timestamp': d['scan_timestamp'],
                'status':         d['status'],
            },
            'summary': {
                'total_tests': d['total_tests'],
                'passed':      d['passed'],
                'failed':      d['failed'],
                'warnings':    d['warnings'],
                'risk_score':  d['risk_score'],
                'risk_label':  d['risk_label'],
            },
            'findings': d['vulnerabilities'],
            'recommendations': self._build_recommendations(d['vulnerabilities']),
        }

        filename = 'security_report_scan_{}.json'.format(d['scan_id'])
        return Response(
            json.dumps(output, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="{}"'.format(filename)}
        )

    # ── CSV ───────────────────────────────────────────────────────────────────

    def generate_csv(self):
        d = self.scan_data
        buf = io.StringIO()
        writer = csv.writer(buf)

        # Header block
        writer.writerow(['API Security Scan Report'])
        writer.writerow(['Generated By', 'API Security Tester v1.0.0 — Samriddhi Poudel (23047345)'])
        writer.writerow(['Institution',  'London Metropolitan University'])
        writer.writerow(['Generated At', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])

        # Scan info
        writer.writerow(['Scan ID',   d['scan_id']])
        writer.writerow(['API Name',  d['api_name']])
        writer.writerow(['API URL',   d['api_url']])
        writer.writerow(['Scan Date', d['scan_timestamp']])
        writer.writerow(['Status',    d['status']])
        writer.writerow([])

        # Summary
        writer.writerow(['SUMMARY'])
        writer.writerow(['Total Tests', 'Passed', 'Failed', 'Warnings', 'Risk Score', 'Risk Level'])
        writer.writerow([d['total_tests'], d['passed'], d['failed'], d['warnings'],
                         str(d['risk_score']) + '%', d['risk_label']])
        writer.writerow([])

        # Findings
        writer.writerow(['DETAILED FINDINGS'])
        writer.writerow(['#', 'Test Name', 'Status', 'Severity', 'Details'])
        for i, v in enumerate(d['vulnerabilities'], 1):
            writer.writerow([i, v['test_name'], v['status'], v['severity'], v['details']])
        writer.writerow([])

        # Recommendations
        writer.writerow(['RECOMMENDATIONS'])
        recs = self._build_recommendations(d['vulnerabilities'])
        for rec in recs:
            writer.writerow([rec])

        filename = 'security_report_scan_{}.csv'.format(d['scan_id'])
        return Response(
            buf.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename="{}"'.format(filename)}
        )

    # ── Recommendations builder ───────────────────────────────────────────────

    def _build_recommendations(self, vulnerabilities):
        recs = []
        names = [v['test_name'] for v in vulnerabilities if v['status'] in ('FAIL', 'WARNING')]

        rec_map = {
            'HTTPS Enforcement':         'Enable HTTPS on all API endpoints. Use TLS 1.2 or higher and redirect all HTTP traffic to HTTPS.',
            'Security Headers Check':    'Add missing HTTP security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy.',
            'SQL Injection Vulnerability':'Use parameterised queries or an ORM. Never interpolate user input directly into SQL statements.',
            'XSS Vulnerability':         'Sanitise and encode all user-supplied input. Implement a strict Content-Security-Policy header.',
            'Broken Authentication':     'Enforce authentication on all endpoints. Use strong token-based auth (JWT/OAuth2) and invalidate tokens on logout.',
            'Rate Limiting':             'Implement rate limiting (e.g. 100 requests/min per IP) to prevent brute force and DoS attacks.',
            'Excessive Data Exposure':   'Audit API responses and remove sensitive fields (passwords, tokens, secrets) before returning data to clients.',
            'SSRF Vulnerability':        'Validate and whitelist all URLs accepted as input. Block requests to internal/private IP ranges.',
            'HTTP Methods Check':        'Disable unnecessary HTTP methods (DELETE, PUT, PATCH) on endpoints that do not require them.',
            'Endpoint Reachability':     'Ensure the API endpoint is reachable and returns expected status codes. Check server logs for errors.',
        }

        for name in names:
            for key, rec in rec_map.items():
                if key.lower() in name.lower() and rec not in recs:
                    recs.append(rec)

        if not recs and vulnerabilities:
            recs.append('Continue regular security scanning and keep all dependencies up to date.')

        return recs