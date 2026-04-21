#  API Security Tester

An automated API security testing tool that scans APIs against the **OWASP API Security Top 10**. Built as a Final Year Project at London Metropolitan University.

**Author:** Samriddhi Poudel (23047345)  
**Institution:** London Metropolitan University  
**Academic Year:** 2025/26

---

##  Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Security Tests](#security-tests)
- [API Endpoints](#api-endpoints)
- [Report Export](#report-export)
- [Surveillance Module](#surveillance-module)
- [Default Credentials](#default-credentials)
- [Screenshots](#screenshots)

---

##  Overview

API Security Tester is a full-stack web application that performs automated vulnerability scanning on any HTTP/HTTPS API endpoint. It runs 10 security tests in parallel, stores results in a MySQL database, generates professional reports in PDF, JSON, and CSV formats, and includes a real-time surveillance module for anomaly detection.

---

##  Features

-  **10 automated security tests** covering OWASP API Security Top 10
-  **Parallel execution** using Python ThreadPoolExecutor (max 10 threads)
-  **PASS / FAIL / WARNING** result classification per test
-  **MySQL database** persistence for scan history and vulnerabilities
-  **PDF report generation** with risk score, findings table, and recommendations
-  **JSON and CSV export** formats
-  **Real-time dashboard** with scan history and stats
-  **Saved endpoints** for quick re-scanning
-  **Surveillance module** with anomaly detection and email alerts
-  **Login authentication** page

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.x, Flask 3.0 |
| Database | MySQL 8.x, SQLAlchemy 3.1 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| PDF Generation | ReportLab |
| HTTP Client | requests 2.31 |
| Email Alerts | smtplib (Gmail SMTP) |
| Concurrency | Python threading, ThreadPoolExecutor |

---

## 📁 Project Structure

```
api-security-tester/
├── backend/
│   ├── app_with_auth.py        # Main Flask application (production)
│   ├── scanner.py              # Core API security scanner
│   ├── surveillance.py         # Surveillance & anomaly detection engine
│   ├── report_generator.py     # PDF, JSON, CSV report generator
│   ├── models_surveillance.py  # SQLAlchemy database models
│   └── config.py               # App configuration (dev/prod)
├── database/
│   ├── schema.sql              # Core 6-table schema
│   └── schema_surveillance.sql # 8 surveillance tables + procedures
├── frontend/
│   ├── login.html              # Login page
│   ├── index.html              # Scanner page
│   ├── dashboard.html          # Scan history dashboard
│   ├── surveillance.html       # Surveillance monitoring page
│   ├── styles.css              # Global stylesheet
│   └── app.js                  # Frontend JavaScript
├── requirements.txt
└── README.md
```

---

##  Prerequisites

- Python 3.8 or higher
- MySQL 8.0 or higher
- pip

---

##  Installation

**1. Clone the repository**

```bash
git clone https://github.com/your-username/api-security-tester.git
cd api-security-tester
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Install additional dependencies for PDF generation**

```bash
pip install reportlab numpy
```

---

##  Database Setup

**1. Start MySQL and log in**

```bash
mysql -u root -p
```

**2. Create the database and run the schemas**

```sql
CREATE DATABASE IF NOT EXISTS api_security_db;
USE api_security_db;
```

```bash
mysql -u root -proot123 api_security_db < database/schema.sql
mysql -u root -proot123 api_security_db < database/schema_surveillance.sql
```

**3. Verify tables were created**

```bash
mysql -u root -proot123 api_security_db -e "SHOW TABLES;"
```

You should see 14 tables including `scans`, `vulnerabilities`, `api_endpoints`, `anomaly_detections`, etc.

**4. (Optional) Update database credentials**

Edit `backend/config.py` if your MySQL credentials differ:

```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:your_password@localhost:3306/api_security_db'
```

---

## 🚀 Running the Application

```bash
cd backend
python app_with_auth.py
```

The server starts at `http://127.0.0.1:8000`

| Page | URL |
|------|-----|
| Login | http://127.0.0.1:8000 |
| Scanner | http://127.0.0.1:8000/index.html |
| Dashboard | http://127.0.0.1:8000/dashboard.html |
| Surveillance | http://127.0.0.1:8000/surveillance.html |

---

##  Security Tests

The scanner runs 10 tests in parallel against the target API:

| # | Test | Detection Method | Expected Result |
|---|------|-----------------|----------------|
| 1 | Endpoint Reachability | HTTP GET request | PASS if status 200 |
| 2 | HTTPS Enforcement | URL scheme check | FAIL if HTTP detected |
| 3 | HTTP Methods Check | Tests GET/POST/PUT/DELETE/OPTIONS | WARN if DELETE allowed |
| 4 | Security Headers Check | Checks 4 security headers | FAIL if headers missing |
| 5 | Broken Authentication | Unauthenticated + invalid token requests | WARN if 200 without auth |
| 6 | SQL Injection | 4 SQL payloads via query params | FAIL if DB errors in response |
| 7 | XSS Vulnerability | 3 script injection payloads | FAIL if payload reflected |
| 8 | Rate Limiting | 20 rapid consecutive requests | WARN if no 429 response |
| 9 | Excessive Data Exposure | Keyword scan of response body | WARN if sensitive fields found |
| 10 | SSRF Vulnerability | Internal IP URL payloads | FAIL if URLs reflected |

### Recommended Test Targets

```
https://api.github.com              # Well-secured API — mostly PASS
https://jsonplaceholder.typicode.com/posts  # Public API — some WARNs
http://127.0.0.1:8000/api/info      # Local API — FAIL HTTPS + WARNs
https://httpbin.org/get             # Missing headers — good for demos
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/info` | App name and version |
| POST | `/api/scan` | Run a security scan |
| GET | `/api/scans` | Get 10 most recent scans |
| GET | `/api/stats` | Total scan and endpoint counts |
| GET | `/api/endpoints` | List saved endpoints |
| POST | `/api/endpoints` | Save a new endpoint |
| GET | `/api/reports/pdf/<scan_id>` | Download PDF report |
| GET | `/api/reports/json/<scan_id>` | Download JSON report |
| GET | `/api/reports/csv/<scan_id>` | Download CSV report |
| POST | `/api/surveillance/alert-email` | Send email alert |

### Example scan request

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"api_url": "https://api.github.com", "api_name": "GitHub API", "http_method": "GET"}'
```

---

##  Report Export

After a scan completes, download reports in three formats:

- **PDF** — branded report with risk score, colour-coded findings table, and recommendations
- **JSON** — structured data with metadata, summary, findings array, and recommendations
- **CSV** — importable spreadsheet with all vulnerability rows

Reports are available from:
- The scan results page (current scan)
- The dashboard (any historical scan)

---

##  Surveillance Module

The surveillance engine monitors API behaviour and detects anomalies:

- **Rate limit violations** — flags IPs exceeding 100 requests per 5 minutes
- **Response time anomalies** — detects responses 2.5 standard deviations above baseline
- **Error rate spikes** — alerts when error rate exceeds 25%
- **Brute force detection** — flags 10+ failed auth attempts from a single IP
- **Geographic anomalies** — detects unusual IP diversity

**Email alerts** are sent automatically when anomalies are detected with severity-based subject prefixes (`[CRITICAL ISSUE]`, `[HIGH ISSUE]`, etc.).

---

##  Default Credentials

```
Username: admin
Password: admin123
```

>  Change these credentials before any production or public deployment.

---

##  Clearing Scan History

```bash
mysql -u root -proot123 api_security_db -e "DELETE FROM vulnerabilities; DELETE FROM alerts; DELETE FROM scans;"
```

---

##  Known Limitations

- Application runs on localhost only — no production deployment configured
- No JWT token authentication on API endpoints
- No scheduled/automated scanning
- Surveillance module requires manual baseline calculation
- Gmail SMTP credentials are hardcoded — move to environment variables for production

---

##  Future Work

- JWT-based API authentication
- Scheduled automated scanning
- Mobile-responsive UI
- Additional OWASP test coverage
- Cloud deployment (AWS / Heroku)
- Real GeoIP integration for geographic anomaly detection
- CI/CD pipeline integration

---

##  License

This project is submitted as a Final Year Project for academic purposes at London Metropolitan University. Not licensed for commercial use.

---

*API Security Tester — Samriddhi Poudel (23047345) — London Metropolitan University — 2025/26*
s