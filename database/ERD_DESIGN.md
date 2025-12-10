# Database Design - ERD Documentation

**Author:** Samriddhi Poudel (23047345)  
**Date:** December 10, 2025  
**Project:** API Security Tester

---

## Tables Overview

### 1. users
Stores user account information
- **Primary Key:** id
- **Fields:** username, email, password_hash, created_at, is_active

### 2. api_endpoints
Stores saved API configurations
- **Primary Key:** id
- **Foreign Key:** user_id → users(id)
- **Fields:** name, url, method, headers, body, description

### 3. scans
Records of all security scans
- **Primary Key:** id
- **Foreign Key:** api_endpoint_id → api_endpoints(id)
- **Fields:** scan_timestamp, status, total_tests, passed_tests, failed_tests

### 4. vulnerabilities
Detailed test results
- **Primary Key:** id
- **Foreign Key:** scan_id → scans(id)
- **Fields:** test_name, category, severity, status, details, recommendation

### 5. alerts
Notifications from scans
- **Primary Key:** id
- **Foreign Key:** scan_id → scans(id)
- **Fields:** alert_type, message, is_read, created_at

### 6. scan_schedules
Automated scan configuration
- **Primary Key:** id
- **Foreign Key:** api_endpoint_id → api_endpoints(id)
- **Fields:** frequency, next_scan_time, is_active

---

## Relationships

- users → api_endpoints (One-to-Many)
- api_endpoints → scans (One-to-Many)
- scans → vulnerabilities (One-to-Many)
- scans → alerts (One-to-Many)
- api_endpoints → scan_schedules (One-to-One)

---

## Database Name
`api_security_db`

## Total Tables
6 tables with proper foreign key constraints