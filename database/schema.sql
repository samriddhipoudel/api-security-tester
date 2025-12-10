-- API Security Tester Database Schema
-- Author: Samriddhi Poudel (23047345)
-- Date: December 10, 2025

-- Database Creation
CREATE DATABASE IF NOT EXISTS api_security_db;
USE api_security_db;

-- Table 1: Users
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Table 2: API Endpoints
CREATE TABLE api_endpoints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    method VARCHAR(10) DEFAULT 'GET',
    headers TEXT,
    body TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table 3: Scans
CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'completed',
    total_tests INT DEFAULT 0,
    passed_tests INT DEFAULT 0,
    failed_tests INT DEFAULT 0,
    warnings INT DEFAULT 0,
    scan_duration FLOAT,
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE
);

-- Table 4: Vulnerabilities
CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    test_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    severity VARCHAR(20),
    status VARCHAR(20),
    details TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Table 5: Alerts
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    alert_type VARCHAR(50),
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Table 6: Scan Schedules
CREATE TABLE scan_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT NOT NULL,
    frequency VARCHAR(50),
    next_scan_time TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE
);

-- Create Indexes
CREATE INDEX idx_scans_timestamp ON scans(scan_timestamp);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_alerts_read ON alerts(is_read);
CREATE INDEX idx_api_endpoints_user ON api_endpoints(user_id);

-- Show created tables
SHOW TABLES;