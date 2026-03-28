-- API Security Tester Database Schema with Surveillance
-- Author: Samriddhi Poudel (23047345)
-- Date: February 5, 2026

-- Database Creation
CREATE DATABASE IF NOT EXISTS api_security_db;
USE api_security_db;

-- Table 7: API Request Logs
CREATE TABLE api_request_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    user_agent TEXT,
    http_method VARCHAR(10),
    request_path VARCHAR(500),
    request_headers TEXT,
    request_body TEXT,
    response_status INT,
    response_time_ms INT,
    response_size_bytes INT,
    is_suspicious BOOLEAN DEFAULT FALSE,
    anomaly_score DECIMAL(5,2) DEFAULT 0.00,
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE,
    INDEX idx_timestamp (request_timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_suspicious (is_suspicious),
    INDEX idx_endpoint_time (api_endpoint_id, request_timestamp)
) ENGINE=InnoDB;

-- Table 8: Behavioral Baselines
CREATE TABLE behavioral_baselines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    avg_value DECIMAL(15,2),
    min_value DECIMAL(15,2),
    max_value DECIMAL(15,2),
    std_deviation DECIMAL(15,2),
    sample_size INT,
    calculation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE,
    UNIQUE KEY unique_endpoint_metric (api_endpoint_id, metric_name),
    INDEX idx_metric (metric_name)
) ENGINE=InnoDB;

-- Table 9: Anomaly Detections
CREATE TABLE anomaly_detections (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT,
    request_log_id BIGINT,
    detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence_score DECIMAL(5,2) NOT NULL,
    description TEXT,
    detection_details JSON,
    is_false_positive BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP NULL,
    status VARCHAR(20) DEFAULT 'new',
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE,
    FOREIGN KEY (request_log_id) REFERENCES api_request_logs(id) ON DELETE SET NULL,
    INDEX idx_detection_time (detection_timestamp),
    INDEX idx_anomaly_type (anomaly_type),
    INDEX idx_severity (severity),
    INDEX idx_status (status)
) ENGINE=InnoDB;

-- Table 10: Attack Patterns
CREATE TABLE attack_patterns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern_name VARCHAR(255) NOT NULL,
    pattern_type VARCHAR(50) NOT NULL,
    description TEXT,
    pattern_regex TEXT,
    pattern_rules JSON,
    severity VARCHAR(20) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (pattern_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB;

-- Table 11: Rate Limit Tracking
CREATE TABLE rate_limit_tracking (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT,
    source_ip VARCHAR(45) NOT NULL,
    time_window_start TIMESTAMP NOT NULL,
    time_window_end TIMESTAMP NOT NULL,
    request_count INT DEFAULT 0,
    bytes_transferred BIGINT DEFAULT 0,
    error_count INT DEFAULT 0,
    is_rate_limited BOOLEAN DEFAULT FALSE,
    threshold_exceeded_at TIMESTAMP NULL,
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE,
    INDEX idx_ip_window (source_ip, time_window_start),
    INDEX idx_endpoint_window (api_endpoint_id, time_window_start)
) ENGINE=InnoDB;

-- Table 12: Threat Intelligence
CREATE TABLE threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    threat_type VARCHAR(50) NOT NULL,
    indicator_value VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,
    threat_level VARCHAR(20) NOT NULL,
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    expiry_date TIMESTAMP NULL,
    UNIQUE KEY unique_indicator (indicator_type, indicator_value),
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_threat_type (threat_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB;

-- Table 13: Security Events
CREATE TABLE security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_endpoint_id INT,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    affected_ips TEXT,
    attack_vector VARCHAR(100),
    mitigation_status VARCHAR(50) DEFAULT 'pending',
    mitigation_actions TEXT,
    resolved_at TIMESTAMP NULL,
    resolved_by VARCHAR(100),
    FOREIGN KEY (api_endpoint_id) REFERENCES api_endpoints(id) ON DELETE CASCADE,
    INDEX idx_event_time (event_timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_status (mitigation_status)
) ENGINE=InnoDB;

-- Table 14: Surveillance Rules
CREATE TABLE surveillance_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(50) NOT NULL,
    description TEXT,
    condition_json JSON NOT NULL,
    threshold_value DECIMAL(15,2),
    time_window_minutes INT,
    severity VARCHAR(20) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    notification_channels TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_triggered TIMESTAMP NULL,
    trigger_count INT DEFAULT 0,
    INDEX idx_type (rule_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB;

-- Update alerts table
ALTER TABLE alerts 
ADD COLUMN severity VARCHAR(20) DEFAULT 'medium' AFTER alert_type,
ADD COLUMN source VARCHAR(50) DEFAULT 'manual' AFTER severity,
ADD COLUMN anomaly_detection_id BIGINT AFTER scan_id,
ADD COLUMN security_event_id INT AFTER anomaly_detection_id,
ADD INDEX idx_severity (severity),
ADD INDEX idx_source (source);

-- Insert default attack patterns
INSERT INTO attack_patterns (pattern_name, pattern_type, description, pattern_regex, severity) VALUES
('SQL Injection - Basic', 'sql_injection', 'Detects basic SQL injection attempts', '(\'|\")(.*)(OR|AND)(.*)(=|LIKE)', 'high'),
('XSS - Script Tag', 'xss', 'Detects script tag injection', '<script[^>]*>.*?</script>', 'high'),
('Path Traversal', 'path_traversal', 'Detects directory traversal attempts', '(\\.\\./|\\.\\.\\\\)', 'medium'),
('Command Injection', 'command_injection', 'Detects OS command injection', '(;|\\||&|`|\\$\\(|\\$\\{)', 'critical'),
('XXE Injection', 'xxe', 'Detects XML external entity injection', '<!ENTITY.*SYSTEM', 'high'),
('LDAP Injection', 'ldap_injection', 'Detects LDAP injection attempts', '(\\*|\\(|\\)|&|\\|)', 'medium'),
('NoSQL Injection', 'nosql_injection', 'Detects NoSQL injection patterns', '(\\$ne|\\$gt|\\$gte|\\$lt|\\$lte|\\$regex)', 'high'),
('Header Injection', 'header_injection', 'Detects HTTP header injection', '(\\r\\n|%0d%0a)', 'medium');

-- Insert default surveillance rules
INSERT INTO surveillance_rules (rule_name, rule_type, description, condition_json, threshold_value, time_window_minutes, severity, action_type, notification_channels) VALUES
('High Request Rate', 'rate_limit', 'Alert on excessive requests from single IP', '{"metric": "request_count", "operator": ">"}', 100, 5, 'high', 'alert_and_log', 'email,dashboard'),
('Failed Auth Spike', 'authentication', 'Alert on multiple failed authentication attempts', '{"metric": "failed_auth_count", "operator": ">"}', 10, 10, 'critical', 'alert_and_block', 'email,sms,dashboard'),
('Unusual Response Time', 'performance', 'Alert on abnormal response times', '{"metric": "avg_response_time", "operator": ">", "baseline_multiplier": 3}', 0, 15, 'medium', 'alert_and_log', 'dashboard'),
('Geographic Anomaly', 'geographic', 'Alert on requests from unusual locations', '{"metric": "new_country", "operator": "=="}', 1, 60, 'medium', 'alert_and_log', 'email,dashboard'),
('Error Rate Spike', 'error_rate', 'Alert on high error rates', '{"metric": "error_rate", "operator": ">"}', 0.25, 5, 'high', 'alert_and_log', 'email,dashboard'),
('Sensitive Data Access', 'data_access', 'Alert on excessive sensitive data requests', '{"metric": "sensitive_endpoint_access", "operator": ">"}', 20, 10, 'critical', 'alert_and_log', 'email,sms,dashboard'),
('Brute Force Attack', 'brute_force', 'Alert on brute force patterns', '{"metric": "failed_attempts_unique_creds", "operator": ">"}', 15, 5, 'critical', 'alert_and_block', 'email,sms,dashboard'),
('Data Exfiltration', 'data_exfiltration', 'Alert on unusually large data transfers', '{"metric": "bytes_transferred", "operator": ">"}', 10485760, 10, 'critical', 'alert_and_block', 'email,sms,dashboard');

-- Views
CREATE OR REPLACE VIEW v_recent_suspicious_activity AS
SELECT 
    arl.id,
    ae.name AS endpoint_name,
    ae.url,
    arl.source_ip,
    arl.http_method,
    arl.request_timestamp,
    arl.response_status,
    arl.anomaly_score,
    ad.anomaly_type,
    ad.severity,
    ad.description
FROM api_request_logs arl
JOIN api_endpoints ae ON arl.api_endpoint_id = ae.id
LEFT JOIN anomaly_detections ad ON arl.id = ad.request_log_id
WHERE arl.is_suspicious = TRUE
ORDER BY arl.request_timestamp DESC
LIMIT 100;

CREATE OR REPLACE VIEW v_threat_summary AS
SELECT 
    DATE(detection_timestamp) AS date,
    anomaly_type,
    severity,
    COUNT(*) AS count,
    AVG(confidence_score) AS avg_confidence
FROM anomaly_detections
WHERE detection_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(detection_timestamp), anomaly_type, severity
ORDER BY date DESC, count DESC;

CREATE OR REPLACE VIEW v_endpoint_health AS
SELECT 
    ae.id,
    ae.name,
    ae.url,
    COUNT(DISTINCT DATE(arl.request_timestamp)) AS days_active,
    COUNT(arl.id) AS total_requests,
    AVG(arl.response_time_ms) AS avg_response_time,
    SUM(CASE WHEN arl.response_status >= 400 THEN 1 ELSE 0 END) AS error_count,
    SUM(CASE WHEN arl.is_suspicious THEN 1 ELSE 0 END) AS suspicious_count,
    MAX(arl.request_timestamp) AS last_request
FROM api_endpoints ae
LEFT JOIN api_request_logs arl ON ae.id = arl.api_endpoint_id
    AND arl.request_timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY ae.id, ae.name, ae.url;

-- Stored Procedures
DELIMITER //

CREATE PROCEDURE calculate_baseline(IN endpoint_id INT)
BEGIN
    INSERT INTO behavioral_baselines (api_endpoint_id, metric_name, avg_value, min_value, max_value, std_deviation, sample_size)
    SELECT 
        endpoint_id,
        'response_time_ms',
        AVG(response_time_ms),
        MIN(response_time_ms),
        MAX(response_time_ms),
        STDDEV(response_time_ms),
        COUNT(*)
    FROM api_request_logs
    WHERE api_endpoint_id = endpoint_id
        AND request_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        AND response_status < 400
    ON DUPLICATE KEY UPDATE
        avg_value = VALUES(avg_value),
        min_value = VALUES(min_value),
        max_value = VALUES(max_value),
        std_deviation = VALUES(std_deviation),
        sample_size = VALUES(sample_size);
    
    INSERT INTO behavioral_baselines (api_endpoint_id, metric_name, avg_value, min_value, max_value, std_deviation, sample_size)
    SELECT 
        endpoint_id,
        'requests_per_hour',
        AVG(hourly_count),
        MIN(hourly_count),
        MAX(hourly_count),
        STDDEV(hourly_count),
        COUNT(*)
    FROM (
        SELECT COUNT(*) as hourly_count
        FROM api_request_logs
        WHERE api_endpoint_id = endpoint_id
            AND request_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(request_timestamp), HOUR(request_timestamp)
    ) hourly_stats
    ON DUPLICATE KEY UPDATE
        avg_value = VALUES(avg_value),
        min_value = VALUES(min_value),
        max_value = VALUES(max_value),
        std_deviation = VALUES(std_deviation),
        sample_size = VALUES(sample_size);
END //

CREATE PROCEDURE detect_rate_limit_violations()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE v_endpoint_id INT;
    DECLARE v_source_ip VARCHAR(45);
    DECLARE v_count INT;
    DECLARE cur CURSOR FOR 
        SELECT api_endpoint_id, source_ip, COUNT(*) as request_count
        FROM api_request_logs
        WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        GROUP BY api_endpoint_id, source_ip
        HAVING COUNT(*) > 100;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO v_endpoint_id, v_source_ip, v_count;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        INSERT INTO anomaly_detections 
            (api_endpoint_id, anomaly_type, severity, confidence_score, description)
        VALUES 
            (v_endpoint_id, 'rate_limit_exceeded', 'high', 95.00, 
             CONCAT('IP ', v_source_ip, ' made ', v_count, ' requests in 5 minutes'));
    END LOOP;
    CLOSE cur;
END //

DELIMITER ;

-- Indexes for performance
CREATE INDEX idx_request_log_analysis ON api_request_logs(api_endpoint_id, request_timestamp, is_suspicious);
CREATE INDEX idx_anomaly_review ON anomaly_detections(status, severity, detection_timestamp);
CREATE INDEX idx_rate_tracking ON rate_limit_tracking(source_ip, api_endpoint_id, time_window_start);

SHOW TABLES;