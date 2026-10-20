-- V7: append-only configuration verification history (no modification to existing CVE tables).
-- Apply only after V6, after taking an external backup. Never drops old records.
USE port_scan;

CREATE TABLE IF NOT EXISTS lab_verification_results (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    observation_uid CHAR(36) NOT NULL,
    port_id BIGINT UNSIGNED NOT NULL,
    scan_id BIGINT UNSIGNED NULL,
    asset_uid CHAR(36) NOT NULL,
    environment_label ENUM('LOCAL_BASELINE','EC2_LAB') NOT NULL,
    check_name ENUM('FTP_ANONYMOUS','SSH_AUTH_POLICY','HTTP_SECURITY_HEADERS','DVWA_SQLI','NUCLEI') NOT NULL,
    execution_status ENUM('SUCCESS','ERROR','SKIPPED') NOT NULL,
    finding_status ENUM('CANDIDATE','POTENTIAL','CONFIRMED','NOT_DETECTED','INCONCLUSIVE') NOT NULL,
    scope_uid VARCHAR(64) NOT NULL,
    scope_sha256 CHAR(64) NOT NULL,
    evidence_sha256 CHAR(64) NOT NULL,
    evidence_json JSON NOT NULL,
    duration_ms INT UNSIGNED NULL,
    observed_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_lab_observation (observation_uid),
    INDEX idx_lab_asset (asset_uid, observed_at),
    INDEX idx_lab_port_check (port_id, check_name, observed_at),
    INDEX idx_lab_scan (scan_id),
    INDEX idx_lab_environment (environment_label, check_name, observed_at),
    CONSTRAINT fk_lab_port FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE RESTRICT,
    CONSTRAINT fk_lab_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_lab_asset FOREIGN KEY (asset_uid) REFERENCES hosts(asset_uid) ON DELETE RESTRICT,
    CONSTRAINT chk_lab_error_inconclusive CHECK (execution_status <> 'ERROR' OR finding_status = 'INCONCLUSIVE'),
    CONSTRAINT chk_lab_skipped_inconclusive CHECK (execution_status <> 'SKIPPED' OR finding_status = 'INCONCLUSIVE')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
