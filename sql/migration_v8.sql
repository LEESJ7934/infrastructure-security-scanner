-- V8: immutable scan observations and explicit asset identity namespaces.
-- Apply only to a backed-up V7 database after testing this migration in isolation.
-- No old observation, timestamp or finding is fabricated/backfilled as a new measurement.
-- No USE statement: the operator must explicitly select the intended database.
ALTER TABLE hosts ADD COLUMN asset_namespace VARCHAR(190) NOT NULL DEFAULT 'legacy';
ALTER TABLE hosts DROP INDEX uq_hosts_ip,
    ADD UNIQUE KEY uq_hosts_namespace_ip (asset_namespace, host_ip);
ALTER TABLE ports MODIFY state ENUM('open','closed','filtered','open_or_filtered','unknown','error','not_tested') NOT NULL DEFAULT 'closed';

CREATE TABLE scan_run_snapshots (
    scan_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    execution_sha256 CHAR(64) NOT NULL,
    time_basis ENUM('UTC','LEGACY_UNSPECIFIED') NOT NULL,
    asset_namespace VARCHAR(190) NOT NULL,
    requested_port_range TEXT NOT NULL,
    snapshot_json JSON NOT NULL,
    imported_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_snapshot_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE scan_port_observations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT UNSIGNED NOT NULL,
    host_id BIGINT UNSIGNED NOT NULL,
    port_id BIGINT UNSIGNED NOT NULL,
    port INT UNSIGNED NOT NULL,
    protocol ENUM('tcp','udp') NOT NULL,
    state ENUM('open','closed','filtered','open|filtered','unknown','error','not_tested') NOT NULL,
    reason VARCHAR(128) NULL,
    error_code VARCHAR(128) NULL,
    service VARCHAR(100) NULL,
    product VARCHAR(100) NULL,
    version VARCHAR(255) NULL,
    banner TEXT NULL,
    fingerprint JSON NULL,
    observed_at DATETIME(6) NULL,
    observation_json JSON NOT NULL,
    identity_sha256 CHAR(64) NOT NULL,
    UNIQUE KEY uq_scan_endpoint (scan_id,host_id,port,protocol),
    INDEX idx_observation_current (host_id,port,protocol,id),
    CONSTRAINT fk_observation_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE RESTRICT,
    CONSTRAINT fk_observation_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_observation_port FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE finding_observation_links (
    vuln_id BIGINT UNSIGNED NOT NULL,
    observation_id BIGINT UNSIGNED NOT NULL,
    relation ENUM('CANDIDATE','VERIFIED') NOT NULL,
    linked_at DATETIME(6) NOT NULL,
    PRIMARY KEY (vuln_id,observation_id,relation),
    CONSTRAINT fk_finding_link FOREIGN KEY (vuln_id) REFERENCES vulns(id) ON DELETE RESTRICT,
    CONSTRAINT fk_finding_observation FOREIGN KEY (observation_id) REFERENCES scan_port_observations(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
