import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from mysql.connector import MySQLConnection

from asset_management import normalize_ip_address
from .db_client import get_connection
from .statuses import (
    ScanStatus,
    VulnStatus,
    normalize_scan_status,
    normalize_vuln_status,
    validate_vuln_transition,
)


VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_EVIDENCE_TYPES = {
    "HTTP_RESPONSE",
    "SCREENSHOT",
    "NUCLEI",
    "BANNER",
    "MANUAL",
    "ERROR_LOG",
}


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    ).replace(tzinfo=None)


def upsert_host(
    conn: MySQLConnection,
    host_ip: str,
    host_name: Optional[str] = None,
    last_scan_id: Optional[int] = None,
    asset_namespace: str = 'legacy',
) -> int:
    now = utc_now()
    canonical_ip = normalize_ip_address(host_ip)
    new_asset_uid = str(uuid4())

    sql = """
    INSERT INTO hosts (
        asset_uid,
        host_ip,
        host_name,
        first_seen,
        last_seen,
        last_scan_id
    )
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        host_name = COALESCE(
            VALUES(host_name),
            host_name
        ),
        last_seen = VALUES(last_seen),
        last_scan_id = COALESCE(
            VALUES(last_scan_id),
            last_scan_id
        );
    """

    if asset_namespace != 'legacy':
        from .scan_history import namespace_for, supports_history
        namespace_for({'asset_namespace': asset_namespace})
        if not supports_history(conn):
            raise RuntimeError('V8 migration required for isolated asset namespaces')
        sql = sql.replace('asset_uid,', 'asset_uid, asset_namespace,', 1).replace(
            'VALUES (%s, %s, %s, %s, %s, %s)', 'VALUES (%s, %s, %s, %s, %s, %s, %s)', 1)
    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            ((new_asset_uid, asset_namespace, canonical_ip, host_name, now, now, last_scan_id)
             if asset_namespace != 'legacy' else (
                new_asset_uid,
                canonical_ip,
                host_name,
                now,
                now,
                last_scan_id,
            )),
        )
        return cursor.lastrowid


def get_all_ports(scan_id: int | None = None, asset_uid: str | None = None) -> List[Dict[str, Any]]:
    """Open TCP observations from each asset's latest successful stored scan.

    ports is a current-state table, not a historical per-scan snapshot. Requiring
    p.last_scan_id = h.last_scan_id excludes stale ports omitted by a later scan.
    """
    conn = get_connection()
    from .scan_history import supports_history, get_observations
    if supports_history(conn):
        try:
            rows = get_observations(conn, scan_id=scan_id, asset_uid=asset_uid, current=scan_id is None)
            return [row for row in rows if row['state'] == 'open' and row['protocol'] == 'tcp']
        finally:
            conn.close()
    sql = """
    SELECT p.id AS port_id, h.asset_uid, h.host_ip, p.port, p.protocol,
           p.service, p.product, p.version, p.banner, p.fingerprint, p.state,
           p.last_scan_id AS scan_id
    FROM ports AS p JOIN hosts AS h ON p.host_id = h.id
    WHERE p.state = 'open' AND p.protocol = 'tcp'
      AND p.last_scan_id = h.last_scan_id
    """
    params = []
    if scan_id is not None:
        sql += " AND p.last_scan_id = %s"
        params.append(scan_id)
    if asset_uid is not None:
        sql += " AND h.asset_uid = %s"
        params.append(asset_uid)
    sql += " ORDER BY h.id, p.port"
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute(sql, tuple(params))
            return cursor.fetchall()
    finally:
        conn.close()


def upsert_port(
    conn: MySQLConnection,
    host_id: int,
    port: int,
    protocol: str,
    service: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    last_scan_id: Optional[int] = None,
    state: str = "closed",
    product: Optional[str] = None,
    fingerprint: Optional[dict] = None,
) -> int:
    normalized_protocol = (
        protocol
        .strip()
        .lower()
    )
    normalized_state = (
        state
        .strip()
        .lower()
    )

    if normalized_state == "open|filtered":
        normalized_state = "open_or_filtered"

    if normalized_protocol not in {
        "tcp",
        "udp",
    }:
        raise ValueError(
            "지원하지 않는 프로토콜입니다: "
            f"{protocol}"
        )

    if normalized_state not in {
        "open",
        "closed",
        "filtered",
        "open_or_filtered",
        "unknown", "error", "not_tested",
    }:
        raise ValueError(
            "지원하지 않는 포트 상태입니다: "
            f"{state}"
        )

    now = utc_now()

    from .scan_history import supports_history
    history_enabled = supports_history(conn)

    sql = """
    INSERT INTO ports (
        host_id,
        port,
        protocol,
        service,
        version,
        banner,
        state,
        first_seen,
        last_seen,
        last_scan_id,
        product,
        fingerprint
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        service = VALUES(service),
        version = VALUES(version),
        banner = VALUES(banner),
        product = VALUES(product),
        fingerprint = VALUES(fingerprint),
        state = VALUES(state),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """

    if history_enabled:
        # A NOT_TESTED row is preserved in immutable history, but cannot erase
        # a previously measured endpoint from the current-state summary.
        assignments = ('service', 'version', 'banner', 'product', 'fingerprint', 'state', 'last_seen', 'last_scan_id')
        for field in assignments:
            sql = sql.replace(f'{field} = VALUES({field})',
                f"{field} = IF(VALUES(state) = 'not_tested', {field}, VALUES({field}))")
    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                host_id,
                port,
                normalized_protocol,
                service,
                version,
                banner,
                normalized_state,
                now,
                now,
                last_scan_id,
                product,
                json.dumps(fingerprint, ensure_ascii=False) if fingerprint is not None else None,
            ),
        )
        return cursor.lastrowid


def insert_scan(
    conn: MySQLConnection,
    scan_uid: str,
    target: str,
    scan_type: str,
    port_range: str,
    started_at: datetime,
    finished_at: Optional[datetime],
    status: str | ScanStatus,
    scope_id: Optional[int] = None,
    requested_targets: Optional[List[str]] = None,
    config_snapshot: Optional[
        Dict[str, Any]
    ] = None,
) -> int:
    normalized_status = (
        normalize_scan_status(status)
    )

    snapshot_json = (
        json.dumps(
            config_snapshot,
            ensure_ascii=False,
            default=str,
        )
        if config_snapshot
        else None
    )
    requested_targets_json = (
        json.dumps(
            requested_targets,
            ensure_ascii=False,
        )
        if requested_targets is not None
        else None
    )

    sql = """
    INSERT INTO scans (
        scan_uid,
        scope_id,
        target,
        requested_targets,
        scan_type,
        port_range,
        started_at,
        finished_at,
        status,
        config_snapshot
    )
    VALUES (
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        scope_id = VALUES(scope_id),
        requested_targets = VALUES(
            requested_targets
        ),
        finished_at = VALUES(finished_at),
        status = VALUES(status),
        config_snapshot = VALUES(
            config_snapshot
        );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                scan_uid,
                scope_id,
                target,
                requested_targets_json,
                scan_type,
                port_range,
                started_at,
                finished_at,
                normalized_status,
                snapshot_json,
            ),
        )
        return cursor.lastrowid


def upsert_vuln(
    conn: MySQLConnection,
    port_id: int,
    cve_id: str,
    title: str,
    severity: str,
    epss: Optional[float] = None,
    cvss: Optional[float] = None,
    risk: Optional[float] = None,
    source: Optional[str] = None,
    status: str | VulnStatus = VulnStatus.POTENTIAL,
) -> int:
    severity_value = (
        severity
        .strip()
        .upper()
    )
    status_value = (
        normalize_vuln_status(status)
    )
    cve_value = (
        cve_id or "NONE"
    ).strip().upper()
    source_value = (
        source or "unknown"
    ).strip()

    if severity_value not in VALID_SEVERITIES:
        raise ValueError(
            "지원하지 않는 심각도입니다: "
            f"{severity}"
        )

    now = utc_now()

    sql = """
    INSERT INTO vulns (
        port_id,
        cve_id,
        title,
        severity,
        epss,
        cvss,
        risk,
        status,
        source,
        first_detected_at,
        last_detected_at,
        created_at,
        updated_at
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        title = VALUES(title),
        severity = VALUES(severity),
        epss = COALESCE(VALUES(epss), epss),
        cvss = COALESCE(VALUES(cvss), cvss),
        risk = COALESCE(VALUES(risk), risk),
        status = CASE
            WHEN vulns.status IN (
                'POTENTIAL',
                'ERROR',
                'CONFIRMED',
                'NOT_APPLICABLE',
                'FALSE_POSITIVE',
                'RETEST_REQUIRED',
                'CLOSED'
            )
            THEN vulns.status
            ELSE VALUES(status)
        END,
        last_detected_at = VALUES(
            last_detected_at
        ),
        updated_at = VALUES(
            updated_at
        );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                port_id,
                cve_value,
                title,
                severity_value,
                epss,
                cvss,
                risk,
                status_value,
                source_value,
                now,
                now,
                now,
                now,
            ),
        )

        vuln_id = cursor.lastrowid

        if cursor.rowcount == 1:
            cursor.execute(
                """
                INSERT INTO
                    remediation_history (
                        vuln_id,
                        from_status,
                        to_status,
                        action_type,
                        reason,
                        changed_by
                    )
                VALUES (
                    %s,
                    NULL,
                    %s,
                    'STATUS_CHANGE',
                    '최초 탐지',
                    'analysis'
                );
                """,
                (
                    vuln_id,
                    status_value,
                ),
            )

        return vuln_id


def insert_vuln(
    conn: MySQLConnection,
    port_id: int,
    cve_id: str,
    title: str,
    severity: str,
    epss: Optional[float] = None,
    source: Optional[str] = None,
    status: str | VulnStatus = VulnStatus.POTENTIAL,
) -> int:
    return upsert_vuln(
        conn=conn,
        port_id=port_id,
        cve_id=cve_id,
        title=title,
        severity=severity,
        epss=epss,
        source=source,
        status=status,
    )


def insert_vuln_evidence(
    conn: MySQLConnection,
    vuln_id: int,
    checker: str,
    evidence_type: str,
    details: Optional[str] = None,
    evidence_path: Optional[str] = None,
    sha256: Optional[str] = None,
) -> int:
    type_value = (
        evidence_type
        .strip()
        .upper()
    )

    if type_value not in VALID_EVIDENCE_TYPES:
        raise ValueError(
            "지원하지 않는 증적 유형입니다: "
            f"{evidence_type}"
        )

    sql = """
    INSERT INTO vuln_evidence (
        vuln_id,
        checker,
        evidence_type,
        details,
        evidence_path,
        sha256
    )
    VALUES (
        %s, %s, %s,
        %s, %s, %s
    );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                vuln_id,
                checker,
                type_value,
                details,
                evidence_path,
                sha256,
            ),
        )
        return cursor.lastrowid


def transition_vuln_status(
    conn: MySQLConnection,
    vuln_id: int,
    new_status: str | VulnStatus,
    reason: Optional[str] = None,
    changed_by: str = "system",
) -> None:
    with conn.cursor(
        dictionary=True
    ) as cursor:
        cursor.execute(
            """
            SELECT status
            FROM vulns
            WHERE id = %s
            FOR UPDATE;
            """,
            (vuln_id,),
        )

        row = cursor.fetchone()

        if not row:
            raise LookupError(
                "취약점 레코드를 "
                "찾을 수 없습니다: "
                f"{vuln_id}"
            )

        current, new = (
            validate_vuln_transition(
                row["status"],
                new_status,
            )
        )

        if current == new:
            return

        now = utc_now()

        verified_at = (
            now
            if new in {
                VulnStatus.CONFIRMED.value,
                VulnStatus.NOT_APPLICABLE.value,
                VulnStatus.FALSE_POSITIVE.value,
            }
            else None
        )

        closed_at = (
            now
            if new == VulnStatus.CLOSED.value
            else None
        )

        cursor.execute(
            """
            UPDATE vulns
            SET
                status = %s,
                verified_at = COALESCE(
                    %s,
                    verified_at
                ),
                closed_at = %s,
                updated_at = %s
            WHERE id = %s;
            """,
            (
                new,
                verified_at,
                closed_at,
                now,
                vuln_id,
            ),
        )

        if new == VulnStatus.RETEST_REQUIRED.value:
            action_type = "RETEST_REQUEST"
        elif new == VulnStatus.CLOSED.value:
            action_type = "CLOSURE"
        elif current == VulnStatus.CLOSED.value:
            action_type = "REOPEN"
        else:
            action_type = "STATUS_CHANGE"

        cursor.execute(
            """
            INSERT INTO
                remediation_history (
                    vuln_id,
                    from_status,
                    to_status,
                    action_type,
                    reason,
                    changed_by
                )
            VALUES (
                %s, %s, %s,
                %s, %s, %s
            );
            """,
            (
                vuln_id,
                current,
                new,
                action_type,
                reason,
                changed_by,
            ),
        )


def update_vuln_verification(
    conn: MySQLConnection,
    vuln_id: int,
    status: str | VulnStatus,
    reason: Optional[str] = None,
) -> None:
    transition_vuln_status(
        conn=conn,
        vuln_id=vuln_id,
        new_status=status,
        reason=reason,
        changed_by="verification",
    )
    from .scan_history import link_finding, supports_history
    if normalize_vuln_status(status) == VulnStatus.CONFIRMED.value and supports_history(conn):
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute('SELECT port_id FROM vulns WHERE id=%s', (vuln_id,))
            row = cursor.fetchone()
        if row:
            link_finding(conn, vuln_id, port_id=row['port_id'], relation='VERIFIED')


def get_ports_with_vuln_candidates(
    conn: Optional[MySQLConnection] = None,
    vuln_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    for_update: bool = False,
) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Current endpoints for CVE verification, retaining the legacy tuple API.

    scan_id selects the port's current observation scan, not historical replay.
    FOR UPDATE is only valid on a caller-owned transaction used to persist results.
    """
    if for_update and conn is None:
        raise ValueError("Row locking requires a caller-owned connection")
    owns_connection = conn is None
    active_connection = conn if conn is not None else get_connection()
    sql = """
    SELECT p.id AS port_id, h.host_ip, p.port, p.protocol, p.service,
           p.product, p.version, p.banner, p.fingerprint, p.state AS port_state,
           p.last_scan_id AS scan_id, s.scan_uid, s.scope_id,
           sa.input_target, sa.resolution_type,
           v.id AS vuln_id, v.cve_id, v.title, v.source, v.status
    FROM vulns AS v
    JOIN ports AS p ON v.port_id = p.id
    JOIN hosts AS h ON p.host_id = h.id
    LEFT JOIN scans AS s ON s.id = p.last_scan_id
    LEFT JOIN scan_assets AS sa ON sa.scan_id = p.last_scan_id AND sa.host_id = h.id
    WHERE v.status IN ('CANDIDATE', 'POTENTIAL', 'RETEST_REQUIRED', 'ERROR')
    """
    params = []
    if vuln_id is not None:
        sql += " AND v.id = %s"
        params.append(vuln_id)
    if scan_id is not None:
        sql += " AND p.last_scan_id = %s"
        params.append(scan_id)
    sql += " ORDER BY v.id"
    if for_update:
        sql += " FOR UPDATE"
    try:
        with active_connection.cursor(dictionary=True) as cursor:
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
        results = []
        for row in rows:
            port_record = {
                "id": row["port_id"], "port_id": row["port_id"],
                "host_ip": row["host_ip"], "port": row["port"], "protocol": row["protocol"],
                "service": row["service"], "product": row["product"], "version": row["version"],
                "banner": row["banner"], "fingerprint": row["fingerprint"], "state": row["port_state"],
                "scan_id": row["scan_id"], "scan_uid": row["scan_uid"], "scope_id": row["scope_id"],
                "input_target": row["input_target"] or row["host_ip"],
                "resolution_type": row["resolution_type"] or "IP",
            }
            vuln_record = {
                "id": row["vuln_id"], "vuln_id": row["vuln_id"],
                "cve": row["cve_id"], "cve_id": row["cve_id"],
                "title": row["title"], "source": row["source"], "status": row["status"],
            }
            results.append((port_record, vuln_record))
        return results
    finally:
        if owns_connection:
            active_connection.close()


def get_risk_assessment_targets(
    *, conn=None, vuln_id=None, scan_id=None, asset_uid=None, for_update=False,
):
    """위험도 평가 selection. scan_id means the port's current scan, not historical replay.

    The locked read deliberately includes newly ineligible rows so the caller can
    skip a concurrent review/source change. No connection is retained by a preview.
    """
    if for_update and (conn is None or vuln_id is None):
        raise ValueError("Locked risk lookup requires a caller transaction and vuln_id")
    owns_connection = conn is None
    active = conn if conn is not None else get_connection()
    sql = """
    SELECT v.id AS vuln_id, v.cve_id, v.source, v.status,
           v.cvss, v.epss, p.id AS port_id, p.port, p.protocol,
           p.last_scan_id AS scan_id, h.id AS host_id, h.asset_uid,
           h.host_ip, h.asset_name, h.asset_type, h.environment,
           h.criticality, h.owner, h.business_unit, h.data_classification,
           h.internet_exposed, h.handles_personal_data, h.lifecycle_status
    FROM vulns AS v
    JOIN ports AS p ON p.id = v.port_id
    JOIN hosts AS h ON h.id = p.host_id
    WHERE 1 = 1
    """
    if not for_update:
        sql += """
        AND v.source LIKE 'catalog:%'
        AND v.status IN ('CANDIDATE', 'POTENTIAL', 'CONFIRMED', 'RETEST_REQUIRED', 'ERROR')
        """
    params = []
    for value, condition in ((vuln_id, " AND v.id = %s"), (scan_id, " AND p.last_scan_id = %s"),
                              (asset_uid, " AND h.asset_uid = %s")):
        if value is not None:
            sql += condition
            params.append(value)
    sql += " ORDER BY v.id"
    if for_update:
        sql += " FOR UPDATE"
    try:
        with active.cursor(dictionary=True) as cursor:
            cursor.execute(sql, tuple(params))
            return cursor.fetchall()
    finally:
        if owns_connection:
            active.close()


def upsert_risk_assessment(conn, vuln_id, details, input_sha256, assessed_at):
    """Caller holds the joined vuln/host row locks and owns commit/rollback."""
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            SELECT id FROM vuln_risk_assessments
            WHERE vuln_id = %s AND methodology_id = %s AND input_sha256 = %s
            FOR UPDATE
        """, (vuln_id, details["methodology_id"], input_sha256))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""
                UPDATE vuln_risk_assessments
                SET last_assessed_at = GREATEST(last_assessed_at, %s), observations = observations + 1
                WHERE id = %s
            """, (assessed_at, existing["id"]))
            return existing["id"], True
        cvss, epss, kev, asset = (details[key] for key in ("cvss", "epss", "kev", "asset_context"))
        cursor.execute("""
            INSERT INTO vuln_risk_assessments (
                vuln_id, methodology_id, methodology_sha256, vuln_status, action, priority,
                cvss_score, cvss_version, cvss_vector, cvss_source,
                epss_score, epss_percentile, epss_date, kev_status, kev_date_added,
                asset_criticality, internet_exposed, handles_personal_data,
                details, input_sha256, first_assessed_at, last_assessed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (vuln_id, details["methodology_id"], details["methodology_sha256"], details["current_status"],
              details["action"], details["priority"], cvss["score"], cvss["version"], cvss["vector"], cvss["source"],
              epss["score"], epss["percentile"], epss["date"], kev["status"], kev["date_added"],
              asset["criticality"], asset["internet_exposed"], asset["handles_personal_data"],
              json.dumps(details, sort_keys=True, ensure_ascii=False, allow_nan=False),
              input_sha256, assessed_at, assessed_at))
        return cursor.lastrowid, False


def update_risk_score_summaries(conn, vuln_id, cvss, epss):
    """Only observed values / official absence replace summaries. Errors preserve them.

    Deliberately never writes risk, severity, status, review dates or history.
    """
    updates, params = [], []
    for field, result in (("cvss", cvss), ("epss", epss)):
        if result["state"] == "OK" and result["score"] is not None:
            updates.append(field + " = %s")
            params.append(result["score"])
        elif result["state"] in {"NO_SCORE", "NOT_FOUND"}:
            updates.append(field + " = %s")
            params.append(None)
    if updates:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE vulns SET " + ", ".join(updates) + " WHERE id = %s", tuple(params + [vuln_id]))
