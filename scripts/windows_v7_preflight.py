"""Read-only Windows MySQL V7 preparation: no DDL, network scan or changes.

Run from project root: py -m scripts.windows_v7_preflight
Uses the existing local .env and lists only *current* HTTP port candidates.
These rows are NOT automatically authenticated as having originated from EC2.
"""
from __future__ import annotations

import json
import sys

from db.db_client import get_connection

NEEDED = {
    "id", "observation_uid", "port_id", "scan_id", "asset_uid",
    "environment_label", "check_name", "execution_status", "finding_status",
    "scope_uid", "scope_sha256", "evidence_sha256", "evidence_json",
    "duration_ms", "observed_at",
}


def describe_local_database(connect=get_connection):
    connection = connect()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT DATABASE() AS database_name, VERSION() AS mysql_version")
            identity = cursor.fetchone()
            if not identity or identity["database_name"] != "port_scan":
                raise ValueError("Expected existing port_scan database, do not initialize another DB")
            cursor.execute(
                """SELECT TABLE_NAME AS table_name FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA = DATABASE()
                     AND TABLE_NAME IN ('scans','hosts','ports','lab_verification_results')"""
            )
            tables = {row["table_name"] for row in cursor.fetchall()}
            result = {
                "mysql_version": identity["mysql_version"],
                "database_name": identity["database_name"],
                "required_v6_tables_present": {"scans", "hosts", "ports"}.issubset(tables),
                "v7_table_present": "lab_verification_results" in tables,
                "v7_schema_complete": False,
                "counts": {},
                "current_http_scan_port_candidates": [],
                "current_scan_port_candidates": [],
                "warning": (
                    "An HTTP row on Windows is not proof of EC2 origin. "
                    "Only import after the exact target and scan history are independently checked."
                ),
                "writes_performed": False,
            }
            if not result["required_v6_tables_present"]:
                return result
            if result["v7_table_present"]:
                cursor.execute(
                    """SELECT COLUMN_NAME AS column_name FROM information_schema.COLUMNS
                       WHERE TABLE_SCHEMA = DATABASE()
                         AND TABLE_NAME = 'lab_verification_results'"""
                )
                result["v7_schema_complete"] = NEEDED.issubset(
                    {row["column_name"] for row in cursor.fetchall()}
                )
            for table in ("scans", "hosts", "ports"):
                cursor.execute("SELECT COUNT(*) AS n FROM " + table)
                result["counts"][table] = cursor.fetchone()["n"]
            if result["v7_table_present"]:
                cursor.execute("SELECT COUNT(*) AS n FROM lab_verification_results")
                result["counts"]["lab_verification_results"] = cursor.fetchone()["n"]
            cursor.execute(
                """SELECT p.id AS port_id, p.port AS port_number, p.service AS service,
                          p.last_scan_id AS scan_id, s.status AS scan_status,
                          s.started_at AS scanned_at, h.asset_uid AS asset_uid,
                          h.host_ip AS host_ip, s.target AS original_scan_target
                   FROM ports AS p
                   JOIN hosts AS h ON h.id = p.host_id
                   JOIN scans AS s ON s.id = p.last_scan_id
                   WHERE p.state = 'open' AND p.protocol = 'tcp'
                     AND p.last_scan_id = h.last_scan_id
                     AND LOWER(COALESCE(p.service,'')) IN ('http','https','ftp','ssh')
                   ORDER BY p.last_seen DESC, p.id DESC LIMIT 25"""
            )
            for item in cursor.fetchall():
                candidate = {
                    k: str(value) if k == "scanned_at" else value
                    for k, value in item.items()
                }
                result["current_scan_port_candidates"].append(candidate)
                if str(item["service"]).lower() in {"http", "https"}:
                    result["current_http_scan_port_candidates"].append(candidate)
            return result
    finally:
        connection.close()


def main():
    try:
        output = describe_local_database()
        print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
        return 0 if output["required_v6_tables_present"] else 2
    except Exception as exc:
        # Avoid printing connection strings, passwords, local file paths, DB
        # server messages and environment variables.
        print(json.dumps({"status": "PRECHECK_FAILED",
                          "error_type": type(exc).__name__,
                          "writes_performed": False}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
