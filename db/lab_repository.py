"""Append-only configuration-verification evidence storage, separate from CVE status."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from db.db_client import get_connection

EXECUTION = frozenset({"SUCCESS", "ERROR", "SKIPPED"})
FINDING = frozenset({"CANDIDATE", "POTENTIAL", "CONFIRMED", "NOT_DETECTED", "INCONCLUSIVE"})
CHECKS = frozenset({"FTP_ANONYMOUS", "SSH_AUTH_POLICY", "HTTP_SECURITY_HEADERS", "DVWA_SQLI", "NUCLEI"})
ENVIRONMENTS = frozenset({"LOCAL_BASELINE", "EC2_LAB"})
SENSITIVE_KEYS = frozenset({"password", "passwd", "cookie", "set-cookie", "authorization",
                            "user_token", "secret", "token", "session", "api_key", "private_key"})


def redact(value):
    """Never store authentication headers or tokens even if a checker adds them."""
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower().replace("-", "_") in
                         {s.replace("-", "_") for s in SENSITIVE_KEYS} else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def make_observation(*, port, environment, check_name, result, scope, observed_at=None):
    if environment not in ENVIRONMENTS or check_name not in CHECKS:
        raise ValueError("Unsupported laboratory environment/check")
    if result.get("status") == "ERROR":
        execution, finding = "ERROR", "INCONCLUSIVE"
    else:
        execution = "SUCCESS"
        finding = result.get("details", {}).get("finding_status", "INCONCLUSIVE")
        if finding not in FINDING:
            raise ValueError("Invalid configuration finding status")
    evidence = redact({
        "checker": result.get("checker"), "reason": result.get("reason"),
        "error_code": result.get("error_code"), "details": result.get("details", {}),
        "additional_checks": result.get("additional_checks", []),
        "scope_uid": scope.scope_uid, "scope_sha256": scope.fingerprint,
        "asset_uid": port["asset_uid"], "port_id": port["port_id"],
        "scan_id": port.get("scan_id"), "host_ip": port["host_ip"],
        "port": port["port"], "check_name": check_name, "environment": environment,
        "execution_status": execution, "finding_status": finding,
    })
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {
        "observation_uid": str(uuid4()), "port_id": port["port_id"],
        "scan_id": port.get("scan_id"), "asset_uid": port["asset_uid"],
        "environment_label": environment, "check_name": check_name,
        "execution_status": execution, "finding_status": finding,
        "scope_uid": scope.scope_uid, "scope_sha256": scope.fingerprint,
        "evidence_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "evidence_json": canonical,
        "duration_ms": result.get("details", {}).get("duration_ms"),
        "observed_at": observed_at or datetime.now(timezone.utc).replace(tzinfo=None),
    }


def insert_observation(observation, *, connect=get_connection):
    """Each observation is new: no UPSERT, status rewrite, CVE mutation or data clearing."""
    connection = connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO lab_verification_results (
                    observation_uid,port_id,scan_id,asset_uid,environment_label,check_name,
                    execution_status,finding_status,scope_uid,scope_sha256,evidence_sha256,
                    evidence_json,duration_ms,observed_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                tuple(observation[key] for key in (
                    "observation_uid","port_id","scan_id","asset_uid","environment_label",
                    "check_name","execution_status","finding_status","scope_uid",
                    "scope_sha256","evidence_sha256","evidence_json","duration_ms","observed_at")),
            )
            new_id = cursor.lastrowid
        connection.commit()
        return new_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def read_observations(*, scan_id=None, asset_uid=None, connect=get_connection):
    """Read-only chronological evidence; never treat missing checks as secure."""
    if (scan_id is None) == (asset_uid is None):
        raise ValueError("Select exactly one scan ID or asset UUID")
    connection = connect()
    try:
        with connection.cursor(dictionary=True) as cursor:
            if scan_id is not None:
                cursor.execute(
                    "SELECT * FROM lab_verification_results WHERE scan_id = %s ORDER BY observed_at,id",
                    (scan_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM lab_verification_results WHERE asset_uid = %s ORDER BY observed_at,id",
                    (asset_uid,),
                )
            return cursor.fetchall()
    finally:
        connection.close()
