"""Save candidates and their matching evidence in one transaction."""
import hashlib
import json
import math

from db.db_client import get_connection
from db.query_helpers import insert_vuln_evidence, upsert_vuln
from db.scan_history import link_finding


def as_float(value, default=None):
    if value is None:
        return default
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Scores must be finite or null.")
    return number


def save_vulns(vulns: list[dict]) -> list[int]:
    if not vulns:
        return []
    # Validate everything before opening a transaction.
    for vuln in vulns:
        if not isinstance(vuln.get("port_id"), int) or isinstance(vuln["port_id"], bool) or vuln["port_id"] <= 0:
            raise ValueError("Saving requires real positive database port IDs.")
        if vuln.get("status") != "CANDIDATE" or not vuln.get("source", "").startswith("catalog:"):
            raise ValueError("CVE 후보 분석 only saves CANDIDATE records from the reviewed catalog.")
        if not vuln.get("fingerprint") or not vuln.get("catalog_sha256"):
            raise ValueError("Missing candidate evidence.")
        for key, maximum in (("cvss", 10), ("epss", 1), ("risk", 1)):
            score = as_float(vuln.get(key))
            if score is not None and not 0 <= score <= maximum:
                raise ValueError(f"Invalid {key} score.")
    conn = get_connection()
    saved_ids = []
    try:
        for vuln in vulns:
            vuln_id = upsert_vuln(
                conn=conn, port_id=vuln["port_id"], cve_id=vuln["cve_id"],
                title=vuln["title"], severity=vuln["severity"],
                epss=as_float(vuln.get("epss")), cvss=as_float(vuln.get("cvss")),
                risk=as_float(vuln.get("risk")), status="CANDIDATE", source=vuln["source"],
            )
            details = json.dumps(vuln, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(details.encode("utf-8")).hexdigest()
            # upsert_vuln holds the parent row lock; concurrent re-saves serialize here.
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM vuln_evidence WHERE vuln_id = %s "
                    "AND checker = 'cve_catalog_mapper' AND sha256 = %s LIMIT 1 FOR UPDATE",
                    (vuln_id, digest),
                )
                exists = cursor.fetchone()
            if not exists:
                insert_vuln_evidence(conn, vuln_id, "cve_catalog_mapper", "BANNER",
                                     details=details, sha256=digest)
            saved_ids.append(vuln_id)
            link_finding(conn, vuln_id, vuln.get('observation_id'), port_id=vuln['port_id'])
        conn.commit()
        return saved_ids
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
