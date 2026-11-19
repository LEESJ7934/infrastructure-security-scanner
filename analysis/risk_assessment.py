"""Independent 위험도 평가 파이프라인: external intel reads, then short V5 transactions."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from analysis.kev_catalog import fetch_kev_catalog, lookup_kev
from analysis.intel_freshness import usable_intel
from analysis.nvd_cvss import fetch_cvss_scores, valid_cve, validate_timeout
from analysis.risk_engine import METHODOLOGY_ID, assess_priority, sha256_json
from analysis.vuln_mapper import RETIRED_RULE_IDS, load_catalog
from api.shodan_epss_report import fetch_epss_scores
from db.db_client import get_connection
from db.query_helpers import (get_risk_assessment_targets, update_risk_score_summaries,
                              upsert_risk_assessment)

ELIGIBLE_STATUSES = frozenset({"CANDIDATE", "POTENTIAL", "CONFIRMED", "RETEST_REQUIRED", "ERROR"})
ASSET_FIELDS = ("asset_uid", "host_id", "host_ip", "asset_name", "asset_type", "environment", "criticality",
                "owner", "business_unit", "data_classification", "internet_exposed", "handles_personal_data",
                "lifecycle_status")


class RiskSelectionError(ValueError):
    pass


class RiskPolicyError(ValueError):
    pass


class RiskDatabaseError(RuntimeError):
    pass


def validate_selection(vuln_id=None, scan_id=None, asset_uid=None):
    if sum(value is not None for value in (vuln_id, scan_id, asset_uid)) != 1:
        raise RiskSelectionError("Exactly one of vuln-id, scan-id or asset-id is required")
    for value in (vuln_id, scan_id):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise RiskSelectionError("DB identifiers must be positive integers")
    if asset_uid is not None:
        try:
            return str(UUID(asset_uid))
        except (ValueError, TypeError, AttributeError) as exc:
            raise RiskSelectionError("asset-id must be an asset UUID") from exc
    return None


def _eligible(row, reviewed):
    source = row.get("source") or ""
    return (row.get("status") in ELIGIBLE_STATUSES and source.startswith("catalog:")
            and source not in RETIRED_RULE_IDS and valid_cve(row.get("cve_id"))
            and reviewed.get(source) == row["cve_id"])


def _asset_context(row):
    asset = {key: row.get(key) for key in ASSET_FIELDS}
    for key in ("internet_exposed", "handles_personal_data"):
        value = asset[key]
        if not isinstance(value, (int, bool)) or value not in (0, 1):
            raise RiskPolicyError("Asset flags must be stored booleans")
        asset[key] = bool(value)
    if asset["criticality"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNASSIGNED"}:
        raise RiskPolicyError("Invalid stored asset criticality")
    return asset


def build_assessment(row, cvss, epss, kev):
    asset = _asset_context(row)
    effective, freshness = usable_intel({"cvss": cvss, "epss": epss, "kev": kev})
    result = assess_priority(row["status"], asset, **effective)
    errors = []
    for name, source in (("cvss", cvss), ("epss", epss), ("kev", kev)):
        if source.get("error_code"):
            errors.append({"provider": name, "source": source.get("endpoint") or source.get("source"),
                           "error_code": source["error_code"], "recovered": False})
    for failure in kev.get("errors", []):
        errors.append({"provider": "kev", **failure, "recovered": kev["state"] == "OK"})
    return {"schema_version": 1, "cve_id": row["cve_id"], "source": row["source"],
            "current_status": row["status"], "asset_context": asset,
            "endpoint": {key: row.get(key) for key in ("port_id", "port", "protocol", "scan_id")},
            "cvss": cvss, "epss": epss, "kev": kev, **result,
            "intel_freshness": freshness,
            "source_errors": errors, "incomplete": bool(errors) or any(
                item["status"] != "FRESH" for item in freshness.values())}


def _save_one(snapshot, intel, reviewed, *, scan_id=None, asset_uid=None):
    conn = None
    try:
        conn = get_connection()
        conn.start_transaction()
        rows = get_risk_assessment_targets(conn=conn, vuln_id=snapshot["vuln_id"], for_update=True)
        current = rows[0] if rows else None
        reason = None
        if current is None:
            reason = "finding_deleted"
        elif not _eligible(current, reviewed):
            reason = "status_or_source_no_longer_eligible"
        elif current["cve_id"] != snapshot["cve_id"]:
            reason = "cve_changed_during_fetch"
        elif ((scan_id is not None and current["scan_id"] != scan_id)
              or (asset_uid is not None and current["asset_uid"] != asset_uid)):
            reason = "selection_context_changed_during_fetch"
        if reason:
            conn.rollback()
            return {"vuln_id": snapshot["vuln_id"], "cve_id": (current or snapshot)["cve_id"],
                    "current_status": current["status"] if current else None, "outcome": "SKIPPED",
                    "reason": reason, "assessment_id": None, "assessment_reused": False}
        # Evaluate the CURRENT locked status/asset context using already fetched public CVE data.
        details = build_assessment(current, **intel[current["cve_id"]])
        input_hash = sha256_json(details)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        assessment_id, reused = upsert_risk_assessment(conn, current["vuln_id"], details, input_hash, now)
        effective, _ = usable_intel({name: details[name] for name in ("cvss", "epss", "kev")})
        update_risk_score_summaries(conn, current["vuln_id"], effective["cvss"], effective["epss"])
        conn.commit()
        return {**details, "vuln_id": current["vuln_id"], "outcome": "SAVED", "input_sha256": input_hash,
                "assessment_id": assessment_id, "assessment_reused": reused}
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        if isinstance(exc, RiskPolicyError):
            raise
        raise RiskDatabaseError("Assessment transaction failed (" + type(exc).__name__ + ")") from exc
    finally:
        if conn is not None:
            conn.close()


def run_risk_assessments(*, vuln_id=None, scan_id=None, asset_uid=None, save=False, timeout=10):
    """No target probing or DNS resolution: only MySQL and fixed public intel URLs."""
    asset_uid = validate_selection(vuln_id, scan_id, asset_uid)
    validate_timeout(timeout)
    try:
        catalog, _ = load_catalog()
        reviewed = {rule["id"]: rule["cve"] for rule in catalog["rules"]}
    except (OSError, ValueError, KeyError) as exc:
        raise RiskPolicyError("Reviewed 검토된 CVE 카탈로그 could not be loaded") from exc
    try:
        snapshots = get_risk_assessment_targets(vuln_id=vuln_id, scan_id=scan_id, asset_uid=asset_uid)
    except Exception as exc:
        raise RiskDatabaseError("Risk selection read failed (" + type(exc).__name__ + ")") from exc
    snapshots = [row for row in snapshots if _eligible(row, reviewed)]
    if not snapshots:
        raise RiskSelectionError("No eligible reviewed 카탈로그 기반 finding matched the selection")
    # Validate the snapshots before requesting external data. This read connection is already closed.
    for row in snapshots:
        _asset_context(row)
    cves = sorted({row["cve_id"] for row in snapshots})
    cvss = fetch_cvss_scores(cves, timeout=timeout)
    epss = fetch_epss_scores(cves, timeout=timeout)
    kev_catalog = fetch_kev_catalog(timeout=timeout)
    intel = {cve: {"cvss": cvss[cve], "epss": epss[cve], "kev": lookup_kev(kev_catalog, cve)} for cve in cves}
    source_errors = []
    # Preserve fetch errors even when all selected rows become terminal and are skipped.
    for row in snapshots:
        for error in build_assessment(row, **intel[row["cve_id"]])["source_errors"]:
            item = {"cve_id": row["cve_id"], **error}
            if item not in source_errors:
                source_errors.append(item)
    outcomes = []
    for row in snapshots:
        if save:
            try:
                outcome = _save_one(row, intel, reviewed, scan_id=scan_id, asset_uid=asset_uid)
            except (RiskDatabaseError, RiskPolicyError) as exc:
                outcomes.append({"vuln_id": row["vuln_id"], "cve_id": row["cve_id"], "outcome": "ERROR",
                                 "error_code": "DB_SAVE_FAILED" if isinstance(exc, RiskDatabaseError) else "POLICY_ERROR",
                                 "message": str(exc), "assessment_id": None, "assessment_reused": False})
                continue
        else:
            details = build_assessment(row, **intel[row["cve_id"]])
            outcome = {**details, "vuln_id": row["vuln_id"], "outcome": "PREVIEW",
                       "input_sha256": sha256_json(details), "assessment_id": None, "assessment_reused": False}
        outcomes.append(outcome)
    failed = bool(source_errors) or any(row["outcome"] == "ERROR" for row in outcomes)
    return {"mode": "SAVE" if save else "PREVIEW", "methodology_id": METHODOLOGY_ID,
            "incomplete": failed, "source_errors": source_errors, "results": outcomes}
