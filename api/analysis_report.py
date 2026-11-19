"""Build one read-only, current-state V6-capable report snapshot and export it locally."""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from analysis.vuln_mapper import load_catalog
from db.db_client import get_connection
from db.statuses import VulnStatus
from db.scan_history import supports_history, get_observations, read_snapshot

PRIORITIES = ("P1", "P2", "P3", "P4", "UNASSESSED")
FRESHNESS = ("CURRENT", "STALE", "MISSING")
SELECTION_NOTE = "Current-state port observations only; this is not historical replay."
COVERAGE_NOTE = "No stored reviewed findings does not establish security. Unobserved services and unsupported CVEs are outside this report."
FRESHNESS_NOTE = "CURRENT means stored assessment context matches this snapshot; external threat feeds were not refreshed."
ASSET_FIELDS = ("id", "asset_uid", "host_ip", "host_name", "asset_name", "asset_type", "environment",
                "criticality", "owner", "business_unit", "data_classification", "handles_personal_data",
                "internet_exposed", "lifecycle_status", "first_seen", "last_seen", "last_scan_id")
PORT_FIELDS = ("port_id", "host_id", "port", "protocol", "service", "product", "version", "state", "last_scan_id")
FINDING_FIELDS = ("vuln_id", "port_id", "cve_id", "title", "source", "status", "severity",
                  "first_detected_at", "last_detected_at", "verified_at", "closed_at")
ASSESSMENT_FIELDS = ("assessment_id", "vuln_id", "methodology_id", "methodology_sha256", "vuln_status",
                     "action", "priority", "cvss_score", "cvss_version", "cvss_vector", "cvss_source",
                     "epss_score", "epss_percentile", "epss_date", "kev_status", "kev_date_added",
                     "asset_criticality", "internet_exposed", "handles_personal_data", "input_sha256",
                     "first_assessed_at", "last_assessed_at", "observations")
FINGERPRINT_FIELDS = ("service", "product", "version", "source", "confidence", "parser_version", "error")
CLOUD_FIELDS = ("cloud_resource_id", "host_id", "provider", "account_id", "region", "resource_type",
                "resource_id", "vpc_id", "subnet_id", "private_ip", "public_ip", "instance_state",
                "first_discovered_at", "last_discovered_at")
CLOUD_FINDING_FIELDS = ("cloud_finding_id", "cloud_resource_id", "rule_id", "category", "title", "severity",
                        "priority", "status", "public_address_present", "remediation", "input_sha256",
                        "first_detected_at", "last_detected_at", "resolved_at", "observations")


class ReportSelectionError(ValueError):
    pass


class ReportDatabaseError(RuntimeError):
    pass


class ReportDataError(ValueError):
    pass


def validate_selection(*, asset_uid=None, scan_id=None):
    if (asset_uid is None) == (scan_id is None):
        raise ReportSelectionError("Exactly one asset UUID or positive scan ID is required")
    if scan_id is not None:
        if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
            raise ReportSelectionError("scan-id must be a positive integer")
        return {"type": "scan", "scan_id": scan_id, "selection_note": SELECTION_NOTE}
    try:
        canonical = str(UUID(asset_uid))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportSelectionError("asset-id must be an asset UUID, not an IP address") from exc
    return {"type": "asset", "asset_uid": canonical, "selection_note": SELECTION_NOTE}


def json_value(value):
    """Preserve absent values and make MySQL Decimal/date results JSON compatible."""
    if isinstance(value, datetime):
        # Historical MySQL DATETIME fields have mixed/unknown origins. Only
        # explicit aware inputs can truthfully be labelled Z.
        return value.isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _boolean(value):
    return bool(value) if isinstance(value, (bool, int)) and value in (0, 1) else None


def _object(value):
    if value is None or value == "":
        return {}, "MISSING"
    try:
        if isinstance(value, (str, bytes)):
            value = json.loads(value, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
        if not isinstance(value, dict):
            raise ValueError("Expected JSON object")
        return json_value(value), "PARSED"
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return {}, "PARSE_ERROR"


def _pick(row, fields):
    return {key: json_value(row.get(key)) for key in fields}


def _array(value):
    if value is None or value == "":
        return [], "MISSING"
    try:
        if isinstance(value, (str, bytes)):
            value = json.loads(value, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
        if not isinstance(value, list):
            raise ValueError("Expected JSON array")
        return json_value(value), "PARSED"
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return [], "PARSE_ERROR"


def _select(cursor, sql, params=()):
    cursor.execute(sql, tuple(params))
    return cursor.fetchall()


def _related(cursor, sql, identifiers, suffix=""):
    results = []
    ids = sorted(set(identifiers))
    for start in range(0, len(ids), 500):
        batch = ids[start:start + 500]
        results.extend(_select(cursor, sql + "(" + ",".join(["%s"] * len(batch)) + ") " + suffix, batch))
    return results


def _read_rows(conn, selection):
    history_enabled = supports_history(conn)
    if history_enabled:
        selection['selection_note'] = ('Immutable per-scan port observations; asset metadata and review status are current, not an as-of snapshot.'
                                       if selection['type'] == 'scan' else 'Latest measured observation per endpoint; partial scans retain earlier endpoints with NOT_REOBSERVED relevance.')
    with conn.cursor(dictionary=True) as cursor:
        asset_sql = "SELECT " + ", ".join("h." + key for key in ASSET_FIELDS) + " FROM hosts AS h WHERE "
        scan_sql = """
            SELECT s.id AS scan_id, s.scan_uid, s.status, s.scan_type, s.target,
                   s.requested_targets, s.port_range, s.started_at, s.finished_at,
                   sc.scope_uid, sc.authorization_ref, sc.approved_by, sc.valid_from,
                   sc.valid_until, sc.policy_sha256
            FROM scans AS s LEFT JOIN scan_scopes AS sc ON sc.id = s.scope_id
            WHERE s.id IN
        """
        if selection["type"] == "asset":
            assets = _select(cursor, asset_sql + "h.asset_uid = %s ORDER BY h.id", [selection["asset_uid"]])
            if not assets:
                raise ReportSelectionError("Asset was not found")
            port_condition = "h.asset_uid = %s AND p.last_scan_id = h.last_scan_id"
            port_params = [selection["asset_uid"]]
            scans = _related(cursor, scan_sql, [row["last_scan_id"] for row in assets if row.get("last_scan_id") is not None])
        else:
            scan_id = selection["scan_id"]
            scans = _related(cursor, scan_sql, [scan_id])
            if not scans:
                raise ReportSelectionError("Scan was not found")
            assets = _select(cursor, asset_sql + """
                EXISTS (SELECT 1 FROM scan_assets AS sa WHERE sa.host_id = h.id AND sa.scan_id = %s)
                OR EXISTS (SELECT 1 FROM ports AS p WHERE p.host_id = h.id AND p.last_scan_id = %s)
                ORDER BY h.id
            """, [scan_id, scan_id])
            port_condition = "p.last_scan_id = %s"
            port_params = [scan_id]
        ports = _select(cursor, """
            SELECT p.id AS port_id, p.host_id, p.port, p.protocol, p.service, p.product,
                   p.version, p.state, p.last_scan_id, p.fingerprint
            FROM ports AS p JOIN hosts AS h ON h.id = p.host_id WHERE
        """ + port_condition + " ORDER BY p.host_id, p.port, p.protocol, p.id", port_params)
        if history_enabled:
            observations = get_observations(conn,
                scan_id=selection.get('scan_id'), asset_uid=selection.get('asset_uid'),
                current=selection['type'] == 'asset')
            ports = [{**o, 'last_scan_id': o['scan_id'], 'history_capability': 'IMMUTABLE_V8'} for o in observations]
            if selection['type'] == 'asset':
                ids = {o['scan_id'] for o in observations} | {a['last_scan_id'] for a in assets if a.get('last_scan_id')}
                scans = _related(cursor, scan_sql, ids)
            for scan in scans:
                saved = read_snapshot(conn, scan['scan_id'])
                scan['immutable_execution'] = saved
                if saved and saved['time_basis'] == 'UTC':
                    for field in ('started_at', 'finished_at'):
                        if isinstance(scan.get(field), datetime) and scan[field].tzinfo is None:
                            scan[field] = scan[field].replace(tzinfo=timezone.utc)
            for asset in assets:
                asset['asset_namespace'] = next((o['asset_namespace'] for o in observations if o['host_id'] == asset['id']), 'legacy')
        findings = _related(cursor, """
            SELECT v.id AS vuln_id, v.port_id, v.cve_id, v.title, v.source, v.status, v.severity,
                   v.first_detected_at, v.last_detected_at, v.verified_at, v.closed_at
            FROM vulns AS v WHERE v.port_id IN
        """, [row["port_id"] for row in ports], "AND v.source LIKE 'catalog:%' ORDER BY v.id")
        if history_enabled:
            links = _related(cursor, 'SELECT l.vuln_id,l.relation,o.id AS observation_id,o.scan_id,'
                'o.identity_sha256,o.product,o.version,o.service,o.state '
                'FROM finding_observation_links l JOIN scan_port_observations o ON o.id=l.observation_id '
                'WHERE l.vuln_id IN', [f['vuln_id'] for f in findings], 'ORDER BY o.id')
            for finding in findings:
                finding['observation_links'] = [link for link in links if link['vuln_id'] == finding['vuln_id']]
        cloud_resources, cloud_findings = [], []
        cloud_select = """
            SELECT cr.id AS cloud_resource_id, cr.host_id, cr.provider, cr.account_id, cr.region,
                   cr.resource_type, cr.resource_id, cr.vpc_id, cr.subnet_id, cr.private_ip,
                   cr.public_ip, cr.instance_state, cr.security_groups, cr.tags,
                   cr.first_discovered_at, cr.last_discovered_at
            FROM cloud_resources AS cr WHERE cr.{column} IN
        """
        seen_cloud_ids = set()
        lookup_groups = (
            ("host_id", [row["id"] for row in assets if row.get("asset_type") == "CLOUD_RESOURCE"]),
            ("private_ip", [row["host_ip"] for row in assets if row.get("host_ip") and row.get('asset_namespace', 'legacy') == 'legacy']),
            ("public_ip", [row["host_ip"] for row in assets if row.get("host_ip") and row.get('asset_namespace', 'legacy') == 'legacy']),
        )
        for column, values in lookup_groups:
            for row in _related(cursor, cloud_select.format(column=column), values, "ORDER BY cr.host_id, cr.id"):
                if row["cloud_resource_id"] not in seen_cloud_ids:
                    seen_cloud_ids.add(row["cloud_resource_id"])
                    cloud_resources.append(row)
        if cloud_resources:
            cloud_findings = _related(cursor, """
                SELECT cf.id AS cloud_finding_id, cf.cloud_resource_id, cf.rule_id, cf.category,
                       cf.title, cf.severity, cf.priority, cf.status, cf.public_address_present,
                       cf.evidence, cf.remediation, cf.input_sha256, cf.first_detected_at,
                       cf.last_detected_at, cf.resolved_at, cf.observations
                FROM cloud_configuration_findings AS cf WHERE cf.cloud_resource_id IN
            """, [row["cloud_resource_id"] for row in cloud_resources],
            "AND cf.status = 'OPEN' ORDER BY cf.cloud_resource_id, cf.rule_id")
        return cursor_rows(cursor, assets, scans, ports, findings, cloud_resources, cloud_findings)


def cursor_rows(cursor, assets, scans, ports, findings, cloud_resources=None, cloud_findings=None):
    try:
        reviewed = {rule["id"]: rule["cve"] for rule in load_catalog()[0]["rules"]}
    except (OSError, ValueError, KeyError) as exc:
        raise ReportDataError("Reviewed 검토된 CVE 카탈로그 could not be read") from exc
    findings = [row for row in findings if reviewed.get(row["source"]) == row["cve_id"]]
    ids = [row["vuln_id"] for row in findings]
    assessments = _related(cursor, """
        SELECT r.id AS assessment_id, r.vuln_id, r.methodology_id, r.methodology_sha256,
               r.vuln_status, r.action, r.priority, r.cvss_score, r.cvss_version, r.cvss_vector,
               r.cvss_source, r.epss_score, r.epss_percentile, r.epss_date, r.kev_status,
               r.kev_date_added, r.asset_criticality, r.internet_exposed, r.handles_personal_data,
               r.details, r.input_sha256, r.first_assessed_at, r.last_assessed_at, r.observations
        FROM vuln_risk_assessments AS r WHERE r.vuln_id IN
    """, ids, """AND NOT EXISTS (
        SELECT 1 FROM vuln_risk_assessments AS newer WHERE newer.vuln_id = r.vuln_id
        AND (newer.last_assessed_at > r.last_assessed_at
             OR (newer.last_assessed_at = r.last_assessed_at AND newer.id > r.id))
    ) ORDER BY r.vuln_id""")
    evidence = _related(cursor, """
        SELECT e.id AS evidence_id, e.vuln_id, e.checker, e.evidence_type, e.sha256, e.collected_at, e.details
        FROM vuln_evidence AS e WHERE e.vuln_id IN
    """, ids, "ORDER BY e.collected_at, e.id")
    history = _related(cursor, """
        SELECT rh.id AS history_id, rh.vuln_id, rh.from_status, rh.to_status,
               rh.action_type, rh.reason, rh.changed_by, rh.changed_at
        FROM remediation_history AS rh WHERE rh.vuln_id IN
    """, ids, "ORDER BY rh.changed_at, rh.id")
    return assets, scans, ports, findings, assessments, evidence, history, (cloud_resources or []), (cloud_findings or [])


def parse_evidence(row):
    result = _pick(row, ("evidence_id", "checker", "evidence_type", "sha256", "collected_at"))
    document, state = _object(row.get("details"))
    result["details_status"] = state
    if state != "PARSED":
        result["parse_error"] = "Invalid or legacy JSON details" if state == "PARSE_ERROR" else None
        result["details"] = {}
        return result
    content = document.get("content", document)
    if not isinstance(content, dict):
        result.update(details_status="PARSE_ERROR", parse_error="Invalid evidence content", details={})
        return result
    parsed = _pick(content, ("result", "reason", "error_code", "additional_checks"))
    if row.get("checker") == "cve_catalog_mapper":
        parsed.update(result=content.get("status"), reason=content.get("match_reason"),
                      additional_checks=content.get("conditions_to_verify"),
                      references=content.get("references"), affected=content.get("affected"),
                      catalog_sha256=content.get("catalog_sha256"),
                      package_assessment=content.get("package_assessment"))
    parsed.update(_pick(document, ("first_checked_at", "last_checked_at", "observations")))
    checks = content.get("details")
    if isinstance(checks, dict):
        parsed["safe_checks"] = checks.get("safe_checks")
        parsed["condition"] = checks.get("condition")
    result["details"] = parsed
    return result


def _assessment(row, finding, asset, endpoint):
    if row is None:
        return None, "MISSING", ["assessment_missing"]
    assessment = _pick(row, ASSESSMENT_FIELDS)
    document, state = _object(row.get("details"))
    assessment["details_status"] = state
    assessment["details"] = _pick(document, ("matched_rules", "missing_inputs", "reason", "source_errors", "incomplete"))
    # Only normalized provider fields are retained; never render arbitrary response bodies.
    provenance = {}
    for provider, fields in {
        "cvss": ("state", "score", "version", "vector", "severity", "source", "metric_type", "endpoint", "error_code", "fetched_at", "ttl_seconds", "freshness_policy"),
        "epss": ("state", "score", "percentile", "date", "source", "error_code", "fetched_at", "ttl_seconds", "freshness_policy"),
        "kev": ("state", "status", "source", "catalog_version", "date_released", "date_added", "due_date",
                "known_ransomware_campaign_use", "required_action", "vendor_project", "product", "error_code", "errors", "fetched_at", "ttl_seconds", "freshness_policy"),
    }.items():
        value = document.get(provider)
        provenance[provider] = _pick(value, fields) if isinstance(value, dict) else None
    assessment["provenance"] = provenance
    from analysis.intel_freshness import evaluate_intel_freshness
    assessment['intel_freshness'] = evaluate_intel_freshness(document)
    for key in ("internet_exposed", "handles_personal_data"):
        assessment[key] = _boolean(assessment[key])
    reasons = []
    for provider, metadata in assessment['intel_freshness'].items():
        if metadata.get('status') == 'STALE':
            reasons.append(provider + '_intel_stale')
        elif metadata.get('status') == 'UNKNOWN' and isinstance(document.get(provider), dict) and 'fetched_at' in document[provider]:
            reasons.append(provider + '_intel_time_invalid')
    for field, current in (("vuln_status", finding["status"]), ("asset_criticality", asset["criticality"]),
                           ("internet_exposed", asset["internet_exposed"]),
                           ("handles_personal_data", asset["handles_personal_data"])):
        if assessment[field] is None or current is None or assessment[field] != current:
            reasons.append(field + "_mismatch_or_missing")
    for key in ("cve_id", "source"):
        if key in document and document[key] != finding[key]:
            reasons.append(key + "_mismatch")
    old_asset = document.get("asset_context")
    if isinstance(old_asset, dict):
        for key in ("asset_uid", "host_ip", "asset_name", "asset_type", "environment", "owner", "business_unit",
                    "data_classification", "lifecycle_status"):
            if key in old_asset and old_asset[key] != asset.get(key):
                reasons.append("asset." + key + "_mismatch")
    old_endpoint = document.get("endpoint")
    if isinstance(old_endpoint, dict):
        for key in ("port_id", "port", "protocol", "scan_id"):
            current = endpoint.get("last_scan_id") if key == "scan_id" else endpoint.get(key)
            if key in old_endpoint and old_endpoint[key] != current:
                reasons.append("endpoint." + key + "_mismatch")
    if assessment["priority"] not in PRIORITIES:
        reasons.append("invalid_stored_priority")
    return assessment, "STALE" if reasons else "CURRENT", reasons


def snapshot_sha256(snapshot):
    content = {key: value for key, value in snapshot.items() if key != "generated_at"}
    content["integrity"] = {key: value for key, value in snapshot.get("integrity", {}).items() if key != "snapshot_sha256"}
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def finding_relevance(finding, endpoint, *, latest_asset_scan=None, historical=False):
    """Current CVE applicability is independent from an immutable review status.

    A matching advertised version establishes candidate applicability, never a
    new confirmation. A previous CONFIRMED remains historical until its positive
    evidence is explicitly linked to this exact observation.
    """
    if endpoint.get('observation_time_basis') == 'LEGACY_UNSPECIFIED':
        return 'NOT_REOBSERVED', 'legacy_observation_timezone_unknown'
    if endpoint.get('state') in {'error', 'unknown', 'not_tested'}:
        return 'NOT_REOBSERVED', 'current_endpoint_not_successfully_inspected'
    if not historical and latest_asset_scan is not None and endpoint.get('last_scan_id') != latest_asset_scan:
        return 'NOT_REOBSERVED', 'endpoint_outside_latest_asset_scan'
    if endpoint.get('state') != 'open':
        return 'STALE', 'endpoint_no_longer_open'
    rule = next((r for r in load_catalog()[0]['rules'] if r['id'] == finding.get('source') and r['cve'] == finding.get('cve_id')), None)
    if rule is None:
        return 'NOT_REOBSERVED', 'reviewed_rule_unavailable'
    if not endpoint.get('product') or not endpoint.get('version'):
        return 'NOT_REOBSERVED', 'current_product_or_version_missing'
    if endpoint['product'] != rule['product']:
        return 'STALE', 'current_product_changed'
    from analysis.vuln_mapper import normalized_version
    version = normalized_version(rule['product'], endpoint['version'])
    if version is None:
        return 'NOT_REOBSERVED', 'current_version_format_unsupported'
    if not (normalized_version(rule['product'], rule['affected']['introduced']) <= version
            < normalized_version(rule['product'], rule['affected']['fixed'])):
        return 'STALE', 'current_version_outside_reviewed_range'
    links = finding.get('observation_links') or []
    source_links = [link for link in links if link['relation'] == 'CANDIDATE']
    if source_links and endpoint.get('identity_sha256') and source_links[-1].get('identity_sha256') != endpoint['identity_sha256']:
        return 'STALE', 'service_observation_identity_changed'
    return 'CURRENT', 'advertised_product_version_matches_candidate_rule_not_patch_proof'


def _assemble(selection, rows):
    assets, scans, ports, findings, assessments, evidence, history, cloud_resources, cloud_findings = rows
    by_asset = {}
    for row in sorted(assets, key=lambda row: row["id"]):
        item = _pick(row, ASSET_FIELDS)
        item['asset_namespace'] = row.get('asset_namespace', 'legacy')
        for key in ("internet_exposed", "handles_personal_data"):
            item[key] = _boolean(row.get(key))
        by_asset[row["id"]] = {**item, "ports": [], "findings": [],
                                "cloud": None, "cloud_configuration_findings": []}
    cloud_by_id = {}
    cloud_asset_links = {}
    asset_ids_by_ip = {}
    for asset_id, asset in by_asset.items():
        if asset.get("host_ip") and asset.get('asset_namespace') == 'legacy':
            asset_ids_by_ip.setdefault(asset["host_ip"], []).append(asset_id)
    for row in cloud_resources:
        item = _pick(row, CLOUD_FIELDS)
        groups, groups_state = _array(row.get("security_groups"))
        tags, tags_state = _object(row.get("tags"))
        item["security_groups"] = groups
        item["security_groups_status"] = groups_state
        item["tags"] = tags if tags_state == "PARSED" else {}
        item["tags_status"] = tags_state
        cloud_by_id[item["cloud_resource_id"]] = item
        linked_asset_ids = set()
        if item["host_id"] in by_asset:
            linked_asset_ids.add(item["host_id"])
        for address in (item.get("private_ip"), item.get("public_ip")):
            linked_asset_ids.update(asset_ids_by_ip.get(address, []))
        cloud_asset_links[item["cloud_resource_id"]] = sorted(linked_asset_ids)
        for asset_id in linked_asset_ids:
            by_asset[asset_id]["cloud"] = item
    cloud_priority_counts = dict.fromkeys(PRIORITIES, 0)
    for row in cloud_findings:
        item = _pick(row, CLOUD_FINDING_FIELDS)
        item["public_address_present"] = _boolean(row.get("public_address_present"))
        evidence_doc, evidence_state = _object(row.get("evidence"))
        item["evidence"] = evidence_doc if evidence_state == "PARSED" else {}
        item["evidence_status"] = evidence_state
        for asset_id in cloud_asset_links.get(item["cloud_resource_id"], []):
            by_asset[asset_id]["cloud_configuration_findings"].append(item)
        if item.get("priority") in cloud_priority_counts:
            cloud_priority_counts[item["priority"]] += 1
    by_port = {}
    for row in sorted(ports, key=lambda row: (row["host_id"], row["port"], row["protocol"], row["port_id"])):
        item = _pick(row, PORT_FIELDS)
        item.update(_pick(row, ('observation_id', 'observed_at', 'reason', 'error_code', 'identity_sha256')))
        fp, fp_state = _object(row.get("fingerprint"))
        item.update(fingerprint=_pick(fp, FINGERPRINT_FIELDS), fingerprint_status=fp_state)
        by_port[item["port_id"]] = item
        by_asset[item["host_id"]]["ports"].append(item)
    latest = {row["vuln_id"]: row for row in assessments}
    evidence_by, history_by = {}, {}
    for row in sorted(evidence, key=lambda row: (str(json_value(row.get("collected_at")) or ""), row["evidence_id"])):
        evidence_by.setdefault(row["vuln_id"], []).append(parse_evidence(row))
    for row in sorted(history, key=lambda row: (str(json_value(row.get("changed_at")) or ""), row["history_id"])):
        history_by.setdefault(row["vuln_id"], []).append(_pick(row, ("history_id", "from_status", "to_status",
                                                        "action_type", "reason", "changed_by", "changed_at")))
    summary = {"asset_count": len(by_asset), "open_port_count": sum(p["state"] == "open" for p in ports),
               "finding_count": len(findings), "cloud_configuration_finding_count": len(cloud_findings),
               "current_finding_count": 0,
               "historical_status_counts": {status.value: 0 for status in VulnStatus},
               "relevance_counts": dict.fromkeys(('CURRENT', 'STALE', 'NOT_REOBSERVED'), 0),
               "status_counts": {status.value: 0 for status in VulnStatus},
               "priority_counts": dict.fromkeys(PRIORITIES, 0),
               "cloud_priority_counts": cloud_priority_counts,
               "assessment_freshness_counts": dict.fromkeys(FRESHNESS, 0),
               "highest_priority": "UNASSESSED",
               "highest_cloud_priority": next((level for level in PRIORITIES if cloud_priority_counts[level]), "UNASSESSED"),
               "coverage_note": COVERAGE_NOTE, "freshness_note": FRESHNESS_NOTE}
    for row in findings:
        item = _pick(row, FINDING_FIELDS)
        port = by_port[item["port_id"]]
        asset = by_asset[port["host_id"]]
        endpoint = {**_pick(port, PORT_FIELDS), "host_ip": asset["host_ip"], "asset_uid": asset["asset_uid"]}
        endpoint.update(_pick(port, ('observation_id', 'identity_sha256', 'observed_at', 'reason', 'error_code')))
        endpoint['observation_time_basis'] = port.get('observation_time_basis')
        relevance, relevance_reason = finding_relevance(row, endpoint,
            latest_asset_scan=asset.get('last_scan_id'), historical=selection['type'] == 'scan')
        verified_links = [link for link in row.get('observation_links', []) if link['relation'] == 'VERIFIED']
        verification_relevance = 'CURRENT' if endpoint.get('observation_id') is not None and any(
            link['observation_id'] == endpoint['observation_id'] for link in verified_links) else 'NOT_REOBSERVED'
        effective_status = item['status'] if relevance == 'CURRENT' else None
        if effective_status == 'CONFIRMED' and verification_relevance != 'CURRENT':
            effective_status = 'RETEST_REQUIRED'
        assessment, freshness, reasons = _assessment(latest.get(item["vuln_id"]), item, asset, endpoint)
        if relevance != 'CURRENT' or effective_status != item['status']:
            reasons.append('finding_current_relevance_not_verified')
            freshness = 'STALE' if assessment else 'MISSING'
        priority = assessment["priority"] if freshness == "CURRENT" else "UNASSESSED"
        item.update(endpoint=endpoint, assessment=assessment, assessment_freshness=freshness,
                    current_relevance=relevance, relevance_reason=relevance_reason,
                    historical_status=item['status'], effective_status=effective_status,
                    verification_relevance=verification_relevance, observation_links=json_value(row.get('observation_links', [])),
                    freshness_reasons=reasons, effective_priority=priority,
                    effective_action=assessment["action"] if freshness == "CURRENT" else None,
                    evidence=evidence_by.get(item["vuln_id"], []), history=history_by.get(item["vuln_id"], []))
        asset["findings"].append(item)
        summary['historical_status_counts'][item['status']] += 1
        summary['relevance_counts'][relevance] += 1
        if effective_status:
            summary['current_finding_count'] += 1
            summary['status_counts'][effective_status] = summary['status_counts'].get(effective_status, 0) + 1
        summary["priority_counts"][priority] += 1
        summary["assessment_freshness_counts"][freshness] += 1
    summary["highest_priority"] = next((level for level in PRIORITIES if summary["priority_counts"][level]), "UNASSESSED")
    for asset in by_asset.values():
        asset["findings"].sort(key=lambda finding: (PRIORITIES.index(finding["effective_priority"]), finding["vuln_id"]))
    scan_documents = []
    for row in sorted(scans, key=lambda row: row["scan_id"]):
        item = _pick(row, ("scan_id", "scan_uid", "status", "scan_type", "target", "port_range", "started_at", "finished_at"))
        item['immutable_execution'] = json_value(row.get('immutable_execution'))
        targets = row.get("requested_targets")
        try:
            targets = json.loads(targets) if isinstance(targets, (str, bytes)) else targets
            if targets is not None and not isinstance(targets, list):
                raise ValueError("Invalid requested targets")
            item["requested_targets"] = json_value(targets)
            item["requested_targets_status"] = "PARSED" if targets is not None else "MISSING"
        except (ValueError, TypeError):
            item.update(requested_targets=None, requested_targets_status="PARSE_ERROR")
        item["scope"] = _pick(row, ("scope_uid", "authorization_ref", "approved_by", "valid_from", "valid_until", "policy_sha256"))
        scan_documents.append(item)
    snapshot = {"schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "selection": selection, "summary": summary, "scans": scan_documents, "assets": list(by_asset.values()),
                "history_capability": 'IMMUTABLE_V8' if any(r.get('immutable_execution') for r in scans) else 'LEGACY_CURRENT_STATE_ONLY',
                "timestamp_policy": 'Explicit UTC is offset-aware; legacy naive wall clocks retain unknown timezone without a fabricated Z.',
                "finding_status_basis": 'Stored review status/history is retained; effective_status is qualified by observation relevance. Historical observation replay is not an as-of finding-status snapshot.',
                "integrity": {"algorithm": "SHA-256", "digest_excludes": ["generated_at", "integrity.snapshot_sha256"]}}
    snapshot["integrity"]["snapshot_sha256"] = snapshot_sha256(snapshot)
    return snapshot


def build_report_snapshot(*, asset_uid=None, scan_id=None):
    selection = validate_selection(asset_uid=asset_uid, scan_id=scan_id)
    conn = None
    try:
        conn = get_connection()
        # Fail closed if the connector/server cannot establish these semantics.
        conn.start_transaction(isolation_level="REPEATABLE READ", consistent_snapshot=True, readonly=True)
        rows = _read_rows(conn, selection)
    except (ReportSelectionError, ReportDataError):
        raise
    except Exception as exc:
        raise ReportDatabaseError("Read-only report query failed (" + type(exc).__name__ + ")") from exc
    finally:
        if conn is not None:
            try:
                conn.rollback()  # End read-only transaction. Never commit in a report.
            finally:
                conn.close()
    return _assemble(selection, rows)


def generate_report(*, asset_uid=None, scan_id=None, output_dir="reports", format="both"):
    if format not in {"json", "pdf", "both"}:
        raise ReportSelectionError("format must be json, pdf or both")
    snapshot = build_report_snapshot(asset_uid=asset_uid, scan_id=scan_id)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    selection = snapshot["selection"]
    identifier = selection.get("asset_uid", selection.get("scan_id"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stem = f"report_{selection['type']}_{identifier}_{stamp}"
    output = {"selection": selection, "snapshot_sha256": snapshot["integrity"]["snapshot_sha256"],
              "json_path": None, "pdf_path": None}
    # Finish both formats before publishing either. Temporary partial files are cleaned up on failure.
    with TemporaryDirectory(prefix=".report-", dir=directory) as temporary:
        created = []
        if format in {"json", "both"}:
            temp = Path(temporary) / (stem + ".json")
            temp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
            created.append(("json_path", temp, directory / temp.name))
        if format in {"pdf", "both"}:
            from api.report_pdf import render_report_pdf
            temp = Path(temporary) / (stem + ".pdf")
            render_report_pdf(snapshot, temp)
            created.append(("pdf_path", temp, directory / temp.name))
        for key, temp, destination in created:
            os.replace(temp, destination)
            output[key] = str(destination)
    return output
