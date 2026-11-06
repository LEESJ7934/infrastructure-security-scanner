"""Personal LAB settings assessment; strict provenance review remains separate.

Uses the common evaluate() engine. User PowerShell confirmations are explicit
manual claims, never inserted into source exports or automatic observations.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .engine import evaluate
from .models import AuditAsset, AuditRule, Observation
from .collectors.windows_server import CHECKS, FIELDS, WindowsInputError, identifier, role, moment
from .windows_policy import AUDIT_GUIDS, WindowsPolicyError, parse_audit, unique, obj, label, ensure

DEFAULT_LAB_CRITERIA = Path(__file__).resolve().parents[1] / "rules/windows-server-personal-lab.json"
MANUAL_KEYS = {
    "WIN-LAB-001": {"enabled", "matching_accounts"},
    "WIN-LAB-002": {"minimum_length"}, "WIN-LAB-003": {"complexity"},
    "WIN-LAB-004": {"lockout_threshold", "lockout_duration", "reset_minutes"},
    "WIN-LAB-005": {"present", "required", "running", "disabled", "print_services_installed", "print_server_installed"},
    "WIN-LAB-006": {"domain", "private", "public", "service_running"},
    "WIN-LAB-007": {"smb1_enabled"}, "WIN-LAB-008": {"require_signing"},
    "WIN-LAB-009": {"parser_verified", "method", "subcategories"},
}
CRITERIA = {
    "WIN-LAB-001": "Built-in local Guest disabled",
    "WIN-LAB-002": "Minimum length >= 14",
    "WIN-LAB-003": "Complexity enabled",
    "WIN-LAB-004": "Lockout threshold 10; duration 30 min; reset 30 min",
    "WIN-LAB-005": "Spooler absent, print features absent, printing confirmed unnecessary; or unneeded service stopped/disabled",
    "WIN-LAB-006": "Selected firewall profiles enabled",
    "WIN-LAB-007": "SMB1 disabled",
    "WIN-LAB-008": "Inbound SMB server signing required",
    "WIN-LAB-009": "Five GUID-based system audit subcategories meet LAB success/failure requirements",
}


def criterion(check, criteria):
    pw = criteria["password"]
    if check == "WIN-LAB-002": return "Minimum length >= " + str(pw["minimum_length"])
    if check == "WIN-LAB-004": return "Lockout threshold " + str(pw["lockout_threshold"]) + "; duration/reset " + str(pw["duration_minutes"]) + "/" + str(pw["reset_minutes"]) + " min"
    if check == "WIN-LAB-006": return "Enabled firewall profiles: " + ", ".join(criteria["firewall_profiles"])
    return CRITERIA[check]


def _json(path, limit):
    try:
        with Path(path).open("rb") as stream: raw = stream.read(limit + 1)
        ensure(len(raw) <= limit, "lab_input_too_large")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                          parse_constant=lambda _: ensure(False, "lab_json_invalid"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise WindowsInputError("lab_input_invalid") from None
    return data, hashlib.sha256(raw).hexdigest()


def load_lab_criteria(path=DEFAULT_LAB_CRITERIA):
    doc, _ = _json(path, 65536)
    obj(doc, {"schema_version", "mode", "rule_version", "server_releases", "password", "firewall_profiles", "audit"})
    ensure(type(doc.get("schema_version")) is int and doc["schema_version"] == 1 and doc.get("mode") == "LAB")
    label(doc.get("rule_version"))
    ensure(isinstance(doc.get("server_releases"), list) and doc["server_releases"]
           and all(item in ("2019", "2022", "2025") for item in doc["server_releases"]))
    pw = doc.get("password")
    obj(pw, {"minimum_length", "complexity_required", "lockout_threshold", "duration_minutes", "reset_minutes"})
    for key in ("minimum_length", "lockout_threshold", "duration_minutes", "reset_minutes"):
        ensure(type(pw.get(key)) is int and 1 <= pw[key] <= 1440)
    ensure(pw.get("complexity_required") is True and pw["minimum_length"] <= 128
           and pw["duration_minutes"] >= pw["reset_minutes"])
    profiles = doc.get("firewall_profiles")
    ensure(isinstance(profiles, list) and profiles and all(item in ("domain", "private", "public") for item in profiles)
           and len(set(profiles)) == len(profiles))
    obj(doc.get("audit"), AUDIT_GUIDS)
    ensure(set(doc["audit"]) == set(AUDIT_GUIDS))
    for value in doc["audit"].values():
        obj(value, {"success", "failure"})
        ensure(set(value) == {"success", "failure"} and all(type(flag) is bool for flag in value.values())
               and any(value.values()))
    return doc


def load_lab_manual(path):
    doc, digest = _json(path, 65536)
    obj(doc, {"schema_version", "asset_id", "server_release", "build_number", "source_kind", "source_reference", "checks"})
    ensure(type(doc.get("schema_version")) is int and doc["schema_version"] == 1)
    for key in ("asset_id", "server_release", "build_number", "source_reference"): identifier(doc.get(key))
    ensure(doc.get("source_kind") == "user_powershell_confirmation")
    obj(doc.get("checks"), CHECKS)
    for check, record in doc["checks"].items():
        obj(record, {"scenario_id", "before", "after", "verified_at", "remediation_performed", "retested", "sequence_confirmed"})
        identifier(record.get("scenario_id"))
        for key in ("remediation_performed", "retested", "sequence_confirmed"):
            ensure(type(record.get(key)) is bool)
        if record.get("verified_at") is not None: moment(record["verified_at"])
        for side in ("before", "after"):
            values = record.get(side)
            obj(values, MANUAL_KEYS[check])
            if check == "WIN-LAB-009":
                parse_audit(values)
                continue
            section = CHECKS[check][0]
            for key, value in values.items():
                ensure(value is None or type(value) is FIELDS[section][key], "lab_manual_type_invalid")
                if type(value) is int: ensure(0 <= value <= 99999)
    return {"document": doc, "sha256": digest, "integrity": "NOT_VERIFIED",
            "original_transcript_attached": False, "source_authenticity_claimed": False}


def audit_details(values, criteria):
    observed = parse_audit(values)
    rows = []
    for guid, name in AUDIT_GUIDS.items():
        actual = (observed or {}).get(guid)
        expected = criteria["audit"][guid]
        status = "NOT_TESTED" if actual is None else "FAIL" if any(expected[k] and not actual[k] for k in ("success", "failure")) else "PASS"
        rows.append({"guid": guid, "name": name, "expected": expected, "observed": actual, "status": status})
    return rows


def predicate(check, values, criteria):
    pw = criteria["password"]
    def complete(*keys): return all(values.get(key) is not None for key in keys)
    if check == "WIN-LAB-001":
        return not values["enabled"] if complete("enabled", "matching_accounts") and values["matching_accounts"] == 1 else None
    if check == "WIN-LAB-002": return values["minimum_length"] >= pw["minimum_length"] if complete("minimum_length") else None
    if check == "WIN-LAB-003": return values.get("complexity")
    if check == "WIN-LAB-004":
        expected = {"lockout_threshold": pw["lockout_threshold"], "lockout_duration": pw["duration_minutes"], "reset_minutes": pw["reset_minutes"]}
        if any(values.get(key) is not None and values[key] != value for key, value in expected.items()): return False
        return True if complete(*expected) else None
    if check == "WIN-LAB-005":
        if values.get("present") is False:
            return True if all(values.get(key) is False for key in ("required", "print_services_installed", "print_server_installed")) else None
        if values.get("required") is False and complete("running", "disabled"):
            return not values["running"] and values["disabled"]
        return None
    if check == "WIN-LAB-006":
        profiles = criteria["firewall_profiles"]
        return all(values[key] for key in profiles) if complete(*profiles) else None
    if check == "WIN-LAB-007": return not values["smb1_enabled"] if complete("smb1_enabled") else None
    if check == "WIN-LAB-008": return values.get("require_signing")
    rows = audit_details(values, criteria)
    if any(row["status"] == "FAIL" for row in rows): return False
    return True if all(row["status"] == "PASS" for row in rows) else None


def _evaluate(bundle, check, values, criteria, *, source, error=False):
    system = bundle.document["system"]
    def applicable(version):
        if system.get("product_type") is None: return None
        if version not in criteria["server_releases"] or system.get("product_type") not in (2, 3): return False
        if role(system) == "unknown": return None
        if check == "WIN-LAB-001" and role(system) == "dc": return False
        if check in {"WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004"} and role(system) != "standalone": return None
        return True
    asset = AuditAsset(bundle.document["asset_id"], "windows_server", system.get("server_release"))
    rule = AuditRule(check, criteria["rule_version"], criterion(check, criteria), CHECKS[check][2],
        condition=lambda v: predicate(check, v, criteria), product="windows_server", version_matches=applicable,
        standard_reference="Personal LAB only; not KISA certification or customer assurance")
    result = evaluate(asset, rule, Observation(values, source, collection_error=error),
                      execution_id=str(uuid4()), checked_at=datetime.now(timezone.utc))
    return {**result.to_safe_dict(), "values": values, "source": source, "criterion": criterion(check, criteria),
            "recommendation": result.recommendation, "assessment_mode": "LAB"}


def build_lab_view(before, after, *, criteria=None, manual=None):
    criteria = criteria or load_lab_criteria()
    for bundle in (before, after):
        ensure(bundle.document["origin"] == "local_server_readonly", "lab_report_requires_saved_server_export")
    ensure(before.document["asset_id"] == after.document["asset_id"], "lab_asset_mismatch")
    for key in ("server_release", "os_version", "build_number", "product_type", "domain_role", "part_of_domain"):
        ensure(before.document["system"].get(key) is not None and before.document["system"].get(key) == after.document["system"].get(key), "lab_system_mismatch")
    records = {}
    if manual:
        doc = manual["document"]
        ensure(doc["asset_id"] == after.document["asset_id"] and doc["server_release"] == after.document["system"].get("server_release")
               and doc["build_number"] == after.document["system"].get("build_number"), "lab_manual_asset_or_system_mismatch")
        records = doc["checks"]
    rows = []
    for check in CHECKS:
        section = CHECKS[check][0]
        auto = {}
        for side, bundle in (("before", before), ("after", after)):
            raw = bundle.document["sections"].get(section, {})
            value = raw.get("values", {}) if raw.get("state") == "COLLECTED" else None
            auto[side] = _evaluate(bundle, check, value, criteria, source="automatic_saved_json", error=raw.get("state") == "ERROR")
            auto[side]["collected_at"] = bundle.document["collected_at"]
        record = records.get(check)
        manual_results = None
        assessed_before, assessed_after = auto["before"], auto["after"]
        basis = "automatic_saved_json"
        contributions = {key: "automatic_saved_json" for key in (auto["after"]["values"] or {})}
        conflicts = []
        if record:
            manual_results = {side: _evaluate(after, check, record[side] or None, criteria, source="user_powershell_confirmation") for side in ("before", "after")}
            manual_results["scenario_id"] = record["scenario_id"]
            manual_results["verified_at"] = record.get("verified_at")
            manual_results["source_reference"] = manual["document"]["source_reference"]
            manual_results["original_transcript_attached"] = False
            # Manual baseline belongs to its own described experiment, not the
            # newer JSON baseline. Never write it into automatic observations.
            if record["before"]: assessed_before = manual_results["before"]
            effective = dict(auto["after"]["values"] or {})
            for key, value in record["after"].items():
                if value is None: continue
                if effective.get(key) is not None and effective[key] != value: conflicts.append(key)
                effective[key] = value
                contributions[key] = "user_powershell_confirmation"
            assessed_after = _evaluate(after, check, effective or None, criteria, source="combined_lab_evidence" if auto["after"]["values"] else "user_powershell_confirmation")
            basis = "user_powershell_confirmation" if all(source == "user_powershell_confirmation" for key, source in contributions.items() if key in MANUAL_KEYS[check]) else "combined_automatic_and_manual"
            if conflicts:
                # Preserve conflicting input channels; no silent PASS override.
                assessed_after = _evaluate(after, check, {}, criteria, source="conflicting_current_values")
        complete = bool(record and record["remediation_performed"] and record["retested"] and record["sequence_confirmed"]
                        and assessed_before["status"] == "FAIL" and assessed_after["status"] == "PASS" and not conflicts)
        progress = ("LAB_REMEDIATION_AND_RETEST_COMPLETE" if complete else "UNCHANGED_PASS" if assessed_before["status"] == assessed_after["status"] == "PASS"
                    else "CURRENT_LAB_PASS" if assessed_after["status"] == "PASS" else "ACTION_REQUIRED" if assessed_after["status"] == "FAIL" else "NOT_VERIFIED")
        rows.append({"check_id": check, "asset_id": after.document["asset_id"], "criterion": criterion(check, criteria),
            "automatic": auto, "manual": manual_results, "before_values": assessed_before["values"], "after_values": assessed_after["values"],
            "before_status": assessed_before["status"], "status": assessed_after["status"], "assessment_basis": basis,
            "after_value_sources": contributions, "conflicting_fields": conflicts, "lab_remediation_status": progress,
            "remediation_complete": complete, "completion_basis": "user_confirmed_action_and_retest" if complete else None,
            "manual_baseline_separate_from_json_baseline": bool(record and record["before"]),
            "recommendation": CHECKS[check][2],
            "audit_subcategories": audit_details(assessed_after["values"] or {}, criteria) if check == "WIN-LAB-009" else None})
    return {"schema_version": 1, "mode": "LAB", "generated_at": datetime.now(timezone.utc).isoformat(), "criteria": criteria,
        "results": rows, "summary": dict(Counter(row["status"] for row in rows)),
        "remediation_completed_count": sum(row["remediation_complete"] for row in rows),
        "manual_source": {key: value for key, value in manual.items() if key != "document"} if manual else None,
        "limitations": ["personal_lab_only_not_KISA_or_customer_certification", "manual_values_are_user_confirmations_not_automatic_collection",
            "no_original_powershell_transcript_attached", "unknown_manual_test_times_not_fabricated",
            "hashes_and_strict_time_comparison_retained_in_advanced_validation", "no_windows_settings_changed"]}
