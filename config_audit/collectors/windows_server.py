"""Offline Windows Server observations; no commands, network or policy writes.

WIN-LAB rules are internal lab criteria, NOT verified KISA item mappings.
2022 build 20348 has a user-reported lab run; 2019/2025 remain candidates.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from uuid import uuid4

from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation
from ..reporting import ReportResult, SourceSnapshot
from ..windows_comparison import assess_collection_time
from ..windows_policy import TARGETS, WindowsPolicyError, load_policy, parse_audit

MAX_BYTES = 1024 * 1024
RULE_VERSION = "0.1"
RULE_VERSIONS = {"WIN-LAB-005": "0.2"}
VERSIONS = {"2019", "2022", "2025"}
STATES = {"COLLECTED", "ERROR", "NOT_TESTED", "NOT_APPLICABLE"}
ERRORS = {"permission_denied", "command_unavailable", "query_failed", "parse_failed"}
KISA = "https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&menuNo=205021&nttId=71928"
# Each tuple: section, criterion, recommendation, scope.
CHECKS = {
    "WIN-LAB-001": ("guest", "Built-in local Guest (RID 501) disabled", "Disable the local Guest account after role review.", "local_sam_guest"),
    "WIN-LAB-002": ("security_policy", "Minimum length meets explicitly approved internal policy", "Review local minimum length against approved organizational policy.", "standalone_local_sam_length"),
    "WIN-LAB-003": ("security_policy", "Local complexity enabled", "Review local complexity against approved organizational policy.", "standalone_local_sam_complexity"),
    "WIN-LAB-004": ("security_policy", "Threshold, duration and reset match explicitly approved internal policy", "Approve lockout and recovery values with denial-of-service risk considered.", "standalone_local_sam_lockout"),
    "WIN-LAB-005": ("spooler", "Unneeded Spooler stopped and disabled; proven absence requires role applicability review", "Confirm printing requirements and installed roles before manual service changes.", "role_approved_spooler"),
    "WIN-LAB-006": ("firewall", "All three ActiveStore profiles enabled and MpsSvc running", "Review resultant firewall profiles and separately test allowed traffic.", "activestore_profiles_not_reachability"),
    "WIN-LAB-007": ("smb", "SMB server SMB1 protocol disabled", "Review legacy dependencies before disabling SMB1 manually.", "inbound_smb_server_protocol"),
    "WIN-LAB-008": ("smb", "SMB server requires signing", "Review inbound SMB signing requirements and client compatibility.", "inbound_smb_server_signing_not_sessions"),
    "WIN-LAB-009": ("audit", "Five system audit subcategories meet explicitly approved internal policy", "Collect GUID-based system policy and review required success/failure events.", "system_audit_subcategories_only"),
}


class WindowsInputError(ValueError):
    """Fixed codes only; never echo raw JSON, exceptions or file paths."""


def require(ok, code="schema_invalid"):
    if not ok:
        raise WindowsInputError(code)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", value), "identifier_invalid")
    require(not re.search(r"secret|token|authorization|password|private.?key|api.?key", value, re.I), "sensitive_identifier")
    return value


def moment(value):
    require(isinstance(value, str) and len(value) <= 64 and "T" in value, "timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value)
        require(parsed.utcoffset() is not None, "timestamp_timezone_required")
    except ValueError:
        raise WindowsInputError("timestamp_invalid") from None
    return value


def unique(pairs):
    output = {}
    for key, value in pairs:
        require(key not in output, "duplicate_json_key")
        output[key] = value
    return output


def keys(value, allowed):
    require(isinstance(value, dict) and set(value) <= set(allowed), "unexpected_fields")


FIELDS = {
    "guest": {"enabled": bool, "matching_accounts": int},
    "security_policy": {"minimum_length": int, "complexity": bool, "lockout_threshold": int,
                        "lockout_duration": int, "reset_minutes": int, "merged_policy": bool},
    "spooler": {"required": bool, "role_approval": str, "running": bool, "disabled": bool,
                "present": bool, "native_error_code": int, "feature_query_state": str,
                "feature_error_code": str, "print_services_installed": bool, "print_server_installed": bool},
    "firewall": {"policy_store": str, "domain": bool, "private": bool, "public": bool, "service_running": bool},
    "smb": {"smb1_enabled": bool, "require_signing": bool},
    "audit": {"parser_verified": bool, "method": str, "subcategories": list},
}


@dataclass(frozen=True)
class WindowsBundle:
    document: dict
    sha256: str
    integrity: str
    expected_sha256: str | None = None


def load_bundle(path, *, expected_sha256=None):
    """Read one explicitly supplied JSON. Hash agreement is not authenticity."""
    if expected_sha256 is not None:
        require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256), "sha256_invalid")
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        raise WindowsInputError("input_unavailable") from None
    require(len(raw) <= MAX_BYTES, "input_too_large")
    digest = hashlib.sha256(raw).hexdigest()
    require(expected_sha256 is None or hmac.compare_digest(digest, expected_sha256.lower()), "sha256_mismatch")
    try:
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(WindowsInputError("json_invalid")))
    except (ValueError, UnicodeError, RecursionError):
        raise WindowsInputError("json_invalid") from None
    validate(document)
    return WindowsBundle(document, digest, "VERIFIED" if expected_sha256 else "NOT_VERIFIED", expected_sha256.lower() if expected_sha256 else None)


def validate(doc):
    keys(doc, {"schema_version", "origin", "asset_id", "collected_at", "system", "sections"})
    require(type(doc.get("schema_version")) is int and doc["schema_version"] == 1)
    require(isinstance(doc.get("origin"), str) and doc["origin"] in {"local_server_readonly", "synthetic"}, "origin_invalid")
    identifier(doc.get("asset_id"))
    moment(doc.get("collected_at"))
    system = doc.get("system")
    keys(system, {"server_release", "os_version", "build_number", "product_type", "domain_role", "part_of_domain", "is_64bit"})
    for name in ("product_type", "domain_role"):
        require(system.get(name) is None or type(system[name]) is int)
    for name in ("part_of_domain", "is_64bit"):
        require(system.get(name) is None or type(system[name]) is bool)
    release = system.get("server_release")
    require(release is None or isinstance(release, str) and re.fullmatch(r"[0-9]{4}", release))
    for field, pattern in (("os_version", r"[0-9]+(?:\.[0-9]+){1,3}"), ("build_number", r"[0-9]{1,10}")):
        value = system.get(field)
        require(value is None or isinstance(value, str) and len(value) <= 40 and re.fullmatch(pattern, value), "os_version_invalid")
    sections = doc.get("sections")
    keys(sections, FIELDS)
    for name, section in sections.items():
        keys(section, {"state", "error_code", "values"})
        require(isinstance(section.get("state"), str) and section["state"] in STATES, "collection_state_invalid")
        require(section.get("error_code") is None or isinstance(section["error_code"], str) and section["error_code"] in ERRORS, "error_code_invalid")
        require(section["state"] != "ERROR" or section.get("error_code") in ERRORS)
        values = section.get("values", {})
        keys(values, FIELDS[name])
        require(section["state"] == "COLLECTED" or not values, "values_without_collection")
        for field, value in values.items():
            if value is None:
                continue
            expected = FIELDS[name][field]
            require(type(value) is expected, "value_type_invalid")
            if name == "audit" and field in {"method", "subcategories"}:
                continue
            if expected is int:
                require(0 <= value <= 99999, "value_range_invalid")
            if field == "role_approval":
                identifier(value)
            elif field == "feature_query_state":
                require(value in {"COLLECTED", "ERROR", "NOT_TESTED"}, "feature_state_invalid")
            elif field == "feature_error_code":
                require(value in ERRORS, "error_code_invalid")
            elif expected is str:
                require(value == "ActiveStore", "policy_store_invalid")
        if name == "audit":
            require(values.get("method") is None or values["method"] == "AuditQuerySystemPolicy", "audit_method_invalid")
            try:
                parse_audit(values)
            except WindowsPolicyError:
                raise WindowsInputError("audit_schema_invalid") from None
        if name == "spooler":
            if values.get("present") is False:
                require(values.get("running") is None and values.get("disabled") is None, "spooler_presence_conflict")
            if values.get("native_error_code") is not None:
                require(values.get("present") is False and values["native_error_code"] == 1060, "spooler_presence_conflict")
            if values.get("feature_query_state") != "COLLECTED":
                require(all(values.get(key) is None for key in ("print_services_installed", "print_server_installed")), "feature_state_conflict")
            if values.get("feature_query_state") == "ERROR":
                require(values.get("feature_error_code") in ERRORS, "feature_error_missing")


def role(system):
    signature = (system.get("product_type"), system.get("domain_role"), system.get("part_of_domain"))
    if signature == (3, 2, False):
        return "standalone"
    if signature == (3, 3, True):
        return "member"
    if signature in {(2, 4, True), (2, 5, True)}:
        return "dc"
    return "unknown"


def _complete(values, names):
    return all(name in values and values[name] is not None for name in names)


def condition(check_id, value):
    """Trusted predicates only; evaluate() owns all status decisions."""
    if not isinstance(value, dict) or value.get("review"):
        return None
    if check_id == "WIN-LAB-005" and value.get("present") is False:
        return None  # Absence is never PASS or FAIL; applicability is reviewed separately.
    requirements = {
        "WIN-LAB-001": ("enabled", "matching_accounts"),
        "WIN-LAB-005": ("required", "role_approval", "running", "disabled"),
        "WIN-LAB-006": ("policy_store", "domain", "private", "public", "service_running"),
        "WIN-LAB-007": ("smb1_enabled",), "WIN-LAB-008": ("require_signing",),
    }
    if check_id not in requirements or not _complete(value, requirements[check_id]):
        return None
    if check_id == "WIN-LAB-001":
        return not value["enabled"] if value["matching_accounts"] == 1 else None
    if check_id == "WIN-LAB-005":
        return None if value["required"] or value["role_approval"] == "UNCONFIRMED" else not value["running"] and value["disabled"]
    if check_id == "WIN-LAB-006":
        return (all(value[name] for name in ("domain", "private", "public", "service_running"))
                if value["policy_store"] == "ActiveStore" else None)
    if check_id == "WIN-LAB-007":
        return not value["smb1_enabled"]
    if check_id == "WIN-LAB-008":
        return value["require_signing"]
    return None


class WindowsServerCollector:
    def __init__(self, bundle=None, policy=None):
        if bundle is not None:
            validate(bundle.document)
        self.bundle = bundle
        self.policy = policy or load_policy()

    def rule(self, check_id):
        section, expected, recommendation, _ = CHECKS[check_id]
        doc = self.bundle.document if self.bundle else None
        system = doc["system"] if doc else {}

        def applicable(version):
            if system.get("product_type") is None:
                return None
            if version not in VERSIONS or system.get("product_type") not in (2, 3):
                return False
            if system.get("is_64bit") is not True or role(system) == "unknown":
                return None
            if check_id == "WIN-LAB-001" and role(system) == "dc":
                return False
            values = doc["sections"].get(section, {}).get("values", {})
            if check_id == "WIN-LAB-005" and values.get("present") is False:
                if (self.bundle.integrity == "VERIFIED" and doc["sections"][section]["state"] == "COLLECTED"
                        and values.get("native_error_code") == 1060
                        and values.get("required") is False and values.get("role_approval") not in (None, "UNCONFIRMED")
                        and values.get("feature_query_state") == "COLLECTED"
                        and values.get("print_services_installed") is False
                        and values.get("print_server_installed") is False):
                    return False
                return True
            if (check_id == "WIN-LAB-005" and values.get("required") is True
                    and values.get("role_approval") not in (None, "UNCONFIRMED")):
                return False
            return True

        predicate = (lambda value: self.policy.predicate(check_id, value) if not value.get("review") else None) if check_id in TARGETS else lambda value: condition(check_id, value)
        return AuditRule(check_id, self.policy.document["version"] if check_id in TARGETS else RULE_VERSIONS.get(check_id, RULE_VERSION), expected, recommendation,
                         condition=predicate, product="windows_server",
                         version_matches=applicable if doc else None,
                         standard_reference="Internal lab baseline; KISA 2025-12-24 mapping UNVERIFIED")

    def collect(self, asset, check_id):
        section = CHECKS[check_id][0]
        if self.bundle is None:
            return Observation()
        doc = self.bundle.document
        reference = f"windows-evidence:{self.bundle.sha256}#{section}"
        if asset.asset_id != doc["asset_id"]:
            return Observation(evidence_reference=reference, collection_error=True)
        value = doc["sections"].get(section)
        if value is None or value["state"] == "NOT_TESTED":
            return Observation(evidence_reference=reference)
        if value["state"] == "ERROR":
            return Observation(evidence_reference=reference, collection_error=True)
        # Only independent hash agreement and explicit scope can support a verdict.
        if self.bundle.integrity != "VERIFIED" or value["state"] != "COLLECTED":
            return Observation({"review": True}, reference)
        if check_id in TARGETS and self.policy.issues(asset.asset_id, doc["system"], check_id):
            return Observation({"review": True}, reference)
        if section == "security_policy" and role(doc["system"]) != "standalone":
            return Observation({"review": True}, reference)
        return Observation(value.get("values", {}), reference)


def audit(bundle=None, *, asset_id, synthetic=False, policy=None):
    identifier(asset_id)
    if bundle is not None:
        require(bundle.document["asset_id"] == asset_id, "asset_binding_mismatch")
        require((bundle.document["origin"] == "synthetic") == synthetic, "origin_mode_mismatch")
    collector = WindowsServerCollector(bundle, policy)
    system = bundle.document["system"] if bundle else {}
    asset = AuditAsset(asset_id, "windows_server", system.get("server_release"))
    now = datetime.now(timezone.utc)
    execution_id = str(uuid4())
    rows = []
    for check_id, (section, _, _, scope) in CHECKS.items():
        result = evaluate(asset, collector.rule(check_id), collector.collect(asset, check_id),
                          execution_id=execution_id, checked_at=now)
        state = bundle.document["sections"].get(section, {}).get("state", "NOT_TESTED") if bundle else "NOT_TESTED"
        policy_issues = collector.policy.issues(asset_id, system, check_id) if check_id in TARGETS else []
        values = bundle.document["sections"].get(section, {}).get("values", {}) if bundle else {}
        missing = {"WIN-LAB-002": ["minimum_length"], "WIN-LAB-003": ["complexity"],
                   "WIN-LAB-004": ["lockout_threshold", "lockout_duration", "reset_minutes"]}.get(check_id, [])
        missing = [key for key in missing if values.get(key) is None]
        if check_id == "WIN-LAB-009" and (not values.get("subcategories") or len(values["subcategories"]) != 5):
            missing.append("system_audit_subcategories")
        reason = "not_collected" if bundle is None else (
            "required_settings_missing" if missing else
            "internal_policy_approval_or_scope_missing" if policy_issues else
            "domain_effective_account_policy_not_verified" if section == "security_policy" and role(system) != "standalone" else
            "independent_hash_not_provided" if bundle.integrity != "VERIFIED" else
            "spooler_absent_role_review" if section == "spooler" and bundle.document["sections"].get(section, {}).get("values", {}).get("present") is False else
            "check_scope_and_collection_conditions")
        rows.append({**result.to_safe_dict(), "product": result.product, "version": result.version,
                     "os_version": system.get("os_version"), "build_number": system.get("build_number"),
                     "product_type": system.get("product_type"), "domain_role": system.get("domain_role"),
                     "part_of_domain": system.get("part_of_domain"),
                     "scope": scope, "verification_method": "saved_readonly_settings",
                     "time_basis": "reanalysis_time",
                     "diagnostic_source": "phase2_windows_server", "collection_status": state,
                     "collection_error_code": bundle.document["sections"].get(section, {}).get("error_code") if bundle else None,
                     "service_presence": bundle.document["sections"].get(section, {}).get("values", {}).get("present") if bundle and section == "spooler" else None,
                     "feature_collection_status": bundle.document["sections"].get(section, {}).get("values", {}).get("feature_query_state") if bundle and section == "spooler" else None,
                     "feature_error_code": bundle.document["sections"].get(section, {}).get("values", {}).get("feature_error_code") if bundle and section == "spooler" else None,
                     "evidence_reference": result.evidence_reference, "recommendation": result.recommendation,
                     "expected_condition": result.expected_condition,
                     "standard_reference": result.standard_reference, "official_check_id": None,
                     "reason": reason, "collected_at": bundle.document["collected_at"] if bundle else None})
        rows[-1]["unmet_conditions"] = sorted(set(policy_issues + ["missing_" + key for key in missing]))
        if check_id in TARGETS:
            rows[-1]["internal_policy"] = {"policy_id": collector.policy.document["policy_id"], "version": collector.policy.document["version"],
                "sha256": collector.policy.sha256, "approval_status": collector.policy.document["approval"]["status"],
                "approval_attested": collector.policy.approval_attested, "approval_integrity": collector.policy.approval_integrity}
    return {"schema_version": 1, "phase": 2, "mode": "synthetic_unit_test_only" if synthetic else "offline_saved_settings" if bundle else "preparation_only",
            "generated_at": now.isoformat(), "origin": bundle.document["origin"] if bundle else None,
            "collection_time_validation": assess_collection_time(bundle.document["collected_at"] if bundle else None, reference_at=now),
            "integrity": bundle.integrity if bundle else "NOT_VERIFIED", "sha256": bundle.sha256 if bundle else None,
            "expected_sha256": bundle.expected_sha256 if bundle else None,
            "results": [] if synthetic else rows, "synthetic_results": rows if synthetic else [],
            "limitations": ["2019_2025_not_vm_validated_2022_build20348_lab_only", "internal_criteria_not_verified_KISA_mapping",
                            "hash_agreement_not_authenticity", "settings_only_not_traffic_or_sessions",
                            "no_domain_user_or_FGPP_verification", "system_audit_settings_not_actual_event_or_per_user_verification",
                            "phase2_evidence_index_policy_not_enabled"]}


def to_report_snapshot(report, *, snapshot_id):
    """Typed common model adapter; opt-in, never updates Day5 artifacts.

    day=0 explicitly means a phase2 source outside the Day1..5 catalog.
    Existing Day5 normalize/index policies intentionally do not accept it.
    Synthetic statuses stay in supplemental analyses, never automatic.
    """
    identifier(snapshot_id)
    rows = report["results"] or report["synthetic_results"]
    synthetic = report["mode"] == "synthetic_unit_test_only"
    def automatic(row):
        if synthetic:
            return None
        value = dict(row)
        value["evidence_references"] = ([{"reference": row["evidence_reference"]}]
                                         if row.get("evidence_reference") else [])
        return value

    return SourceSnapshot(snapshot_id, 0, "phase2_windows_server", "windows_server_v1",
                          tuple(ReportResult(row["asset_id"], row["check_id"], row["rule_version"],
                                             automatic(row),
                                             analyses={"synthetic_simulation": dict(row)} if synthetic else {},
                                             recommendation=row["recommendation"]) for row in rows),
                          diagnostics=tuple(report["limitations"]),
                          collection={"integrity": report["integrity"], "phase": 2,
                                      "generated_at": report["generated_at"]})
