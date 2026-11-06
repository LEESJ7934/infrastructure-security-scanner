"""Versioned internal criteria, explicitly attested approvals and audit GUIDs.

No policy writes. An approval file's hash proves agreement, not authority.
Operational approval requires a caller's explicit review acknowledgement too.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

TARGETS = {"WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004", "WIN-LAB-009"}
AUDIT_GUIDS = {
    "0cce9215-69ae-11d9-bed3-505054503030": "Logon",
    "0cce923f-69ae-11d9-bed3-505054503030": "Credential Validation",
    "0cce9235-69ae-11d9-bed3-505054503030": "User Account Management",
    "0cce922f-69ae-11d9-bed3-505054503030": "Audit Policy Change",
    "0cce922b-69ae-11d9-bed3-505054503030": "Process Creation",
}
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "rules/windows-server-lab.json"


class WindowsPolicyError(ValueError):
    pass


def ensure(ok, code="policy_schema_invalid"):
    if not ok:
        raise WindowsPolicyError(code)


def obj(value, allowed):
    ensure(isinstance(value, dict) and set(value) <= set(allowed))


def label(value):
    ensure(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", value), "policy_label_invalid")
    ensure(not re.search(r"secret|token|authorization|private.?key|api.?key", value, re.I), "policy_sensitive_metadata")


def aware(value):
    if not isinstance(value, str) or len(value) > 64 or "T" not in value or value.endswith("-00:00"):
        return None
    try:
        result = datetime.fromisoformat(value)
        return result if result.utcoffset() is not None else None
    except ValueError:
        return None


def unique(pairs):
    output = {}
    for key, value in pairs:
        ensure(key not in output, "policy_duplicate_key")
        output[key] = value
    return output


def parse_audit(values):
    """System-policy masks only; never parse localized display labels or CSV."""
    obj(values, {"parser_verified", "method", "subcategories"})
    if values.get("method") != "AuditQuerySystemPolicy":
        return None
    ensure(values.get("parser_verified") is True, "audit_parser_unverified")
    rows = values.get("subcategories")
    if rows is None:
        return None
    ensure(isinstance(rows, list) and len(rows) <= 5, "audit_schema_invalid")
    result = {}
    for row in rows:
        obj(row, {"guid", "mask"})
        guid = row.get("guid")
        ensure(isinstance(guid, str), "audit_guid_invalid")
        guid = guid.lower().strip("{}")
        ensure(guid in AUDIT_GUIDS and guid not in result, "audit_guid_invalid")
        mask = row.get("mask")
        ensure(type(mask) is int and mask in (0, 1, 2, 3, 4), "audit_mask_invalid")
        result[guid] = {"success": bool(mask & 1), "failure": bool(mask & 2), "mask": mask}
    return result


@dataclass(frozen=True)
class WindowsPolicy:
    document: dict
    sha256: str
    approval_attested: bool = False
    approval_integrity: str = "NOT_VERIFIED"

    def issues(self, asset_id, system, check_id):
        approval = self.document["approval"]
        scope = approval["scope"]
        issues = []
        if not self.approval_attested or self.approval_integrity != "VERIFIED" or approval["status"] != "APPROVED":
            issues.append("internal_policy_approval_not_verified")
        if (asset_id not in scope["asset_ids"] or check_id not in scope["check_ids"]
                or system.get("server_release") not in scope["server_releases"]
                or system.get("build_number") not in scope["build_numbers"]):
            issues.append("internal_policy_scope_not_matched")
        if (system.get("product_type"), system.get("domain_role"), system.get("part_of_domain")) != (3, 2, False):
            issues.append("domain_or_role_effective_policy_not_verified")
        if check_id == "WIN-LAB-004" and any(self.document["password"].get(key) is None for key in ("duration_minutes", "reset_minutes")):
            issues.append("lockout_duration_reset_approval_missing")
        return issues

    def predicate(self, check_id, values):
        settings = self.document["password"]
        if check_id == "WIN-LAB-009":
            observed = parse_audit(values)
            if observed is None or set(observed) != set(AUDIT_GUIDS):
                return None
            for guid, expected in self.document["audit"].items():
                if any(expected[key] and not observed[guid][key] for key in ("success", "failure")):
                    return False
            return True
        if values.get("merged_policy") is not True:
            return None
        needed = {"WIN-LAB-002": ("minimum_length",), "WIN-LAB-003": ("complexity",),
                  "WIN-LAB-004": ("lockout_threshold", "lockout_duration", "reset_minutes")}[check_id]
        if any(values.get(key) is None for key in needed):
            return None
        if check_id == "WIN-LAB-002":
            return values["minimum_length"] >= settings["minimum_length"]
        if check_id == "WIN-LAB-003":
            return values["complexity"] is settings["complexity_required"]
        if any(settings.get(key) is None for key in ("duration_minutes", "reset_minutes")):
            return None
        return (values["lockout_threshold"] == settings["lockout_threshold"]
                and values["lockout_duration"] == settings["duration_minutes"]
                and values["reset_minutes"] == settings["reset_minutes"])


def load_policy(path=DEFAULT_POLICY, *, project_root=None, acknowledge_approval=False):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(65537)
        ensure(len(raw) <= 65536, "policy_size_invalid")
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                         parse_constant=lambda _: ensure(False, "policy_json_invalid"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise WindowsPolicyError("policy_input_invalid") from None
    obj(doc, {"schema_version", "policy_id", "version", "approval", "password", "audit"})
    ensure(type(doc.get("schema_version")) is int and doc["schema_version"] == 1)
    label(doc.get("policy_id")); label(doc.get("version"))
    approval = doc.get("approval")
    obj(approval, {"status", "authority", "approved_at", "scope", "basis", "evidence"})
    ensure(isinstance(approval.get("status"), str) and approval["status"] in {"DRAFT", "APPROVED"})
    for field in ("authority", "basis"):
        if approval.get(field) is not None:
            label(approval[field])  # Non-secret record IDs, not arbitrary raw text.
    approved_at = aware(approval.get("approved_at"))
    if approval.get("approved_at") is not None:
        ensure(approved_at is not None, "policy_approval_time_invalid")
    scope = approval.get("scope")
    obj(scope, {"asset_ids", "server_releases", "build_numbers", "check_ids", "role"})
    ensure(scope.get("role") == "standalone_local_sam_and_system_audit")
    for key in ("asset_ids", "server_releases", "build_numbers", "check_ids"):
        ensure(isinstance(scope.get(key), list) and len(scope[key]) <= 64)
        for item in scope[key]: label(item)
        ensure(len(set(scope[key])) == len(scope[key]))
    ensure(set(scope["check_ids"]) <= TARGETS)
    settings = doc.get("password")
    obj(settings, {"minimum_length", "complexity_required", "lockout_threshold", "duration_minutes", "reset_minutes"})
    ensure(type(settings.get("minimum_length")) is int and 1 <= settings["minimum_length"] <= 128)
    ensure(settings.get("complexity_required") is True)
    ensure(type(settings.get("lockout_threshold")) is int and 1 <= settings["lockout_threshold"] <= 999)
    for key in ("duration_minutes", "reset_minutes"):
        ensure(settings.get(key) is None or type(settings[key]) is int and 1 <= settings[key] <= 1440)
    if all(settings.get(key) is not None for key in ("duration_minutes", "reset_minutes")):
        ensure(settings["duration_minutes"] >= settings["reset_minutes"])
    audit = doc.get("audit")
    obj(audit, AUDIT_GUIDS)
    ensure(set(audit) == set(AUDIT_GUIDS))
    for value in audit.values():
        obj(value, {"success", "failure"})
        ensure(set(value) == {"success", "failure"} and all(type(item) is bool for item in value.values()))
        ensure(value["success"] or value["failure"])
    evidence = approval.get("evidence")
    obj(evidence, {"path", "sha256"})
    for key in ("path", "sha256"):
        ensure(evidence.get(key) is None or isinstance(evidence[key], str))
    verified = False
    if approval["status"] == "APPROVED":
        ensure(approval.get("authority") and approval.get("basis") and approved_at is not None, "policy_approval_incomplete")
        ensure(approved_at <= datetime.now(timezone.utc), "policy_approval_future")
        ensure(scope["asset_ids"] and scope["check_ids"], "policy_approval_incomplete")
        relative, expected = evidence.get("path"), evidence.get("sha256")
        ensure(isinstance(relative, str) and isinstance(expected, str) and re.fullmatch(r"[a-fA-F0-9]{64}", expected), "policy_approval_evidence_missing")
        ensure(not re.search(r"\\|:|\.\.|^/|(^|/)(?:\.env|\.git)(/|$)", relative, re.I), "policy_approval_path_invalid")
        ensure(all(not part.startswith(".") for part in relative.split("/"))
               and not re.search(r"secret|private.?key|\.env", relative, re.I), "policy_approval_path_invalid")
        root = Path(project_root or DEFAULT_POLICY.parent.parent).resolve()
        allowed = root / "evidence/phase2-windows/approvals"
        candidate = allowed / relative
        try:
            ensure(candidate.suffix.lower() in {".json", ".txt", ".pdf"}, "policy_approval_path_invalid")
            ensure(candidate.resolve().is_relative_to(allowed.resolve()) and allowed.resolve().is_relative_to(root), "policy_approval_path_invalid")
            for part in (candidate, *candidate.parents):
                if part == root: break
                ensure(not part.is_symlink() and not getattr(part, "is_junction", lambda: False)(), "policy_approval_path_invalid")
            with candidate.open("rb") as stream: proof = stream.read(1024 * 1024 + 1)
            ensure(len(proof) <= 1024 * 1024 and hashlib.sha256(proof).hexdigest() == expected.lower(), "policy_approval_hash_mismatch")
            verified = True
        except OSError:
            raise WindowsPolicyError("policy_approval_evidence_unavailable") from None
    return WindowsPolicy(doc, hashlib.sha256(raw).hexdigest(), bool(acknowledge_approval and verified),
                         "VERIFIED" if verified else "NOT_VERIFIED")
