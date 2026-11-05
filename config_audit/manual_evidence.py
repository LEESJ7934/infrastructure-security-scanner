"""Local operator attestations, kept separate from automatic observations.

Only structured lab facts are exported. No arbitrary notes, source paths,
artifact contents, credentials or exception messages cross this boundary.
Artifact hashes establish integrity, not truth of the operator's conclusion.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

SCOPES = {
    "FW-01": "interface_assignment_only",
    "FW-02": "wan_to_firewall_tcp443_only",
    "FW-03": "wan_to_firewall_tcp22_only",
    "FW-04": "rules_inspect_screen_only",
    "FW-05": "log_collection_only",
    "FW-06": "windows_to_alpine_icmp_lab_only",
}
STATUSES = {"PASS", "FAIL", "NEEDS_REVIEW", "NOT_TESTED"}
RULE_NAMES = {"Default deny / state violation rule", "LAB-D4-Block-Windows-Alpine",
              "anti-lockout", "LAN default allow"}
KINDS = {"screenshot", "test_output", "firewall_log", "inspect_view", "operator_note"}
MAX_JSON_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024


class ManualEvidenceError(Exception):
    """Only fixed error codes, never user data or filesystem exception text."""


def require(condition):
    if not condition:
        raise ManualEvidenceError("manual_input_invalid")


def keys(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= value.keys()
            and value.keys() <= set(required) | set(optional))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def validate_test(test, check_id, source_count):
    keys(test, ("scenario", "source", "destination", "protocol", "port", "expected_result",
                "actual_result", "firewall_action", "rule_name", "source_indices"),
         ("packets_sent", "packets_received"))
    require(test["scenario"] in ("pass", "block", "restored"))
    require(test["expected_result"] in ("allowed", "blocked"))
    require((test["scenario"] == "block") == (test["expected_result"] == "blocked"))
    require(test["actual_result"] in ("success", "timeout", "unreachable", "inconclusive"))
    require(test["firewall_action"] in ("pass", "block", "reject", "not_observed"))
    require(test["rule_name"] is None or test["rule_name"] in RULE_NAMES)
    require(isinstance(test["source_indices"], list) and test["source_indices"]
            and all(type(index) is int and 0 <= index < source_count for index in test["source_indices"]))
    require(type(test["port"]) is int or test["port"] is None)
    packet = (test["source"], test["destination"], test["protocol"], test["port"])
    targets = {
        "FW-02": {("10.77.50.10", "10.77.50.1", "tcp", 443),
                  ("10.77.40.10", "10.77.40.1", "tcp", 443)},
        "FW-03": {("10.77.50.10", "10.77.50.1", "tcp", 22)},
        "FW-06": {("10.77.40.10", "10.77.50.10", "icmp", None)},
    }
    require(check_id in targets and packet in targets[check_id])
    if test["protocol"] == "icmp":
        sent, received = test.get("packets_sent"), test.get("packets_received")
        require(type(sent) is int and type(received) is int and 0 <= received <= sent <= 100 and sent > 0)
        require(test["actual_result"] != "success" or received == sent)
        require(test["actual_result"] != "timeout" or received == 0)
    else:
        require("packets_sent" not in test and "packets_received" not in test)


def pass_claim_consistent(check_id, tests):
    """Check internal consistency of a PASS claim, not artifact content truth."""
    for test in tests:
        allowed = test["expected_result"] == "allowed"
        if test["actual_result"] != ("success" if allowed else "timeout"):
            return False
        if allowed and test["firewall_action"] in {"block", "reject"}:
            return False
        if not allowed and test["firewall_action"] not in {"block", "reject"}:
            return False
    if check_id in {"FW-02", "FW-03"}:
        return any(test["source"] == "10.77.50.10" and test["expected_result"] == "blocked"
                   and test["rule_name"] == "Default deny / state violation rule" for test in tests)
    if check_id == "FW-06":
        return (all(any(test["scenario"] == scenario and test["expected_result"] == expected for test in tests)
                    for scenario, expected in (("pass", "allowed"), ("block", "blocked"), ("restored", "allowed")))
                and any(test["scenario"] == "block" and test["rule_name"] == "LAB-D4-Block-Windows-Alpine"
                        for test in tests))
    return True


def source_integrity(source, base):
    keys(source, ("kind", "path", "sha256"))
    require(source["kind"] in KINDS and isinstance(source["path"], str) and source["path"])
    digest = source["sha256"]
    require(isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest))
    path = Path(source["path"])
    require(not path.is_absolute() and ".." not in path.parts and ":" not in source["path"])
    try:
        resolved = (base / path).resolve()
        require(resolved.is_relative_to(base))
        with resolved.open("rb") as stream:
            digest_state, size = hashlib.sha256(), 0
            while chunk := stream.read(65536):
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    return "source_too_large"
                digest_state.update(chunk)
    except (OSError, ValueError):
        return "source_missing_or_unreadable"
    return "MATCH" if digest_state.hexdigest() == digest else "source_hash_mismatch"


def validate_record(record, base):
    keys(record, ("check_id", "reported_status", "verified_at", "scope", "sources", "tests"), ("inspection", "time_basis"))
    check_id, reported = record["check_id"], record["reported_status"]
    require(check_id in SCOPES and reported in STATUSES and record["scope"] == SCOPES[check_id])
    require(isinstance(record["sources"], list) and len(record["sources"]) <= 20)
    require(isinstance(record["tests"], list) and len(record["tests"]) <= 20)
    if reported == "NOT_TESTED":
        require(record["verified_at"] is None and not record["sources"] and not record["tests"]
                and "inspection" not in record)
        return {"reported_status": reported, "status": "NOT_TESTED", "scope": SCOPES[check_id],
                "validation_status": "DRAFT", "attached": False, "reason": "manual_template_unfilled"}
    require(isinstance(record["verified_at"], str))
    time_basis = record.get("time_basis", "test_time")
    require(time_basis in ("test_time", "artifact_review"))
    try:
        verified = datetime.fromisoformat(record["verified_at"])
    except ValueError:
        raise ManualEvidenceError("manual_input_invalid") from None
    require(verified.utcoffset() is not None and verified <= datetime.now(timezone.utc))
    tests = record["tests"]
    for test in tests:
        validate_test(test, check_id, len(record["sources"]))
    if check_id == "FW-04":
        inspection = record.get("inspection")
        keys(inspection, ("rule_count", "default_deny_seen", "anti_lockout_seen", "lan_default_allow_seen",
                          "lab_block_before_default_allow", "lab_block_enabled"))
        require(type(inspection["rule_count"]) is int and 0 <= inspection["rule_count"] <= 10000)
        require(all(type(value) is bool for key, value in inspection.items() if key != "rule_count"))
    else:
        require("inspection" not in record)
    checks = [source_integrity(source, base) for source in record["sources"]]
    reason = next((result for result in checks if result != "MATCH"), None)
    if not checks:
        reason = "manual_sources_missing"
    if check_id in {"FW-02", "FW-03", "FW-06"} and not tests:
        reason = reason or "manual_tests_missing"
    if check_id == "FW-06" and reported == "PASS" and not any(test["scenario"] == "restored" for test in tests):
        reason = reason or "manual_restore_test_missing"
    if reported == "PASS" and not pass_claim_consistent(check_id, tests):
        reason = reason or "manual_pass_claim_inconsistent"
    result = {
        "reported_status": reported, "status": "NEEDS_REVIEW" if reason else reported,
        "scope": SCOPES[check_id], "verified_at": verified.isoformat(),
        "time_basis": time_basis,
        "validation_status": "INCOMPLETE" if reason else "VALID", "attached": bool(checks) and all(v == "MATCH" for v in checks),
        "reason": reason or "operator_attestation_with_matching_artifacts",
        "content_verified_by_agent": False, "current_execution_evidence": False,
        "sources": [{"reference": f"manual:{check_id}:source-{index + 1}", "kind": source["kind"],
                     "integrity": integrity} for index, (source, integrity) in enumerate(zip(record["sources"], checks))],
        "tests": tests,
    }
    if check_id == "FW-04":
        result["inspection"] = record["inspection"]
    return result


def load_manual_evidence(path):
    if path is None:
        return {"status": "NOT_SUPPLIED", "reason": "manual_evidence_not_supplied", "checks": {}}
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        require(len(raw) <= MAX_JSON_BYTES)
        payload = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
        keys(payload, ("schema_version", "asset_id", "checks"))
        require(type(payload["schema_version"]) is int and payload["schema_version"] == 1
                and payload["asset_id"] == "SJ-D4-OPNsense")
        require(isinstance(payload["checks"], list) and len(payload["checks"]) <= 6)
        base, checks = Path(path).resolve().parent, {}
        for record in payload["checks"]:
            result = validate_record(record, base)
            require(record["check_id"] not in checks)
            checks[record["check_id"]] = result
        return {"status": "LOADED", "reason": "manual_input_loaded", "checks": checks}
    except OSError:
        code = "manual_file_unreadable"
    except (ValueError, TypeError, KeyError, RecursionError, ManualEvidenceError):
        code = "manual_input_invalid"
    return {"status": "ERROR", "reason": code, "checks": {}}


def attach_manual_results(results, bundle):
    """Never mutate automatic status, evidence, API metadata or execution ID."""
    for row in results:
        row["automatic_status"] = row["status"]
        manual = bundle["checks"].get(row["check_id"])
        if manual is None:
            manual = {"status": "ERROR" if bundle["status"] == "ERROR" else "NOT_TESTED",
                      "attached": False, "reason": bundle["reason"] if bundle["status"] == "ERROR"
                      else "manual_check_not_supplied"}
        row["manual_verification"] = manual
        if manual.get("validation_status") == "VALID" and {row["status"], manual["status"]} == {"PASS", "FAIL"}:
            row["comparison"] = "STATUS_CONFLICT_REQUIRES_REVIEW"
        elif manual.get("validation_status") == "VALID":
            row["comparison"] = "SEPARATE_SCOPE_AND_TIME; automatic_status_preserved"
        else:
            row["comparison"] = "MANUAL_EVIDENCE_UNVERIFIED"


def manual_failure(results, bundle):
    return bundle["status"] == "ERROR" or any(
        row["manual_verification"].get("validation_status") == "INCOMPLETE"
        or row["manual_verification"]["status"] == "FAIL"
        or row["comparison"] == "STATUS_CONFLICT_REQUIRES_REVIEW" for row in results
    )
