"""Authorize CVE verification and persist each result in one V4 transaction."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone

from analysis.vuln_mapper import RETIRED_RULE_IDS
from db.db_client import get_connection
from db.query_helpers import (get_ports_with_vuln_candidates, insert_vuln_evidence,
                              update_vuln_verification)
from db.statuses import validate_vuln_transition
from db.scan_history import link_finding
from scanner.scope import ScopePolicy, ScopeValidationError
from scanner.targets import ResolvedTarget, normalize_hostname, resolve_target_specs
from verification.base_checker import RESULT_EVIDENCE_TYPES, RESULT_STATUSES, check_result
from verification.cve_verifiers import get_verifier


ELIGIBLE_STATUSES = frozenset({"CANDIDATE", "POTENTIAL", "RETEST_REQUIRED", "ERROR"})


class VerificationConflictError(RuntimeError):
    """The target or review state changed while a probe was in progress."""


class VerificationDatabaseError(RuntimeError):
    """Evidence/status/history could not be committed together."""


def _resolved_target(port_record: dict) -> ResolvedTarget:
    ip = str(ipaddress.ip_address(port_record["host_ip"]))
    if port_record.get("resolution_type") == "HOSTNAME":
        return ResolvedTarget(ip, normalize_hostname(port_record["input_target"]), "HOSTNAME")
    return ResolvedTarget(ip, ip, "IP")


def authorize_selection(targets: list[tuple[dict, dict]], policy: ScopePolicy) -> None:
    """Validate the entire selection before even the first verification probe."""
    policy.validate_time()
    if not targets:
        return
    endpoints = {}
    resolved = []
    for port_record, _ in targets:
        target = _resolved_target(port_record)
        port = port_record["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ScopeValidationError("Invalid verification port")
        endpoints.setdefault(target.ip, set()).add((port_record["protocol"], port))
        if target not in resolved:
            resolved.append(target)
    policy.authorize(resolved, worker_count=1, port_count=max(map(len, endpoints.values())))


def _check_current_hostname(target: ResolvedTarget, policy: ScopePolicy) -> None:
    """Only real execution resolves approved hostnames; dry-run does no DNS."""
    if target.resolution_type != "HOSTNAME":
        return
    current = resolve_target_specs([target.input_target], max_targets=policy.max_targets)
    policy.authorize(current, worker_count=1, port_count=1)
    if target.ip not in {entry.ip for entry in current}:
        raise ScopeValidationError("The approved hostname no longer resolves to the stored target IP")


def run_checker(checker, port_record: dict, vuln_candidate: dict) -> dict:
    """Validate a checker result instead of mapping ambiguous legacy values to safe."""
    try:
        result = checker.run_check(port_record, vuln_candidate)
        if not isinstance(result, dict) or result.get("status") not in RESULT_STATUSES:
            raise ValueError("Invalid verifier status")
        if (not isinstance(result.get("reason"), str) or not result["reason"]
                or result.get("evidence_type") not in RESULT_EVIDENCE_TYPES
                or not isinstance(result.get("details"), dict)
                or not isinstance(result.get("additional_checks", []), list)):
            raise ValueError("Invalid verifier result contract")
        if result["status"] == "CONFIRMED":
            proof = result.get("positive_evidence")
            if (not isinstance(proof, dict) or not proof.get("summary")
                    or proof.get("kind") in {None, "banner", "version", "http_status"}):
                raise ValueError("CONFIRMED requires positive CVE-specific evidence")
        json.dumps(result, allow_nan=False)
        return {**result, "checker": type(checker).__name__}
    except TimeoutError:
        code = "TIMEOUT"
    except OSError:
        code = "CONNECTION_ERROR"
    except Exception:
        code = "VERIFIER_ERROR"
    return check_result("ERROR", "Verification failed; no non-vulnerable conclusion is available.",
                        checker=type(checker).__name__, evidence_type="ERROR_LOG", error_code=code,
                        details={"safe_checks": [], "failure_stage": "verifier_execution"})


def resulting_status(current: str, result_status: str) -> str:
    if current not in ELIGIBLE_STATUSES:
        raise VerificationConflictError("The vulnerability is already in a reviewed state")
    new_status = result_status
    if current == "RETEST_REQUIRED" and result_status == "POTENTIAL":
        new_status = "RETEST_REQUIRED"
    elif current in {"CANDIDATE", "ERROR"} and result_status == "CONFIRMED":
        # First establish POTENTIAL. Confirmation is a separate subsequent stage.
        new_status = "POTENTIAL"
    validate_vuln_transition(current, new_status)
    return new_status


def _target_identity(port: dict, vuln: dict) -> tuple:
    return (port["id"], port["host_ip"], port["port"], port["protocol"], port.get("scan_id"),
            port.get("service"), port.get("product"), port.get("version"), port.get("banner"),
            port.get("input_target"), port.get("resolution_type"),
            vuln["id"], vuln.get("cve_id") or vuln.get("cve"), vuln.get("source"))


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def save_verification(port_record: dict, vuln_candidate: dict, result: dict,
                      policy: ScopePolicy, checked_at: str) -> dict:
    """Lock the parent first, then deduplicate evidence and change status/history."""
    vuln_id = vuln_candidate["id"]
    content = {
        "checker": result["checker"], "cve_id": vuln_candidate.get("cve_id") or vuln_candidate.get("cve"),
        "source": vuln_candidate.get("source"),
        "target": {key: port_record.get(key) for key in
                   ("id", "host_ip", "port", "protocol", "scan_id", "scan_uid", "input_target")},
        "scope": {"scope_uid": policy.scope_uid, "policy_sha256": policy.fingerprint},
        "result": result["status"], "reason": result["reason"], "error_code": result.get("error_code"),
        "evidence_type": result["evidence_type"], "details": result["details"],
        "additional_checks": result.get("additional_checks", []),
    }
    if result.get("positive_evidence"):
        content["positive_evidence"] = result["positive_evidence"]
    # Wall-clock times and repetition counters are deliberately outside the digest.
    digest = hashlib.sha256(_json(content).encode("utf-8")).hexdigest()
    connection = None
    try:
        connection = get_connection()
        locked = get_ports_with_vuln_candidates(connection, vuln_id=vuln_id, for_update=True)
        if not locked:
            raise VerificationConflictError("The record was removed or moved to a reviewed state")
        locked_port, locked_vuln = locked[0]
        if (_target_identity(locked_port, locked_vuln) != _target_identity(port_record, vuln_candidate)
                or locked_vuln.get("source") in RETIRED_RULE_IDS):
            raise VerificationConflictError("The target, scan or CVE changed during verification")
        new_status = resulting_status(locked_vuln["status"], result["status"])
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(
                "SELECT id, details FROM vuln_evidence WHERE vuln_id = %s AND checker = %s "
                "AND sha256 = %s LIMIT 1 FOR UPDATE",
                (vuln_id, result["checker"], digest),
            )
            existing = cursor.fetchone()
            if existing:
                previous = json.loads(existing["details"])
                document = {"schema_version": 1, "content": content,
                            "first_checked_at": previous["first_checked_at"], "last_checked_at": checked_at,
                            "observations": int(previous.get("observations", 1)) + 1}
                evidence_id = existing["id"]
                cursor.execute("UPDATE vuln_evidence SET details = %s WHERE id = %s", (_json(document), evidence_id))
            else:
                document = {"schema_version": 1, "content": content, "first_checked_at": checked_at,
                            "last_checked_at": checked_at, "observations": 1}
                details = _json(document)
                if len(details.encode("utf-8")) > 60000:
                    raise ValueError("Verification evidence exceeds the V4 TEXT budget")
                evidence_id = insert_vuln_evidence(connection, vuln_id, result["checker"],
                                                   result["evidence_type"], details=details, sha256=digest)
        update_vuln_verification(connection, vuln_id, new_status, reason=result["reason"][:500])
        if result['status'] == 'CONFIRMED':
            link_finding(connection, vuln_id, port_id=port_record['id'], relation='VERIFIED')
        connection.commit()
        return {"status": new_status, "evidence_id": evidence_id, "evidence_reused": bool(existing)}
    except VerificationConflictError:
        if connection is not None:
            connection.rollback()
        raise
    except Exception as exc:
        if connection is not None:
            connection.rollback()
        raise VerificationDatabaseError(f"DB_SAVE_FAILED for vuln_id={vuln_id} ({type(exc).__name__})") from exc
    finally:
        if connection is not None:
            connection.close()


def run_verifications(*, policy: ScopePolicy, vuln_id: int | None = None,
                      scan_id: int | None = None, dry_run: bool = False, timeout: float = 5.0) -> list[dict]:
    policy.validate_time()
    targets = get_ports_with_vuln_candidates(vuln_id=vuln_id, scan_id=scan_id)
    active = [(port, vuln) for port, vuln in targets
              if vuln.get("source") not in RETIRED_RULE_IDS and vuln["status"] in ELIGIBLE_STATUSES]
    authorize_selection(active, policy)
    outcomes = []
    for port_record, vuln in targets:
        cve_id = vuln.get("cve_id") or vuln.get("cve") or ""
        entry = {"vuln_id": vuln["id"], "cve_id": cve_id, "host_ip": port_record["host_ip"],
                 "port": port_record["port"], "protocol": port_record["protocol"], "current_status": vuln["status"]}
        if vuln.get("source") in RETIRED_RULE_IDS or vuln["status"] not in ELIGIBLE_STATUSES:
            outcomes.append({**entry, "action": "SKIP", "reason": "retired_rule_or_reviewed_state"})
            continue
        checker = get_verifier(cve_id, timeout=timeout)
        if dry_run:
            outcomes.append({**entry, "action": "DRY_RUN", "checker": type(checker).__name__})
            continue
        target = _resolved_target(port_record)
        # Validate time again before each probe; resolve only an already approved hostname.
        authorize_selection([(port_record, vuln)], policy)
        probe_record = dict(port_record)
        if target.resolution_type == "HOSTNAME":
            probe_record["server_name"] = target.input_target
        try:
            _check_current_hostname(target, policy)
        except ScopeValidationError:
            raise
        except (ValueError, OSError):
            result = check_result(
                "ERROR", "Approved hostname resolution failed; the stored endpoint was not contacted.",
                checker=type(checker).__name__, evidence_type="ERROR_LOG", error_code="DNS_RESOLUTION_ERROR",
                details={"safe_checks": ["approved_hostname_resolution"]},
                additional_checks=["Check DNS availability and the current approved hostname-to-IP mapping."],
            )
        else:
            result = run_checker(checker, probe_record, vuln)
        checked_at = datetime.now(timezone.utc).isoformat()
        saved = save_verification(port_record, vuln, result, policy, checked_at)
        outcomes.append({**entry, "action": "VERIFIED", "checked_at": checked_at,
                         "result": result, **saved})
    return outcomes


if __name__ == "__main__":
    # Preserve the module entry point, but require the same explicit CLI selection/scope.
    from scripts.run_verification import main
    raise SystemExit(main())
