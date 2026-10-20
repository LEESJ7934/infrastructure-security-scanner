"""Import bounded operator-collected EC2 configuration evidence; default read-only.

No EC2 access, scan creation, CVE mutation or migration. Loopback EC2 origin
requires operator confirmation; hashes do not authenticate the remote machine.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

from db.lab_repository import insert_observation, make_observation
from db.query_helpers import get_all_ports
from scanner.scope import ScopePolicy
from scanner.targets import ResolvedTarget
from scripts.collect_ec2_config_evidence import HEADER_NAMES

CHECK_PORTS = {"FTP_ANONYMOUS": (21, "ftp"), "HTTP_SECURITY_HEADERS": (80, "http"),
               "SSH_AUTH_POLICY": (22, "ssh")}


def parse_evidence(path, expected_sha256):
    if Path(path).stat().st_size > 16384:
        raise ValueError("Evidence exceeds 16 KiB")
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > 16384 or digest != expected_sha256.lower():
        raise ValueError("Evidence size or source SHA-256 mismatch")
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "environment", "check", "tested_at", "target", "execution_status", "details"
    }:
        raise ValueError("Unexpected evidence fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["environment"] != "EC2_LAB":
        raise ValueError("Unsupported evidence schema/environment")
    check = data["check"]
    if not isinstance(check, str) or check not in CHECK_PORTS:
        raise ValueError("Unsupported check")
    number, _ = CHECK_PORTS[check]
    if data["target"] != {"host": "127.0.0.1", "port": number} or type(data["target"]["port"]) is not int:
        raise ValueError("Evidence endpoint mismatch")
    when = datetime.fromisoformat(data["tested_at"].replace("Z", "+00:00"))
    if when.tzinfo is None or when > datetime.now(timezone.utc):
        raise ValueError("Explicit timezone and nonfuture observation required")
    details = data["details"]
    if not isinstance(details, dict):
        raise ValueError("Details must be an object")
    execution = data["execution_status"]
    missing = []
    if execution == "ERROR":
        if set(details) != {"error_type"} or details["error_type"] not in {
            "OSError", "TimeoutError", "ConnectionRefusedError", "error_perm", "error_temp",
            "error_proto", "error_reply", "ValueError", "KeyError", "FileNotFoundError",
            "CalledProcessError", "TimeoutExpired", "RemoteDisconnected", "BadStatusLine"}:
            raise ValueError("Unexpected error details")
        finding = "INCONCLUSIVE"
    elif execution != "SUCCESS":
        raise ValueError("Unsupported execution status")
    elif check == "FTP_ANONYMOUS":
        if set(details) != {"reply_code"} or type(details["reply_code"]) is not int or details["reply_code"] not in {230, 530}:
            raise ValueError("FTP login result must be 230 or 530")
        finding = "CONFIRMED" if details["reply_code"] == 230 else "NOT_DETECTED"
    elif check == "HTTP_SECURITY_HEADERS":
        flags = ("nosniff", "referrer_policy_present", "csp_present", "frame_protection_present")
        if set(details) != {"http_status", *flags} or type(details["http_status"]) is not int or not 100 <= details["http_status"] <= 599 or any(type(details[k]) is not bool for k in flags):
            raise ValueError("Invalid HTTP header evidence")
        missing = [name for name, flag in zip(HEADER_NAMES, flags) if not details[flag]]
        finding = "POTENTIAL" if missing else "NOT_DETECTED"
    else:
        if set(details) != {"pubkeyauthentication", "passwordauthentication", "policy_source"} or details["policy_source"] != "sshd_T_default_config" or any(type(details[k]) is not bool for k in ("pubkeyauthentication", "passwordauthentication")):
            raise ValueError("Invalid SSH policy evidence")
        finding = "POTENTIAL" if details["passwordauthentication"] else "NOT_DETECTED"
    return data, digest, when, finding, missing


def import_evidence(*, evidence_path, expected_sha256, scope, scan_id, port_id,
                    expected_host, dry_run=True):
    if type(scan_id) is not int or type(port_id) is not int or min(scan_id, port_id) < 1:
        raise ValueError("Positive existing scan/port IDs required")
    expected_host = str(ipaddress.ip_address(expected_host))
    data, digest, when, finding, missing = parse_evidence(evidence_path, expected_sha256)
    number, service = CHECK_PORTS[data["check"]]
    ports = [p for p in get_all_ports(scan_id=scan_id) if p["port_id"] == port_id
             and p["scan_id"] == scan_id and p["host_ip"] == expected_host
             and int(p["port"]) == number and p["service"].lower() == service]
    if len(ports) != 1:
        raise ValueError("Exact existing scan/port/host/service match required")
    target = [ResolvedTarget(expected_host, expected_host, "IP")]
    scope.authorize(target, worker_count=1, port_count=1)
    scope.authorize(target, worker_count=1, port_count=1, now=when)
    details = {**data["details"], "finding_status": finding,
               "source_file_sha256": digest, "tested_at": when.isoformat(),
               "source_target": data["target"], "missing_headers": missing,
               "evidence_origin": "operator_supplied_ec2_local_file", "remote_attestation": False,
               "endpoint_mapping": "operator_confirmed_ec2_loopback_to_existing_scan",
               "cve_confirmed": False, "authorized_scope": scope.to_snapshot()}
    observation = make_observation(port=ports[0], environment="EC2_LAB", check_name=data["check"],
        result={"status": "ERROR" if data["execution_status"] == "ERROR" else "POTENTIAL",
                "checker": "OperatorCollectedEC2ConfigImport", "details": details,
                "reason": "Operator-collected loopback result; SSH default policy excludes Match context and daemon overrides"},
        scope=scope, observed_at=when.astimezone(timezone.utc).replace(tzinfo=None))
    record_id = None if dry_run else insert_observation(observation, deduplicate=True)
    return {"status": "DRY_RUN" if dry_run else "RECORDED_OR_EXISTING", "observation_id": record_id,
            "scan_id": scan_id, "port_id": port_id, "check": data["check"],
            "execution_status": observation["execution_status"], "finding_status": finding,
            "source_file_sha256": digest, "evidence_sha256": observation["evidence_sha256"],
            "writes_performed": not dry_run, "remote_attestation": False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence-file", type=Path, required=True)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--scope-file", type=Path, required=True)
    p.add_argument("--scan-id", type=int, required=True)
    p.add_argument("--port-id", type=int, required=True)
    p.add_argument("--expected-host", required=True, help="DB host independently matched to the owned EC2; may be a tunnel address")
    p.add_argument("--commit", action="store_true")
    a = p.parse_args(argv)
    try:
        result = import_evidence(evidence_path=a.evidence_file, expected_sha256=a.source_sha256,
            scope=ScopePolicy.load(a.scope_file), scan_id=a.scan_id, port_id=a.port_id,
            expected_host=a.expected_host, dry_run=not a.commit)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "NOT_RECORDED", "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
