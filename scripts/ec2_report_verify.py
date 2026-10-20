"""Verify owner-run EC2 before/after manifests against one integrated V7 report.

No network or AWS access. This verifies hashes and consistent recorded claims;
it does not cryptographically authenticate the remote EC2 configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


class EvidenceValidationError(ValueError):
    pass


def _load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise EvidenceValidationError("Evidence file must contain a JSON object")
    return data


def _check_manifest(path, expected_phase):
    item = _load(path)
    expected_hash = item.pop("manifest_sha256", "")
    if item.get("phase") != expected_phase or not expected_hash:
        raise EvidenceValidationError("Missing/mismatched SSM manifest phase")
    canonical = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    if digest != expected_hash:
        raise EvidenceValidationError("SSM manifest digest mismatch")
    if item.get("transport") != "AWS Systems Manager start-session port forwarding to 127.0.0.1":
        raise EvidenceValidationError("SSM transport not attested")
    return item


def _statuses(group, check, port=None):
    records = group.get("by_check", {}).get(check, [])
    if port is not None:
        records = [r for r in records if r.get("evidence", {}).get("port") == port]
    return [r.get("finding_status") for r in records
            if r.get("execution_status") == "SUCCESS"]


def verify_report(*, before_manifest, after_manifest, report_json):
    before = _check_manifest(before_manifest, "before")
    after = _check_manifest(after_manifest, "after")
    for key in ("instance_id", "region", "ec2_scan_id", "baseline_scan_id"):
        if before.get(key) != after.get(key):
            raise EvidenceValidationError("Before/after target or scan ID mismatch: " + key)
    report = _load(report_json)
    comparison = report.get("lab_comparison", {})
    scans = comparison.get("scan_ids", {})
    if (scans.get("LOCAL_BASELINE") != before["baseline_scan_id"] or
            scans.get("EC2_LAB") != before["ec2_scan_id"]):
        raise EvidenceValidationError("Report scan IDs do not match SSM manifests")
    env = comparison.get("environments", {})
    local = env.get("LOCAL_BASELINE", {})
    remote = env.get("EC2_LAB", {})
    for item in local.get("observations", []) + remote.get("observations", []):
        if item.get("evidence_integrity") != "MATCH":
            raise EvidenceValidationError("DB evidence hash mismatch")
    expected_baseline = {
        "FTP_ANONYMOUS": ("NOT_DETECTED", 2121),
        "SSH_AUTH_POLICY": ("NOT_DETECTED", 2222),
        "HTTP_SECURITY_HEADERS": ("NOT_DETECTED", 8081),
    }
    for check, (status, port) in expected_baseline.items():
        if status not in _statuses(local, check, port):
            raise EvidenceValidationError("Baseline check missing: " + check)
    expected_remote = {
        "FTP_ANONYMOUS": ("CONFIRMED", 2122),
        "SSH_AUTH_POLICY": ("POTENTIAL", 2223),
        "DVWA_SQLI": ("CONFIRMED", 4280),
        "NUCLEI": ("POTENTIAL", 8082),
    }
    for check, (status, port) in expected_remote.items():
        if status not in _statuses(remote, check, port):
            raise EvidenceValidationError("Remote check not proven: " + check)
    http = _statuses(remote, "HTTP_SECURITY_HEADERS", 8082)
    if http != ["POTENTIAL", "NOT_DETECTED"]:
        raise EvidenceValidationError("HTTP before/after result sequence not established")
    return {
        "result": "RECORDED_EVIDENCE_CONSISTENT",
        "warning": "SSM/operator evidence is not a cryptographic remote attestation",
        "instance_id": before["instance_id"], "region": before["region"],
        "baseline_scan_id": before["baseline_scan_id"],
        "ec2_scan_id": before["ec2_scan_id"],
        "ftp_ssh_http": "RECORDED", "dvwa": "RECORDED", "nuclei": "RECORDED",
        "http_retest": "POTENTIAL_TO_NOT_DETECTED",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before-manifest", required=True)
    p.add_argument("--after-manifest", required=True)
    p.add_argument("--report-json", required=True)
    args = p.parse_args(argv)
    try:
        print(json.dumps(verify_report(before_manifest=args.before_manifest,
                                       after_manifest=args.after_manifest,
                                       report_json=args.report_json), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "INCONCLUSIVE", "error": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
