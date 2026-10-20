"""Import a *user-collected* non-destructive DVWA evidence file to V7 history.

Does not contact EC2, create a port scan, modify an existing result or claim
cryptographic attestation of EC2 origin. Only approved existing scan/port rows.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from db.query_helpers import get_all_ports
from db.lab_repository import make_observation, insert_observation
from scanner.scope import ScopePolicy
from scanner.targets import ResolvedTarget

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def parse_dvwa_evidence(path: str | Path) -> tuple[dict, str, datetime]:
    source = Path(path)
    if source.stat().st_size > 16384:
        raise ValueError("DVWA evidence file exceeds 16 KiB; do not import raw responses")
    raw = source.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Evidence must be valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or set(data) != {
        "tested_at", "check", "method", "baseline", "injection",
        "finding_status", "cve_confirmed"
    }:
        raise ValueError("Unexpected evidence fields; raw credentials/HTML not accepted")
    if data["check"] != "DVWA_SQLI" or data["method"] != "Read-only row comparison":
        raise ValueError("Only the established read-only DVWA procedure is allowed")
    if data["cve_confirmed"] is not False:
        raise ValueError("DVWA SQL injection evidence must not assert a CVE")
    if data["finding_status"] != "CONFIRMED":
        raise ValueError("Only a confirmed proof may be imported as CONFIRMED")
    for key in ("baseline", "injection"):
        row = data[key]
        if not isinstance(row, dict) or set(row) != {
            "http_status", "result_rows", "response_sha256"
        }:
            raise ValueError("Unexpected HTTP observation structure")
        if type(row["http_status"]) is not int or row["http_status"] != 200:
            raise ValueError("HTTP status must be exactly 200")
        if type(row["result_rows"]) is not int or not 0 <= row["result_rows"] <= 1000:
            raise ValueError("Invalid result row count")
        if not isinstance(row["response_sha256"], str) or not SHA256.fullmatch(
            row["response_sha256"]
        ):
            raise ValueError("Invalid evidence response hash")
    if not (data["baseline"]["result_rows"] == 1
            and data["injection"]["result_rows"] > 1):
        raise ValueError("Evidence does not establish row expansion")
    try:
        timestamp = datetime.fromisoformat(data["tested_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid observation timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("Observation timestamp must have an explicit timezone")
    return data, hashlib.sha256(raw).hexdigest(), timestamp.astimezone(timezone.utc).replace(tzinfo=None)


def import_evidence(*, evidence_path, scope: ScopePolicy, scan_id: int,
                    port_id: int, dry_run=True):
    if scan_id < 1 or port_id < 1:
        raise ValueError("Positive existing scan and port IDs required")
    data, raw_file_hash, observed_at = parse_dvwa_evidence(evidence_path)
    ports = [row for row in get_all_ports(scan_id=scan_id)
             if row["port_id"] == port_id and
             str(row.get("service", "")).lower() in ("http", "https")]
    if len(ports) != 1:
        raise ValueError("No uniquely matching HTTP service in existing scan")
    port = ports[0]
    scope.authorize([ResolvedTarget(port["host_ip"], port["host_ip"], "IP")],
                    worker_count=1, port_count=1)
    # This verification only checks that the file matches the documented lab
    # procedure. The hash is NOT a signed remote EC2 attestation.
    result = {
        "status": "POTENTIAL",
        "checker": "OperatorCollectedDVWAImport",
        "reason": "Operator-supplied read-only SQL row expansion; independent EC2 provenance unverified",
        "details": {
            "finding_status": "CONFIRMED",
            "safe_checks": ["dvwa_seeded_select_only"],
            "evidence_origin": "operator_supplied_ec2_local_file",
            "source_file_sha256": raw_file_hash,
            "baseline": data["baseline"],
            "injection": data["injection"],
            "remote_attestation": False,
            "cve_confirmed": False,
        },
        "additional_checks": ["Review operator session logs and original evidence provenance"],
    }
    observation = make_observation(
        port=port, environment="EC2_LAB",
        check_name="DVWA_SQLI", result=result, scope=scope,
        observed_at=observed_at,
    )
    if dry_run:
        return {"status": "DRY_RUN", "scan_id": scan_id, "port_id": port_id,
                "finding_status": observation["finding_status"],
                "execution_status": observation["execution_status"],
                "source_file_sha256": raw_file_hash,
                "evidence_sha256": observation["evidence_sha256"],
                "writes_performed": False}
    record_id = insert_observation(observation)
    return {"status": "RECORDED", "observation_id": record_id,
            "scan_id": scan_id, "port_id": port_id,
            "finding_status": observation["finding_status"],
            "execution_status": observation["execution_status"],
            "source_file_sha256": raw_file_hash,
            "evidence_sha256": observation["evidence_sha256"],
            "remote_attestation": False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence-file", type=Path, required=True)
    p.add_argument("--scope-file", type=Path, required=True)
    p.add_argument("--scan-id", type=int, required=True)
    p.add_argument("--port-id", type=int, required=True)
    p.add_argument("--commit", action="store_true", help="Explicitly insert new append-only V7 row")
    a = p.parse_args(argv)
    try:
        scope = ScopePolicy.load(a.scope_file)
        result = import_evidence(evidence_path=a.evidence_file, scope=scope,
                                 scan_id=a.scan_id, port_id=a.port_id,
                                 dry_run=not a.commit)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "NOT_RECORDED", "error": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
