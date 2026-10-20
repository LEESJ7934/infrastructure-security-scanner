"""Explicit, preauthorized standalone lab checks attached to existing scan rows."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from db.query_helpers import get_all_ports
from db.lab_repository import make_observation, insert_observation
from scanner.scope import ScopePolicy
from scanner.targets import ResolvedTarget
from verification.dvwa_sqli_lab import verify_dvwa_sqli
from verification.reviewed_nuclei import execute_reviewed


def run_special(*, scope: ScopePolicy, scan_id: int, port_id: int, environment: str,
                check: str, dry_run=False, username=None, password=None,
                nuclei_binary=None, template_root=None, template_name=None,
                reviewed_sha256=None, timeout=10):
    if scan_id < 1 or port_id < 1 or environment not in {"LOCAL_BASELINE", "EC2_LAB"}:
        raise ValueError("Invalid selection")
    if check not in {"DVWA_SQLI", "NUCLEI"}:
        raise ValueError("Unsupported check")
    ports = [p for p in get_all_ports(scan_id=scan_id)
             if p["port_id"] == port_id and str(p.get("service")).lower() in {"http", "https"}]
    if len(ports) != 1:
        raise ValueError("Selected HTTP port not present in current stored scan")
    port = ports[0]
    scope.authorize([ResolvedTarget(port["host_ip"], port["host_ip"], "IP")],
                    worker_count=1, port_count=1)
    if dry_run:
        return {"action": "DRY_RUN", "scan_id": scan_id, "port_id": port_id, "check": check}
    # Revalidate immediately before performing the check.
    scope.authorize([ResolvedTarget(port["host_ip"], port["host_ip"], "IP")],
                    worker_count=1, port_count=1)
    host = port["host_ip"]
    uri_host = f"[{host}]" if ":" in host else host
    scheme = "https" if port.get("service") == "https" else "http"
    origin = f"{scheme}://{uri_host}:{port['port']}"
    if check == "DVWA_SQLI":
        result = verify_dvwa_sqli(origin=origin, approved_ip=host,
                                  username=username or "", password=password or "",
                                  timeout=timeout)
    else:
        if not nuclei_binary or not template_root or not template_name or not reviewed_sha256:
            raise ValueError("Nuclei binary, reviewed template and SHA-256 required")
        # Exact target/Scope binding; no arbitrary URL/path may be supplied.
        try:
            nuclei = execute_reviewed(
                nuclei_binary=nuclei_binary, template_root=template_root,
                template_allowlist={template_name: reviewed_sha256},
                template_name=template_name, origin=origin, approved_ips={host},
                timeout=timeout)
        except (OSError, ValueError, RuntimeError) as exc:
            nuclei = {"execution_status": "ERROR", "finding_status": "INCONCLUSIVE",
                      "reason": type(exc).__name__, "results": []}
        result = {
            "status": "ERROR" if nuclei["execution_status"] == "ERROR" else "POTENTIAL",
            "checker": "ReviewedNucleiRunner", "reason": nuclei["reason"],
            "details": {**nuclei, "safe_checks": ["reviewed_template_only"]}}
    observation = make_observation(port=port, environment=environment,
                                   check_name=check, result=result, scope=scope)
    record_id = insert_observation(observation)
    return {"action": "RECORDED", "observation_id": record_id,
            "execution_status": observation["execution_status"],
            "finding_status": observation["finding_status"],
            "evidence_sha256": observation["evidence_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-id", required=True, type=int)
    parser.add_argument("--port-id", required=True, type=int)
    parser.add_argument("--scope-file", required=True, type=Path)
    parser.add_argument("--environment", required=True, choices=("LOCAL_BASELINE", "EC2_LAB"))
    parser.add_argument("--check", required=True, choices=("DVWA_SQLI","NUCLEI"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--nuclei-binary")
    parser.add_argument("--template-root")
    parser.add_argument("--template-name")
    parser.add_argument("--template-sha256")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args(argv)
    try:
        outcome = run_special(
            scope=ScopePolicy.load(args.scope_file), scan_id=args.scan_id,
            port_id=args.port_id, environment=args.environment, check=args.check,
            dry_run=args.dry_run, username=os.getenv("DVWA_USERNAME"),
            password=os.getenv("DVWA_PASSWORD"), nuclei_binary=args.nuclei_binary,
            template_root=args.template_root, template_name=args.template_name,
            reviewed_sha256=args.template_sha256, timeout=args.timeout)
        print(json.dumps(outcome, ensure_ascii=False))
        return 1 if outcome.get("execution_status") == "ERROR" else 0
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
