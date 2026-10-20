"""Owner-operated SSM tunnel runner for an EXISTING approved EC2.

All targets are 127.0.0.1 forwarding endpoints; no public IP scan, no AWS write
APIs, no SSH password guessing, no EC2 provisioning, no remote changes.
Requires AWS CLI + Session Manager plugin and an existing local V7 MySQL.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

from db.query_helpers import get_all_ports
from db.lab_repository import insert_observation, make_observation
from scanner.scope import ScopePolicy
from scanner.targets import ResolvedTarget
from scripts.ec2_lab_preflight import inspect_existing_instance
from scripts.generate_integrated_lab_report import generate_integrated_report
from scripts.run_scan import main as scan_main
from scripts.run_lab_special import run_special
from verification.checker_http import HTTPChecker
from verification.lab_runner import execute

BEFORE_PORTS = (2122, 2223, 8082, 4280)
AFTER_PORTS = (8082,)


def _local_port_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


@contextmanager
def ssm_tunnels(*, instance_id: str, region: str, ports: tuple[int, ...],
                aws_cli: str = "aws", wait_seconds: int = 35):
    """Open only loopback Session Manager forwarding ports and clean up children."""
    if any(not _local_port_free(port) for port in ports):
        raise RuntimeError("At least one local forwarding port is already bound; refusing ambiguous evidence")
    processes = []
    try:
        for port in ports:
            args = [
                aws_cli, "ssm", "start-session", "--target", instance_id,
                "--region", region, "--document-name", "AWS-StartPortForwardingSession",
                "--parameters", json.dumps({"portNumber": [str(port)],
                                            "localPortNumber": [str(port)]}),
            ]
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
            processes.append(p)
        for port, process in zip(ports, processes):
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("SSM tunnel process terminated before forwarding port " + str(port))
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.75):
                        break
                except OSError:
                    time.sleep(0.4)
            else:
                raise RuntimeError("SSM loopback forwarding was not established on port " + str(port))
        yield
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            if process.stdin is not None:
                process.stdin.close()
        for process in processes:
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def _verified_scope(path: str | Path) -> ScopePolicy:
    scope = ScopePolicy.load(path)
    # Even with SSM, NEVER use broad network ranges in the local scan.
    if not scope.allowed_targets or any(x not in ("127.0.0.1", "::1", "localhost")
                                        for x in scope.allowed_targets):
        raise ValueError("SSM runner requires a loopback-only scope allowlist")
    scope.authorize([ResolvedTarget("127.0.0.1", "127.0.0.1", "IP")],
                    worker_count=1, port_count=len(BEFORE_PORTS))
    return scope


def _new_scan(scope_file: str | Path) -> int:
    output = io.StringIO()
    with redirect_stdout(output):
        status = scan_main(["scan", "-sT", "-sV", "--target", "127.0.0.1",
                            "--ports", ",".join(map(str, BEFORE_PORTS)),
                            "--scope-file", str(scope_file), "--max-workers", "4",
                            "--timeout", "3"])
    if status != 0:
        raise RuntimeError("EC2 forwarded endpoints scan failed")
    match = re.search(r"DB save completed \(scan_id=(\d+)\)", output.getvalue())
    if not match:
        raise RuntimeError("Scan ID missing from persisted scan result")
    return int(match.group(1))


def _checked_port(scan_id: int, port_number: int) -> dict:
    ports = [p for p in get_all_ports(scan_id=scan_id) if int(p["port"]) == port_number
             and p["host_ip"] == "127.0.0.1"]
    if len(ports) != 1:
        raise RuntimeError("Exact previously scanned port not found: " + str(port_number))
    return ports[0]


def _write_manifest(*, output_dir: Path, instance_id: str, region: str,
                    local_id: int, ec2_id: int, phase: str, results: list,
                    report: dict) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "instance_id": instance_id, "region": region, "phase": phase,
        "transport": "AWS Systems Manager start-session port forwarding to 127.0.0.1",
        "transport_note": "User-executed command evidence, not cryptographic proof of remote configuration",
        "baseline_scan_id": local_id, "ec2_scan_id": ec2_id,
        "tests": results, "integrated_report": report,
        "aws_resource_changes": "NONE_BY_RUNNER",
        "ec2_os_ssh_changes": "NONE_BY_RUNNER",
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    path = output_dir / f"ssm_ec2_{phase}_{ec2_id}_{digest[:12]}.json"
    path.write_text(json.dumps({"manifest_sha256": digest, **payload},
                               ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(path)


def run(*, instance_id: str, region: str, baseline_scan_id: int, scope_file: str,
        phase: str, ec2_scan_id=None, ssh_policy_file=None, nuclei_binary=None,
        output_dir="reports/ec2", aws_cli="aws") -> dict:
    if baseline_scan_id < 1 or phase not in ("before", "after"):
        raise ValueError("Valid baseline scan and phase required")
    if phase == "after" and (ec2_scan_id is None or ec2_scan_id < 1):
        raise ValueError("The existing EC2 scan ID is required for retesting")
    scope = _verified_scope(scope_file)
    if not get_all_ports(scan_id=baseline_scan_id):
        raise RuntimeError("Stored baseline scan missing; do not infer baseline safety")
    details = inspect_existing_instance(instance_id=instance_id, region=region, aws_cli=aws_cli)
    results = []
    ports = BEFORE_PORTS if phase == "before" else AFTER_PORTS
    with ssm_tunnels(instance_id=instance_id, region=region, ports=ports, aws_cli=aws_cli):
        if phase == "before":
            ec2_scan_id = _new_scan(scope_file)
            ssh_policy = {}
            if ssh_policy_file:
                ssh_policy = json.loads(Path(ssh_policy_file).read_text(encoding="utf-8"))
                if not isinstance(ssh_policy, dict):
                    raise ValueError("SSH policy must be a JSON object")
            rows = execute(policy=scope, environment="EC2_LAB",
                           scan_id=ec2_scan_id, allow_ftp_anonymous=True,
                           ssh_policy=ssh_policy, timeout=5)
            results.extend(rows)
            if not any(x["check_name"] == "FTP_ANONYMOUS" and
                       x.get("finding_status") == "CONFIRMED" for x in rows):
                raise RuntimeError("Anonymous FTP was not confirmed; no successful EC2 claim")
            if not any(x["check_name"] == "HTTP_SECURITY_HEADERS" and
                       x["port"] == 8082 and x.get("finding_status") == "POTENTIAL" for x in rows):
                raise RuntimeError("Expected lab HTTP header observation not found")
            if not nuclei_binary or not Path(nuclei_binary).is_file():
                raise ValueError("Reviewed Nuclei executable required for full EC2 verification")
            for kind, port in (("NUCLEI", 8082), ("DVWA_SQLI", 4280)):
                kw = dict(scope=scope, scan_id=ec2_scan_id,
                          port_id=_checked_port(ec2_scan_id, port)["port_id"],
                          environment="EC2_LAB", check=kind)
                if kind == "NUCLEI":
                    template = Path("lab/nuclei/missing-nosniff.yaml")
                    kw.update(nuclei_binary=nuclei_binary, template_root=str(template.parent),
                              template_name=template.name,
                              reviewed_sha256=hashlib.sha256(template.read_bytes()).hexdigest(),
                              timeout=35)
                else:
                    kw.update(username=os.environ.get("DVWA_USERNAME", ""),
                              password=os.environ.get("DVWA_PASSWORD", ""), timeout=10)
                outcome = run_special(**kw)
                results.append({"check_name": kind, **outcome})
                if outcome.get("execution_status") != "SUCCESS":
                    raise RuntimeError(kind + " real remote check was not successful")
                if kind == "DVWA_SQLI" and outcome.get("finding_status") != "CONFIRMED":
                    raise RuntimeError("DVWA SQL injection was not confirmed")
        else:
            port = _checked_port(ec2_scan_id, 8082)
            check = HTTPChecker(timeout=5).run_check(port, {})
            if check.get("details", {}).get("finding_status") != "NOT_DETECTED":
                raise RuntimeError("Improved EC2 HTTP headers were not confirmed; no retest claim")
            observation = make_observation(port=port, environment="EC2_LAB",
                                           check_name="HTTP_SECURITY_HEADERS",
                                           result=check, scope=scope)
            observation_id = insert_observation(observation)
            results.append({"check_name": "HTTP_SECURITY_HEADERS", "phase": "after",
                            "execution_status": observation["execution_status"],
                            "finding_status": observation["finding_status"],
                            "observation_id": observation_id,
                            "evidence_sha256": observation["evidence_sha256"]})
    # User-run SSM command history and independent DB rows are necessary evidence.
    report = generate_integrated_report(local_scan_id=baseline_scan_id,
                                        ec2_scan_id=ec2_scan_id,
                                        output_dir=output_dir, format="both")
    manifest = _write_manifest(output_dir=Path(output_dir), instance_id=instance_id,
                               region=region, local_id=baseline_scan_id,
                               ec2_id=ec2_scan_id, phase=phase, results=results, report=report)
    return {"phase": phase, "ec2_scan_id": ec2_scan_id,
            "ec2_ssm_status": details["ssm_status"], "results": results,
            "report": report, "attestation_manifest": manifest}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--instance-id", required=True)
    p.add_argument("--region", default="ap-northeast-2")
    p.add_argument("--baseline-scan-id", required=True, type=int)
    p.add_argument("--ec2-scan-id", type=int)
    p.add_argument("--scope-file", required=True)
    p.add_argument("--phase", choices=("before", "after"), required=True)
    p.add_argument("--nuclei-binary")
    p.add_argument("--ssh-policy-file")
    p.add_argument("--output-dir", default="reports/ec2")
    p.add_argument("--execute", action="store_true", help="Owner explicitly approves live scoped checks")
    args = p.parse_args(argv)
    if not args.execute:
        print("DRY_RUN_ONLY: use --execute after verifying SSM, Docker and local DB.")
        return 0
    try:
        outcome = run(instance_id=args.instance_id, region=args.region,
                      baseline_scan_id=args.baseline_scan_id,
                      scope_file=args.scope_file, phase=args.phase,
                      ec2_scan_id=args.ec2_scan_id, nuclei_binary=args.nuclei_binary,
                      ssh_policy_file=args.ssh_policy_file, output_dir=args.output_dir)
        print(json.dumps(outcome, ensure_ascii=False, default=str))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        # Never include AWS CLI stderr or credentials.
        print(json.dumps({"status": "NOT_VERIFIED", "error_type": type(exc).__name__,
                          "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
