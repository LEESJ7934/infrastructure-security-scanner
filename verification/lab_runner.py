"""Scope-gated configuration checks over current existing scanned ports."""
from __future__ import annotations

from db.query_helpers import get_all_ports
from db.lab_repository import insert_observation, make_observation
from scanner.scope import ScopePolicy
from scanner.targets import ResolvedTarget
from verification.checker_ftp import FTPChecker
from verification.checker_http import HTTPChecker
from verification.checker_ssh import SSHChecker


def kind_of(port):
    service = str(port.get("service") or "").lower()
    if service == "ftp":
        return "FTP_ANONYMOUS"
    if service == "ssh":
        return "SSH_AUTH_POLICY"
    if service in {"http", "https"}:
        return "HTTP_SECURITY_HEADERS"
    return None


def selected_ports(*, policy, asset_uid=None, scan_id=None, include_services=None):
    ports = get_all_ports(asset_uid=asset_uid, scan_id=scan_id)
    checks = [(p, kind_of(p)) for p in ports if kind_of(p) is not None]
    if include_services is not None:
        checks = [(p, k) for p, k in checks if k in include_services]
    if checks:
        # Authorization must happen for ALL endpoints before ANY request.
        targets = [ResolvedTarget(p["host_ip"], p["host_ip"], "IP") for p, _ in checks]
        policy.authorize(
            list({t.ip: t for t in targets}.values()),
            worker_count=1,
            port_count=max(sum(1 for p, _ in checks if p["host_ip"] == ip)
                           for ip in {p["host_ip"] for p, _ in checks}),
        )
    else:
        policy.validate_time()
    return checks


def execute(*, policy: ScopePolicy, environment: str, asset_uid=None, scan_id=None,
            allow_ftp_anonymous=False, ssh_policy=None, dry_run=False, timeout=5):
    """Explicit config-verification workflow; never alters CVE state."""
    if (asset_uid is None) == (scan_id is None):
        raise ValueError("Specify exactly one existing asset or scan")
    if environment not in {"LOCAL_BASELINE", "EC2_LAB"}:
        raise ValueError("Explicit environment label required")
    if timeout <= 0 or timeout > 30:
        raise ValueError("Timeout must be in (0,30]")
    checks = selected_ports(policy=policy, asset_uid=asset_uid, scan_id=scan_id)
    outputs = []
    for port, check_name in checks:
        endpoint = (port["host_ip"], int(port["port"]))
        entry = {"asset_uid": port["asset_uid"], "port_id": port["port_id"],
                 "host_ip": port["host_ip"], "port": port["port"],
                 "check_name": check_name, "environment": environment}
        if dry_run:
            outputs.append({**entry, "action": "DRY_RUN"})
            continue
        # Explicit re-authorization immediately before the network request.
        policy.authorize([ResolvedTarget(endpoint[0], endpoint[0], "IP")],
                         worker_count=1, port_count=1)
        if check_name == "FTP_ANONYMOUS":
            checker = FTPChecker(timeout=timeout, allow_anonymous_login=allow_ftp_anonymous,
                                 approved_endpoints=(endpoint,) if allow_ftp_anonymous else ())
        elif check_name == "HTTP_SECURITY_HEADERS":
            checker = HTTPChecker(timeout=timeout)
        else:
            attested = (ssh_policy or {}).get(f"{endpoint[0]}:{endpoint[1]}")
            checker = SSHChecker(timeout=timeout, approved_auth_policy=attested)
        result = checker.run_check(port, {})
        observation = make_observation(port=port, environment=environment, check_name=check_name,
                                       result=result, scope=policy)
        evidence_id = insert_observation(observation)
        outputs.append({**entry, "action": "RECORDED", "observation_id": evidence_id,
                        "execution_status": observation["execution_status"],
                        "finding_status": observation["finding_status"],
                        "evidence_sha256": observation["evidence_sha256"]})
    return outputs
