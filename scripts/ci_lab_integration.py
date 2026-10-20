"""Live-only CI integration: actual Docker TCP services, scanner, MySQL and PDF.

Run against disposable loopback containers only; never run on production assets.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import requests
from pathlib import Path
from time import sleep

from db.db_client import get_connection
from db.query_helpers import get_all_ports
from scanner.scope import ScopePolicy
from scripts.run_scan import main as run_scan_main
from scripts.generate_integrated_lab_report import generate_integrated_report
from verification.lab_runner import execute
from scripts.run_lab_special import run_special


SCOPE = ScopePolicy.load("config/scope.example.json")


def checked_scan(ports):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = run_scan_main(["scan", "-sT", "-sV", "--target", "127.0.0.1",
                               "--ports", ",".join(map(str, ports)), "--scope-file",
                               "config/scope.example.json", "--max-workers", "4",
                               "--timeout", "3"])
    if status != 0:
        raise RuntimeError("Real scan failed")
    match = re.search(r"DB save completed \(scan_id=(\d+)\)", output.getvalue())
    if not match:
        raise RuntimeError("Real scan DB id missing")
    scan_id = int(match[1])
    rows = get_all_ports(scan_id=scan_id)
    mapped = {row["port"]: row for row in rows}
    for port in ports:
        if port not in mapped:
            raise AssertionError("Expected open TCP port absent: " + str(port))
    return scan_id, mapped


def status_map(results):
    return {row["port"]: (row["check_name"], row["execution_status"], row["finding_status"])
            for row in results}


def check_running_ssh_password_policy(service: str, expected: str) -> bool:
    # Read the effective command line of the running *lab container's* sshd.
    # No change to operating-system SSH or credentials is made.
    cmd = subprocess.run(
        ["docker", "compose", "-f", "lab/compose.yml", "exec", "-T", service,
         "sh", "-c", "tr '\\000' ' ' </proc/1/cmdline"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout
    if "/usr/sbin/sshd" not in cmd:
        raise AssertionError("Lab SSH process not identified")
    observed = re.findall(r"PasswordAuthentication=(yes|no)", cmd)
    if observed != [expected]:
        raise AssertionError("Lab SSH runtime auth policy differs from expected")
    return expected == "yes"


def verify_header_remediation(port, scan_id):
    # Re-create ONLY disposable lab http-weak with good security headers.
    # No host SSH, EC2, IAM or user database changes occur.
    command = ["docker", "compose", "-f", "lab/compose.yml",
               "-f", "lab/compose.retest.yml", "--profile", "vulnerable",
               "up", "-d", "--no-deps", "--force-recreate", "http-weak"]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=90)
    from scanner.targets import ResolvedTarget
    from verification.checker_http import HTTPChecker
    from db.lab_repository import insert_observation, make_observation
    SCOPE.authorize([ResolvedTarget("127.0.0.1", "127.0.0.1", "IP")],
                    worker_count=1, port_count=1)
    result = None
    for _ in range(30):
        result = HTTPChecker(timeout=2).run_check(port, {})
        if result.get("details", {}).get("finding_status") == "NOT_DETECTED":
            break
        sleep(1)
    if result.get("details", {}).get("finding_status") != "NOT_DETECTED":
        raise AssertionError("HTTP remediation did not remove missing header finding")
    observation = make_observation(
        port=port, environment="EC2_LAB", check_name="HTTP_SECURITY_HEADERS",
        result=result, scope=SCOPE,
    )
    insert_observation(observation)
    return {"port":port["port"], "before":"POTENTIAL", "after":"NOT_DETECTED"}


def check_historical_preservation(conn):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT COUNT(*) AS c FROM scans WHERE scan_uid='pre-v7-fixture'")
        if cursor.fetchone()["c"] != 1:
            raise AssertionError("Existing V6 scan was lost in migration")


def main():
    conn = get_connection()
    try:
        check_historical_preservation(conn)
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_schema='port_scan' AND table_name='lab_verification_results'")
            assert cursor.fetchone()["c"] == 1
    finally:
        conn.close()

    assert check_running_ssh_password_policy("ssh-safe", "no") is False
    assert check_running_ssh_password_policy("ssh-weak", "yes") is True

    local_id, normal = checked_scan([2121, 2222, 8081])
    actual_local = execute(policy=SCOPE, environment="LOCAL_BASELINE", scan_id=local_id,
                           allow_ftp_anonymous=True, ssh_policy={"127.0.0.1:2222":{
                               "pubkeyauthentication": True, "passwordauthentication": False}})
    baseline = status_map(actual_local)
    assert baseline.get(2121) == ("FTP_ANONYMOUS", "SUCCESS", "NOT_DETECTED"), (baseline, {p: {"service": row.get("service"), "banner": str(row.get("banner"))[:120]} for p,row in normal.items()})
    assert baseline[2222] == ("SSH_AUTH_POLICY", "SUCCESS", "NOT_DETECTED"), baseline
    assert baseline[8081] == ("HTTP_SECURITY_HEADERS", "SUCCESS", "NOT_DETECTED"), baseline

    ec2_id, weak = checked_scan([2122, 2223, 8082, 4280])
    actual_weak = execute(policy=SCOPE, environment="EC2_LAB", scan_id=ec2_id,
                          allow_ftp_anonymous=True, ssh_policy={"127.0.0.1:2223":{
                              "pubkeyauthentication": True, "passwordauthentication": True}})
    vulnerabilities = status_map(actual_weak)
    assert vulnerabilities[2122] == ("FTP_ANONYMOUS", "SUCCESS", "CONFIRMED"), vulnerabilities
    assert vulnerabilities[2223] == ("SSH_AUTH_POLICY", "SUCCESS", "POTENTIAL"), vulnerabilities
    assert vulnerabilities[8082] == ("HTTP_SECURITY_HEADERS", "SUCCESS", "POTENTIAL"), vulnerabilities

    # Optional external binary: smoke-test actual Nuclei executable + safe local template.
    if os.environ.get("CI_NUCLEI_BINARY"):
        path = Path("lab/nuclei/missing-nosniff.yaml")
        outcome = run_special(
            scope=SCOPE, scan_id=ec2_id, port_id=weak[8082]["port_id"],
            environment="EC2_LAB", check="NUCLEI", nuclei_binary=os.environ["CI_NUCLEI_BINARY"],
            template_root="lab/nuclei", template_name=path.name,
            reviewed_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), timeout=35)
        if outcome["execution_status"] != "SUCCESS":
            conn = get_connection()
            try:
                with conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT evidence_json FROM lab_verification_results WHERE id = %s",
                                   (outcome["observation_id"],))
                    saved = cursor.fetchone()
                    document = saved["evidence_json"]
                    if isinstance(document, str): document = json.loads(document)
                    raise AssertionError("Nuclei failed: " + str({
                        "error_type": document.get("reason"),
                        "details_reason": document.get("details", {}).get("reason"),
                        "error_code": document.get("error_code")}))
            finally:
                conn.close()
        assert outcome["finding_status"] == "POTENTIAL", outcome

    # DVWA must have a freshly initialized isolated database before this step.
    if os.environ.get("CI_DVWA_USERNAME") and os.environ.get("CI_DVWA_PASSWORD"):
        outcome = run_special(
            scope=SCOPE, scan_id=ec2_id, port_id=weak[4280]["port_id"],
            environment="EC2_LAB", check="DVWA_SQLI",
            username=os.environ["CI_DVWA_USERNAME"],
            password=os.environ["CI_DVWA_PASSWORD"], timeout=10)
        if outcome["execution_status"] != "SUCCESS":
            conn = get_connection()
            try:
                with conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT evidence_json FROM lab_verification_results WHERE id = %s",
                                   (outcome["observation_id"],))
                    saved = cursor.fetchone()
                    document = saved["evidence_json"]
                    if isinstance(document, str): document = json.loads(document)
                    raise AssertionError("DVWA lab execution failed: " + str({
                        "error_code": document.get("error_code"),
                        "reason": document.get("reason"),
                        "details": {k: v for k, v in document.get("details", {}).items()
                                    if k in {"finding_status", "steps", "request_labels"}}}))
            finally:
                conn.close()
        if outcome["finding_status"] != "CONFIRMED":
            conn = get_connection()
            try:
                with conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT evidence_json FROM lab_verification_results WHERE id = %s",
                                   (outcome["observation_id"],))
                    evidence = cursor.fetchone()["evidence_json"]
                    if isinstance(evidence, str):
                        evidence = json.loads(evidence)
                    raise AssertionError("DVWA result not established: " + str({
                        "finding_status": evidence.get("finding_status"),
                        "steps": evidence.get("details", {}).get("steps", [])}))
            finally:
                conn.close()

    remediation = verify_header_remediation(weak[8082], ec2_id)
    assert remediation == {"port": 8082, "before": "POTENTIAL", "after": "NOT_DETECTED"}

    output = generate_integrated_report(local_scan_id=local_id, ec2_scan_id=ec2_id,
                                        output_dir="reports/ci", format="both")
    summary = json.loads(Path(output["json_path"]).read_text(encoding="utf-8"))
    assert summary["selection"]["local_scan_id"] == local_id
    assert summary["lab_comparison"]["scan_ids"]["EC2_LAB"] == ec2_id
    changed = summary["lab_comparison"]["environments"]["EC2_LAB"]["by_check"]["HTTP_SECURITY_HEADERS"]
    statuses = [row["finding_status"] for row in changed if row["evidence"]["port"] == 8082]
    assert statuses == ["POTENTIAL", "NOT_DETECTED"], statuses
    assert Path(output["pdf_path"]).read_bytes()[:5] == b"%PDF-"
    for key, group in summary["lab_comparison"]["environments"].items():
        assert group["coverage"]["FTP_ANONYMOUS"] == "OBSERVED"
        for observation in group["observations"]:
            assert observation["evidence_integrity"] == "MATCH", key

    # Invalid FK must be rejected; read-only evidence history must survive.
    conn = get_connection()
    try:
        from mysql.connector import IntegrityError
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM lab_verification_results")
            original_count = cursor.fetchone()[0]
            try:
                cursor.execute("""INSERT INTO lab_verification_results
                    (observation_uid,port_id,asset_uid,environment_label,check_name,
                    execution_status,finding_status,scope_uid,scope_sha256,evidence_sha256,evidence_json,observed_at)
                    VALUES (UUID(),999999999,'00000000-0000-0000-0000-000000000000',
                    'LOCAL_BASELINE','FTP_ANONYMOUS','ERROR','INCONCLUSIVE','scope',
                    REPEAT('0',64),REPEAT('0',64),'{}',UTC_TIMESTAMP())""")
            except IntegrityError:
                conn.rollback()
            else:
                conn.rollback()
                raise AssertionError("FK constraint did not reject invalid observation")
            cursor.execute("SELECT COUNT(*) FROM lab_verification_results")
            assert cursor.fetchone()[0] == original_count
    finally:
        conn.close()
    print(json.dumps({"live":True,"local_scan_id":local_id,"ec2_lab_simulated_scan_id":ec2_id,
                      "local":baseline,"vulnerable":vulnerabilities,
                      "pdf_created":True,"mysql_v7":True}, ensure_ascii=False))


if __name__ == "__main__":
    main()
