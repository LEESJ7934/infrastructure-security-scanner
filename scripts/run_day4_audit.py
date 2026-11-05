"""Offline preparation by default; explicit, read-only API execution on opt-in."""

import argparse
from datetime import datetime, timezone
import json
import os
from uuid import uuid4

from config_audit.engine import evaluate
from config_audit.collectors import opnsense as fw
from config_audit.models import AuditAsset, AuditRule
from config_audit.manual_evidence import attach_manual_results, load_manual_evidence, manual_failure
from config_audit.collectors import opnsense_pf
from config_audit.collectors import opnsense_log_rules

DESCRIPTIONS = (
    "LAN/WAN assignment, enabled state and IPv4 /24 match the lab",
    "WAN-origin HTTPS 443 denied with current test and firewall evidence",
    "Approved WAN ICMP allowed and sampled unauthorized TCP 22 denied",
    "Complete normalized rules enforce the five documented lab packet cases",
    "Current allow and block logs match probe tuples and available rule IDs",
    "Windows to Alpine ICMP matches the selected scenario and firewall log",
)


def rows(evidence, asset=None):
    collector = fw.OPNsenseCollector(evidence)
    asset = asset or AuditAsset("SJ-D4-OPNsense", "opnsense", "26.7")
    result = []
    for index, description in enumerate(DESCRIPTIONS, 1):
        check_id = f"FW-{index:02}"
        rule = AuditRule(check_id, "1", description, "Review Day 4 policy and current evidence.",
                         condition=lambda value: value if type(value) is bool else None,
                         product="opnsense")
        observation = collector.collect(asset, check_id)
        evaluated = evaluate(asset, rule, observation, execution_id=evidence.execution_id,
                             checked_at=evidence.checked_at)
        row = evaluated.to_safe_dict()
        row.update(evidence_reference=evaluated.evidence_reference,
                   reason=collector.reasons[check_id])
        names = {"FW-01": ("interfaces", "export"), "FW-04": ("rules",),
                 "FW-05": ("logs", "rule_ids")}.get(check_id, ())
        row["api_results"] = {name: evidence.api_results[name] for name in names if name in evidence.api_results}
        if check_id == "FW-04":
            row["scope"] = ("five_lab_packet_cases; normalized_coverage_attested" if evidence.complete_rules
                            else "five_lab_packet_cases; complete_effective_ruleset_unverified")
        if check_id == "FW-05":
            row["rule_id_mapping"] = evidence.rule_id_mapping
        result.append(row)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="OPNsense Day 4: no network access without --execute.")
    parser.add_argument("--execute", action="store_true", help="Read approved HTTPS API endpoints only.")
    parser.add_argument("--ping", action="store_true", help="Also send one Windows-to-Alpine ICMP probe.")
    parser.add_argument("--scenario", choices=("pass", "block"), default="pass")
    parser.add_argument("--manual-evidence", metavar="PATH", help="Attach local operator evidence without changing automatic verdicts.")
    parser.add_argument("--pf-rules-evidence", metavar="PATH", help="Analyze a local pfctl -sr snapshot; no commands are executed.")
    parser.add_argument("--pf-rules-detail", metavar="PATH", help="Optional pfctl -vvsr snapshot for comparison.")
    parser.add_argument("--pf-rules-sha256", metavar="SHA256", help="Independently expected hash of the -sr snapshot.")
    parser.add_argument("--pf-rules-detail-sha256", metavar="SHA256")
    parser.add_argument("--pf-rules-archive", metavar="PATH", help="Optional tar; member bytes are compared without extraction.")
    parser.add_argument("--pf-rules-archive-sha256", metavar="SHA256", help="Independently expected archive hash.")
    parser.add_argument("--fw05-log-evidence", metavar="PATH", help="Correlate a saved WAN TCP/22 log with PF snapshots.")
    parser.add_argument("--fw05-log-sha256", metavar="SHA256")
    parser.add_argument("--fw05-test-start", metavar="ISO_TIMESTAMP")
    parser.add_argument("--fw05-test-end", metavar="ISO_TIMESTAMP")
    parser.add_argument("--fw05-test-context", metavar="PATH", help="Optional trusted-collector clock/probe/generation context.")
    parser.add_argument("--fw05-test-context-sha256", metavar="SHA256")
    args = parser.parse_args(argv)
    if args.ping and not args.execute:
        parser.error("--ping requires --execute")
    if not args.pf_rules_evidence and any((args.pf_rules_detail, args.pf_rules_sha256, args.pf_rules_detail_sha256,
                                          args.pf_rules_archive, args.pf_rules_archive_sha256)):
        parser.error("PF auxiliary options require --pf-rules-evidence")
    if (args.pf_rules_detail_sha256 and not args.pf_rules_detail) or (args.pf_rules_archive_sha256 and not args.pf_rules_archive):
        parser.error("PF hashes require their corresponding input files")
    if args.fw05_log_evidence and not args.pf_rules_evidence:
        parser.error("--fw05-log-evidence requires --pf-rules-evidence")
    if not args.fw05_log_evidence and any((args.fw05_log_sha256, args.fw05_test_start, args.fw05_test_end,
                                          args.fw05_test_context, args.fw05_test_context_sha256)):
        parser.error("FW-05 auxiliary options require --fw05-log-evidence")
    if bool(args.fw05_test_start) != bool(args.fw05_test_end):
        parser.error("FW-05 test window requires both start and end")
    if args.fw05_test_context_sha256 and not args.fw05_test_context:
        parser.error("FW-05 context hash requires its input file")
    started = datetime.now(timezone.utc)
    evidence = fw.Evidence(uuid4().hex, started, started)
    manual = load_manual_evidence(args.manual_evidence)
    pf_snapshot = opnsense_pf.analyze(
        args.pf_rules_evidence, detail=args.pf_rules_detail, sha256=args.pf_rules_sha256,
        detail_sha256=args.pf_rules_detail_sha256, archive=args.pf_rules_archive,
        archive_sha256=args.pf_rules_archive_sha256, execution_id=evidence.execution_id, checked_at=started,
    ) if args.pf_rules_evidence else None
    log_rule_evidence = opnsense_log_rules.analyze(
        args.fw05_log_evidence, rules_path=args.pf_rules_evidence, detail=args.pf_rules_detail,
        log_sha256=args.fw05_log_sha256, rules_sha256=args.pf_rules_sha256, detail_sha256=args.pf_rules_detail_sha256,
        archive=args.pf_rules_archive, archive_sha256=args.pf_rules_archive_sha256,
        test_start=args.fw05_test_start, test_end=args.fw05_test_end,
        context_path=args.fw05_test_context, context_sha256=args.fw05_test_context_sha256,
        execution_id=evidence.execution_id, checked_at=started,
    ) if args.fw05_log_evidence else None
    execution_skipped = args.execute and (manual["status"] == "ERROR"
        or any(report is not None and report["status"] == "ERROR" for report in (pf_snapshot, log_rule_evidence)))
    if args.execute and not execution_skipped:
        client = None
        try:
            client = fw.ReadOnlyClient(
                account=os.environ.get("OPNSENSE_API_ACCOUNT"), key=os.environ.get("OPNSENSE_API_KEY"),
                secret=os.environ.get("OPNSENSE_API_SECRET"), ca_bundle=os.environ.get("OPNSENSE_CA_BUNDLE"),
            )
            fw.collect_api(client, evidence)
            if args.ping:
                try:
                    evidence.probes.append(fw.ping_lan(evidence.execution_id, args.scenario))
                    # Read after the probe, but do not invent log field/probe mappings.
                    if not fw.collect_api_endpoint(client, evidence, "logs"):
                        evidence.errors["FW-06"] = "post_probe_log_collection_failed"
                except fw.CollectionError as exc:
                    evidence.errors["FW-06"] = str(exc)
        except fw.CollectionError as exc:
            evidence.errors = {f"FW-{i:02}": str(exc) for i in range(1, 7)}
        finally:
            if client is not None:
                client.close()
    evidence.checked_at = datetime.now(timezone.utc)
    results = rows(evidence)
    attach_manual_results(results, manual)
    if pf_snapshot is not None:
        next(row for row in results if row["check_id"] == "FW-04")["pf_snapshot"] = pf_snapshot
    if log_rule_evidence is not None:
        log_rule_evidence["automatic_collection"] = evidence.api_results.get("logs", {
            "status": "NOT_TESTED", "reason": "live_api_not_executed", "endpoint": fw.ENDPOINTS["logs"]})
        log_rule_evidence["api_rule_id_mapping"] = evidence.rule_id_mapping
        next(row for row in results if row["check_id"] == "FW-05")["log_rule_evidence"] = log_rule_evidence
    print(json.dumps({
        "mode": "execute" if args.execute else "prepare", "target": fw.TARGET,
        "preparation": [
            "기본 모드는 네트워크·Ping을 실행하지 않습니다.",
            "별도 비 root 최소 권한 계정, 환경 변수의 Key/Secret, 신뢰 CA와 IP SAN이 필요합니다.",
            r"실행: .\.venv\Scripts\python.exe -B -m scripts.run_day4_audit --execute",
            "별도 Ping 승인: --execute --ping --scenario pass 또는 block (정책 변경 없음)",
            "VM 시작과 Alpine Live IP 복원은 운영자가 별도로 준비해야 합니다.",
            "26.7 실응답의 규칙·로그 어댑터 검증 전 FW-04/05/06 PASS를 확정하지 않습니다.",
            "WAN 측 HTTPS/ICMP/TCP 시험은 이 Windows LAN 실행으로 대체되지 않습니다.",
        ], "api_results": evidence.api_results, "rule_id_mapping": evidence.rule_id_mapping,
        "manual_evidence": {"status": manual["status"], "reason": manual["reason"]},
        "execution_skipped": execution_skipped,
        "results": results,
    }, ensure_ascii=False, indent=2))
    return int(any(row["status"] in {"FAIL", "ERROR"} for row in results) or manual_failure(results, manual)
               or any(report is not None and report["status"] in {"FAIL", "ERROR"} for report in (pf_snapshot, log_rule_evidence)))


if __name__ == "__main__":
    raise SystemExit(main())
