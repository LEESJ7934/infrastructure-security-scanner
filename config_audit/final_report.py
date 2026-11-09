"""One offline snapshot -> JSON, PDF, evidence, comparison and a file manifest.

No imports of DB report builders, collection scripts or diagnostic evaluators.
Only fixed local inputs and literal rule definitions are read. Raw settings,
firewall events, headers and backup contents never enter the report model.
"""

import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from uuid import uuid4

from .comparison import SnapshotRelation, compare_snapshots
from .evidence_index import (EvidenceAccessError, EvidenceBinding, EvidencePolicy, _fingerprint,
                             _open_file, attach_evidence_index, build_evidence_index)
from .reporting import (MAX_BYTES, ReportInputError, SourceSnapshot, integrate, normalize, unique_object)
from .statuses import AuditStatus

INPUTS = (("logs/day2-before.json", 2, "day2-before", "results"),
          ("logs/day2-after.json", 2, "day2-after", "results"),
          ("logs/day3-final.json", 3, "day3-final", "results"),
          ("evidence/day4/manual.json", 4, "day4-manual", "manual"))
FILES = {"report": "day5-integrated-report.json", "pdf": "day5-integrated-report.pdf",
         "evidence": "day5-evidence-index.json", "comparison": "day5-comparison.json",
         "manifest": "day5-manifest.json"}
REFERENCE_COUNTS = {"VERIFIED": 15, "MISMATCH": 0, "MISSING": 0, "NOT_VERIFIED": 33,
                    "EXTERNAL_REFERENCE": 12, "INVALID_REFERENCE": 0}
SECRET_KEYS = re.compile(r"authorization|api[_ -]?(?:key|secret)|private[_ -]?key|^password$", re.I)
SECRET_VALUE = re.compile(r"(?:authorization|api[_ -]?(?:key|secret)|private[_ -]?key|password)\s*[:=]\s*\S+|"
                          r"-----BEGIN .*PRIVATE KEY-----|\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]+|https?://[^/\s]+@", re.I)


class FinalReportError(ValueError):
    """Fixed safe error codes, never input contents or OS exceptions."""


def scrub(value):
    """Publication defense in depth. Unknown raw fields never reach this layer."""
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SECRET_KEYS.search(str(key)) else scrub(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [scrub(item) for item in value]
    if isinstance(value, str) and SECRET_VALUE.search(value):
        return "[REDACTED]"
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def content_sha256(snapshot):
    body = {key: value for key, value in snapshot.items() if key != "content_sha256"}
    return hashlib.sha256(canonical(body)).hexdigest()


def _read(policy, candidate, limit):
    before = policy.inspect(candidate)
    if before.st_size > limit:
        raise FinalReportError("input_size_limit")
    descriptor = _open_file(policy, candidate)
    with os.fdopen(descriptor, "rb") as stream:
        if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
            raise FinalReportError("input_changed")
        data = stream.read(limit + 1)
        if len(data) != before.st_size or _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
            raise FinalReportError("input_changed")
    if _fingerprint(policy.inspect(candidate)) != _fingerprint(before):
        raise FinalReportError("input_changed")
    return data


def _load(policy, relative, day, identifier, kind):
    metadata = {"snapshot_id": identifier, "source": relative, "day": day, "input_kind": kind,
                "observed_file_sha256": None, "hash_is_independent_expectation": False}
    try:
        data = _read(policy, policy.path(relative), MAX_BYTES)
        metadata["observed_file_sha256"] = hashlib.sha256(data).hexdigest()
        def reject_constant(_):
            raise FinalReportError("json_constant_invalid")
        decoded = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object, parse_constant=reject_constant)
        snapshot = normalize(decoded, day=day, snapshot_id=identifier, source=str(policy.root / relative), input_kind=kind)
    except FileNotFoundError:
        code = "input_missing"
    except (EvidenceAccessError, ReportInputError, FinalReportError) as exc:
        code = str(exc)
    except (OSError, UnicodeError, ValueError, RecursionError):
        code = "input_invalid_or_unreadable"
    else:
        metadata["import_status"] = snapshot.import_status
        return snapshot, metadata
    metadata.update(import_status="ERROR", error_code=code)
    return SourceSnapshot(identifier, day, str(policy.root / relative), kind, diagnostics=(code,), import_status="ERROR"), metadata


def _catalog(policy):
    """Extract only literal descriptions/recommendations via AST, never import scripts."""
    catalog = {}
    for day in (2, 3, 4):
        relative = f"scripts/run_day{day}_audit.py"
        try:
            raw = _read(policy, policy.root / relative, 128 * 1024)
            tree = ast.parse(raw.decode("utf-8-sig"))
            digest = hashlib.sha256(raw).hexdigest()
            def add(check, description, recommendation, line):
                catalog[check] = {"check_name": description, "expected_condition": description,
                                  "recommendation": recommendation, "catalog_rule_version": "1",
                                  "source_reference": f"{relative}:{line}", "source_sha256": digest}
            if day == 2:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "AuditRule":
                        if len(node.args) >= 4 and all(isinstance(arg, ast.Constant) and isinstance(arg.value, str) for arg in node.args[:4]):
                            check, version, description, recommendation = [arg.value for arg in node.args[:4]]
                            if version == "1":
                                add(check, description, recommendation, node.lineno)
            else:
                versions = {node.args[1].value for node in ast.walk(tree)
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "AuditRule"
                            and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)}
                if versions != {"1"}:
                    continue
                name_prefix = {"IDS_RULES": "IDS", "WAF_RULES": "WAF"} if day == 3 else {"DESCRIPTIONS": "FW"}
                # Recommendation is read only from the actual AuditRule call.
                recommendations = [node.args[3].value for node in ast.walk(tree)
                                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "AuditRule"
                                   and len(node.args) >= 4 and isinstance(node.args[3], ast.Constant) and isinstance(node.args[3].value, str)]
                for node in tree.body:
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                        prefix = name_prefix.get(node.targets[0].id)
                        if prefix and isinstance(node.value, (ast.Tuple, ast.List)):
                            for index, item in enumerate(node.value.elts, 1):
                                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                                    add(f"{prefix}-{index:02}", item.value, recommendations[0] if len(set(recommendations)) == 1 else None, item.lineno)
        except (OSError, UnicodeError, ValueError, EvidenceAccessError, FinalReportError, SyntaxError):
            # No fabricated guide when the literal rule definition is unavailable.
            continue
    return catalog


def _extras():
    bindings = [EvidenceBinding("lab/ids-waf-lab/artifacts/" + name, day=3, snapshot_id="day3-final",
                                role="unassigned_local_artifact") for name in ("day3.pcap", "suricata-eve.json", "suricata-fast.log")]
    for name, check, channel in (("fw04-active-rules.txt", "FW-04", "pf"),
                                 ("fw04-active-rules-detail.txt", "FW-04", "pf"), ("fw04-rules.tar", "FW-04", "pf"),
                                 ("fw05-wan-tcp22.json", "FW-05", "log_analysis"), ("fw05-wan-tcp22-retest.json", "FW-05", "log_analysis")):
        bindings.append(EvidenceBinding("evidence/day4/" + name, asset_id="SJ-D4-OPNsense", check_id=check, day=4,
                                        snapshot_id="day4-manual", channel=channel,
                                        role="supporting_artifact_without_saved_analysis"))
    return bindings


def build_final_snapshot(project_root):
    policy = EvidencePolicy(project_root)
    loaded = [_load(policy, *spec) for spec in INPUTS]
    report = integrate([item[0] for item in loaded])
    index = build_evidence_index(report, project_root=policy.root, extra_bindings=_extras())
    for _source, metadata in loaded:
        for entry in index["entries"]:
            if entry["snapshot_id"] == metadata["snapshot_id"] and entry["channel"] == "snapshot_input" and entry["actual_sha256"]:
                if metadata["observed_file_sha256"] != entry["actual_sha256"]:
                    raise FinalReportError("input_changed_after_import")
    report = attach_evidence_index(report, index)
    comparison = compare_snapshots(report, [SnapshotRelation("day2-before", "day2-after")]).to_dict()
    catalog, details, groups = _catalog(policy), [], []
    for snapshot in report.snapshots:
        grouped = {}
        for row in snapshot.results:
            channels = {"automatic": row.automatic, "manual": row.manual,
                        "pf": row.analyses.get("pf_snapshot"), "log_analysis": row.analyses.get("log_rule_evidence")}
            for channel, value in channels.items():
                if value is None:
                    continue
                counts = grouped.setdefault((row.asset_id, channel), {status.value: 0 for status in AuditStatus})
                counts[value["status"]] += 1
            definition = deepcopy(catalog.get(row.check_id))
            matches_version = definition is not None and row.rule_version == definition["catalog_rule_version"]
            details.append({"record_id": f"RESULT-{len(details)+1:03}", "snapshot_id": snapshot.snapshot_id,
                            "day": snapshot.day, **row.to_dict(), "definition": definition,
                            "definition_is_matching_rule_version": matches_version,
                            "expected_condition": definition["expected_condition"] if matches_version else None,
                            "recommendation_from_definition": definition["recommendation"] if matches_version else None,
                            "observed_value": None, "observed_value_note": "원본 관찰값 미저장; 저장 판정과 수동 시험 기록만 보존",
                            "unknowns": ["조치 이력 미확인", "CVE/CVSS 평가 자료 없음"] +
                            ([] if matches_version else ["원본 규칙 버전/기준 미확인; 규칙 정의는 참고 설명만 제공"])})
        for (asset, channel), counts in sorted(grouped.items()):
            groups.append({"snapshot_id": snapshot.snapshot_id, "asset_id": asset, "channel": channel, "status_counts": counts})
    selected = [row for row in details if row["snapshot_id"] in {"day2-after", "day3-final", "day4-manual"}]
    def count_channel(channel):
        counts = Counter(row[channel]["status"] for row in selected if row.get(channel) is not None)
        return {status.value: counts[status.value] for status in AuditStatus}
    actual = index["counts"]
    limitations = ["실습 프로젝트의 과거 저장 자료를 통합한 오프라인 보고서이며 실장비 재점검을 수행하지 않았습니다.",
                  "FW-04/05의 미검증 및 FW-06 수동 판정은 원본대로 보존하며 자동 PASS로 변경하지 않습니다.",
                  "완전한 Day4 자동 실행 결과 JSON이 없어 FW-01을 포함한 자동 결과를 생성하지 않습니다.",
                  "Day3 외부 증적 참조를 로컬 아티팩트와 동일한 증거로 간주하지 않습니다.",
                  "독립 기대 해시가 없는 파일은 NOT_VERIFIED이며 해시 일치는 진위·수집 완전성의 증명이 아닙니다.",
                  "PF 규칙 세대 연속성 및 전체 유효 정책은 입증되지 않았고 PF/로그 분석을 새로 실행하지 않았습니다.",
                  f"Day2 원본 상태 변화와 엄격한 UNVERIFIABLE {comparison['summary']['UNVERIFIABLE']}건은 구분하며 조치 완료를 확정하지 않습니다."]
    snapshot = scrub({"schema_version": "day5-offline-final/1", "report_version": "1.0", "report_id": uuid4().hex,
                      "generated_at": report.generated_at, "mode": "offline_stored_evidence_only",
                      "completion_status": "COMPLETE_WITH_LIMITATIONS" if all(s.import_status == "LOADED" for s in report.snapshots) else "PARTIAL",
                      "inputs": [metadata for _, metadata in loaded], "diagnostics": report.to_dict(), "comparison": comparison,
                      "details": details, "summary": {"asset_count": len({r["asset_id"] for r in details}),
                          "record_count": len(details), "unique_check_count": len({(r["asset_id"], r["check_id"]) for r in details}),
                          "by_snapshot_asset_channel": groups,
                          "selected_view": {"snapshot_ids": ["day2-after", "day3-final", "day4-manual"],
                                            "note": "명시적으로 선택한 서로 다른 시점의 기록이며 현재 전체 안전성을 나타내는 합계가 아닙니다.",
                                            "record_count": len(selected), "automatic": count_channel("automatic"), "manual": count_channel("manual")}},
                      "index_reference_difference": {"counts": {key: actual[key]-REFERENCE_COUNTS[key] for key in REFERENCE_COUNTS},
                                                     "unique_local_files": index["unique_local_files"]-23,
                                                     "connections": len(index["entries"])-60}, "limitations": limitations})
    snapshot["content_sha256"] = content_sha256(snapshot)
    return snapshot


def generate_final_report(project_root, output_dir=None):
    """Generate all five artifacts from one constructed snapshot; manifest is last."""
    from api.report_pdf import render_day5_report_pdf
    root = Path(project_root).resolve(strict=True)
    target = Path(output_dir) if output_dir else root / "reports/day5"
    # Outputs must stay under reports, never overwrite evidence or follow links.
    target = target if target.is_absolute() else root / target
    if not target.is_relative_to(root / "reports") or ".." in target.parts:
        raise FinalReportError("output_outside_reports")
    current = root
    for part in target.relative_to(root).parts:
        current = current / part
        if current.exists() and (current.is_symlink() or getattr(current.lstat(), "st_file_attributes", 0) & 0x400):
            raise FinalReportError("output_link_denied")
    snapshot = build_final_snapshot(root)
    target.mkdir(parents=True, exist_ok=True)
    for filename in FILES.values():
        path = target / filename
        if path.exists() and (path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400 or path.stat().st_nlink != 1):
            raise FinalReportError("output_link_denied")
    with TemporaryDirectory(prefix=".day5-", dir=target) as temporary:
        temporary = Path(temporary)
        def write_json(name, value):
            (temporary/name).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
        write_json(FILES["report"], snapshot)
        write_json(FILES["evidence"], {"report_id": snapshot["report_id"], "report_content_sha256": snapshot["content_sha256"],
                                       "evidence_index": snapshot["diagnostics"]["evidence_index"]})
        write_json(FILES["comparison"], {"report_id": snapshot["report_id"], "report_content_sha256": snapshot["content_sha256"],
                                         "comparison": snapshot["comparison"]})
        pdf_metadata = render_day5_report_pdf(snapshot, temporary/FILES["pdf"])
        artifacts = []
        for kind in ("report", "pdf", "evidence", "comparison"):
            path = temporary/FILES[kind]
            artifacts.append({"kind": kind, "filename": path.name, "size_bytes": path.stat().st_size,
                              "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest = {"schema_version": 1, "report_id": snapshot["report_id"], "generated_at": snapshot["generated_at"],
                    "completed_at": datetime.now(timezone.utc).isoformat(), "report_version": snapshot["report_version"],
                    "report_content_sha256": snapshot["content_sha256"], "content_digest_basis": "canonical UTF-8 JSON excluding only content_sha256",
                    "inputs": snapshot["inputs"], "artifacts": artifacts, "pdf": pdf_metadata,
                    "completion_status": snapshot["completion_status"], "index_reference_difference": snapshot["index_reference_difference"],
                    "limitations": snapshot["limitations"]+["manifest는 자기 자신의 파일 해시를 포함하지 않으며 서명이 아닙니다."]}
        write_json(FILES["manifest"], manifest)
        for name in FILES.values():
            os.replace(temporary/name, target/name)
    return {"output_dir": str(target), "report_id": snapshot["report_id"], "content_sha256": snapshot["content_sha256"],
            "completion_status": snapshot["completion_status"], "pdf": pdf_metadata,
            "summary": snapshot["summary"], "evidence_counts": snapshot["diagnostics"]["evidence_index"]["counts"],
            "comparison_summary": snapshot["comparison"]["summary"],
            "paths": {kind: str(target/name) for kind, name in FILES.items()}}
