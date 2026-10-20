"""Atomic read-only V6+V7 reports for two separately scanned lab environments.

No network probes, AWS mutation, or scanner execution. Missing checks are NOT_TESTED.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from api.analysis_report import (
    _assemble, _read_rows, get_connection, snapshot_sha256, validate_selection
)
from api.report_pdf import render_report_pdf
from scripts.generate_lab_comparison import build_comparison


def build_integrated_snapshot(*, local_scan_id: int, ec2_scan_id: int,
                              runtime_context="OPERATOR_STORED_OBSERVATIONS", safe_sql_evidence=None):
    if runtime_context not in {"OPERATOR_STORED_OBSERVATIONS", "GITHUB_ACTIONS_DISPOSABLE_DOCKER"}:
        raise ValueError("Unsupported report runtime context")
    if local_scan_id < 1 or ec2_scan_id < 1 or local_scan_id == ec2_scan_id:
        raise ValueError("Two distinct positive scan IDs required")
    connection = get_connection()
    try:
        connection.start_transaction(isolation_level="REPEATABLE READ",
                                     consistent_snapshot=True, readonly=True)
        left = _read_rows(connection, validate_selection(scan_id=local_scan_id))
        right = _read_rows(connection, validate_selection(scan_id=ec2_scan_id))
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(
                """SELECT * FROM lab_verification_results
                   WHERE (scan_id = %s AND environment_label = 'LOCAL_BASELINE')
                      OR (scan_id = %s AND environment_label = 'EC2_LAB')
                   ORDER BY observed_at,id""",
                (local_scan_id, ec2_scan_id))
            lab_rows = cursor.fetchall()
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()
    baseline = _assemble(validate_selection(scan_id=local_scan_id), left)
    ec2 = _assemble(validate_selection(scan_id=ec2_scan_id), right)
    comparison = build_comparison(lab_rows)
    comparison["scan_ids"] = {"LOCAL_BASELINE": local_scan_id, "EC2_LAB": ec2_scan_id}
    independent_sql = {"status": "NOT_TESTED", "dvwa_remediated": False}
    if safe_sql_evidence is not None:
        import hashlib
        from scripts.verify_safe_sql_baseline import validate_evidence
        source = Path(safe_sql_evidence)
        if source.stat().st_size > 16384:
            raise ValueError("Safe SQL evidence exceeds bound")
        raw = source.read_bytes()
        independent_sql = {"status": "OPERATOR_OR_CI_RECORDED_OBSERVATION",
                           "source_file_sha256": hashlib.sha256(raw).hexdigest(),
                           "evidence": validate_evidence(json.loads(raw), local_scan_id), "dvwa_remediated": False}
    baseline.update(
        independent_sql_baseline=independent_sql,
        runtime_context=runtime_context,
        peer_report=ec2,
        lab_comparison=comparison,
        report_scope="V6+V7 two-scan comparison; one read-only repeatable-read database snapshot",
        selection={"type": "lab_pair", "local_scan_id": local_scan_id,
                   "ec2_scan_id": ec2_scan_id}
    )
    baseline["integrity"]["snapshot_sha256"] = snapshot_sha256(baseline)
    return baseline


def generate_integrated_report(*, local_scan_id: int, ec2_scan_id: int,
                               output_dir="reports", format="both",
                               runtime_context="OPERATOR_STORED_OBSERVATIONS", safe_sql_evidence=None):
    if format not in {"json", "pdf", "both"}:
        raise ValueError("Unsupported export format")
    snapshot = build_integrated_snapshot(local_scan_id=local_scan_id, ec2_scan_id=ec2_scan_id,
                                         runtime_context=runtime_context, safe_sql_evidence=safe_sql_evidence)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    name = f"integrated_lab_{local_scan_id}_{ec2_scan_id}_{stamp}"
    output = {"snapshot_sha256": snapshot["integrity"]["snapshot_sha256"],
              "json_path": None, "pdf_path": None}
    with TemporaryDirectory(prefix=".labreport-", dir=directory) as tmp:
        created = []
        if format in {"json", "both"}:
            p = Path(tmp) / (name + ".json")
            p.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False,
                                    default=str) + "\n", encoding="utf-8")
            created.append(("json_path", p))
        if format in {"pdf", "both"}:
            p = Path(tmp) / (name + ".pdf")
            render_report_pdf(snapshot, p)
            created.append(("pdf_path", p))
        for key, src in created:
            dst = directory / src.name
            os.replace(src, dst)
            output[key] = str(dst)
    return output


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--local-scan-id", type=int, required=True)
    p.add_argument("--ec2-scan-id", type=int, required=True)
    p.add_argument("--safe-sql-evidence-file", type=Path)
    p.add_argument("--output-dir", default="reports")
    p.add_argument("--format", choices=("json", "pdf", "both"), default="both")
    a = p.parse_args(argv)
    try:
        print(json.dumps(generate_integrated_report(
            local_scan_id=a.local_scan_id, ec2_scan_id=a.ec2_scan_id,
            output_dir=a.output_dir, format=a.format, safe_sql_evidence=a.safe_sql_evidence_file), ensure_ascii=False))
        return 0
    except Exception as e:
        print(json.dumps({"error": type(e).__name__}), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
