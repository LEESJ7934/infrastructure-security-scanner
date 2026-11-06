"""Explicit local Windows exports -> separate offline JSON/PDF, never Day5.

Uses evaluate-backed collector and existing comparison models. Only allowlisted
numeric/boolean settings are published; original exports are never written.
"""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from xml.sax.saxutils import escape

from .collectors.windows_server import audit, load_bundle, to_report_snapshot, WindowsInputError
from .comparison import SnapshotRelation
from .reporting import OfflineReport
from .windows_comparison import compare_windows_snapshots
from .windows_policy import AUDIT_GUIDS, parse_audit

VALUE_KEYS = {
    "WIN-LAB-001": ("guest", ("enabled", "matching_accounts")),
    "WIN-LAB-002": ("security_policy", ("minimum_length",)),
    "WIN-LAB-003": ("security_policy", ("complexity",)),
    "WIN-LAB-004": ("security_policy", ("lockout_threshold", "lockout_duration", "reset_minutes")),
    "WIN-LAB-005": ("spooler", ("present", "native_error_code", "required", "print_services_installed", "print_server_installed")),
    "WIN-LAB-006": ("firewall", ("domain", "private", "public", "service_running")),
    "WIN-LAB-007": ("smb", ("smb1_enabled",)),
    "WIN-LAB-008": ("smb", ("require_signing",)),
}


def values(bundle, check_id):
    if check_id == "WIN-LAB-009":
        raw = bundle.document["sections"].get("audit", {}).get("values", {})
        return {"subcategories": parse_audit(raw)}
    section, keys = VALUE_KEYS[check_id]
    raw = bundle.document["sections"].get(section, {}).get("values", {})
    return {key: raw.get(key) for key in keys}


def build_windows_report(before_path, after_path, *, before_sha256=None, after_sha256=None, policy):
    """Missing independent before hash is NOT filled with the measured digest."""
    bundles = [load_bundle(path, expected_sha256=expected) for path, expected in
               ((before_path, before_sha256), (after_path, after_sha256))]
    if any(bundle.document["origin"] != "local_server_readonly" for bundle in bundles):
        raise WindowsInputError("device_report_requires_saved_server_origin")
    generated = datetime.now(timezone.utc).isoformat()
    reports, snapshots, entries = [], [], []
    for side, bundle in zip(("before", "after"), bundles):
        report = audit(bundle, asset_id=bundle.document["asset_id"], policy=policy)
        snapshot = to_report_snapshot(report, snapshot_id="windows-" + side)
        reports.append(report); snapshots.append(snapshot)
        for row in snapshot.results:
            entries.append({"evidence_id": side + "-" + row.check_id, "snapshot_id": snapshot.snapshot_id,
                "asset_id": row.asset_id, "check_id": row.check_id, "rule_version": row.rule_version,
                "channel": "automatic", "role": "snapshot_input", "original_reference": "windows-" + side,
                "exists": True, "actual_sha256": bundle.sha256, "expected_sha256": bundle.expected_sha256,
                "status": bundle.integrity, "hash_comparison": "MATCH" if bundle.expected_sha256 else "NOT_COMPARED",
                "verified_at": generated, "error": None})
    common = OfflineReport(generated, tuple(snapshots), evidence_index={"entries": entries, "verified_at": generated})
    comparison = compare_windows_snapshots(common, [SnapshotRelation("windows-before", "windows-after")])
    # This workflow requires BOTH independent source hashes, stricter than the
    # common engine's limited-confidence comparisons for unhashed saved files.
    if any(bundle.integrity != "VERIFIED" for bundle in bundles):
        pairs = comparison["pairs"]
        for pair in pairs:
            for row in pair["results"]:
                row["unmet_conditions"] = sorted(set(row["unmet_conditions"] + ["independent_source_hash_missing"]))
                if row["comparison_result"] in {"IMPROVED_OBSERVED", "UNCHANGED_PASS", "UNRESOLVED", "REGRESSED", "NEW_FINDING"}:
                    row["comparison_result"] = "UNVERIFIABLE"
                    row["comparability"]["status"] = "UNVERIFIABLE"
                    row["observed_change"] = None
        counts = Counter(row["comparison_result"] for pair in pairs for row in pair["results"])
        comparison["summary"] = {key: counts[key] for key in comparison["summary"]}
        comparison["observed_transition_summary"] = dict(Counter(row["observed_change"] for pair in pairs for row in pair["results"] if row["observed_change"]))
    changes = []
    for first, last in zip(reports[0]["results"], reports[1]["results"]):
        candidates = [row for row in comparison["pairs"][0]["results"] if row["check_id"] == first["check_id"]]
        verdicts = {row["comparison_result"] for row in candidates}
        changes.append({"check_id": first["check_id"], "asset_id_before": first["asset_id"], "asset_id_after": last["asset_id"],
                        "before_values": values(bundles[0], first["check_id"]), "after_values": values(bundles[1], first["check_id"]),
                        "before_status": first["status"], "after_status": last["status"],
                        "comparison_result": next(iter(verdicts)) if len(verdicts) == 1 else "UNVERIFIABLE",
                        "comparison_candidate_count": len(candidates),
                        "unmet_conditions": sorted(set(first["unmet_conditions"] + last["unmet_conditions"] +
                                                       [issue for row in candidates for issue in row["unmet_conditions"]])),
                        "recommendation": last["recommendation"]})
    return {"schema_version": 1, "mode": "offline_windows_reanalysis_only", "generated_at": generated,
        "internal_policy": policy.document, "policy_sha256": policy.sha256,
        "approval_attested": policy.approval_attested, "approval_integrity": policy.approval_integrity,
        "snapshots": [snapshot.to_dict() for snapshot in snapshots], "source_results": reports,
        "changes": changes, "evidence_index": common.evidence_index, "comparison": comparison,
        "limitations": ["not_KISA_certification", "no_new_live_collection_or_real_environment_completion_claim",
            "hash_agreement_not_source_authenticity", "approval_authority_requires_human_review",
            "null_means_not_collected_not_zero", "system_audit_settings_not_event_delivery_or_per_user_policy",
            "remediation_causality_not_verified", "original_exports_unchanged"]}


def write_windows_report(report, directory):
    """Create a fresh output directory, with no overwrites of existing reports."""
    directory = Path(directory)
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except OSError:
        raise WindowsInputError("new_report_directory_required") from None
    json_path = directory / "windows-report.json"
    pdf_path = directory / "windows-report.pdf"
    if report.get("mode") == "LAB":
        from .windows_lab_report import write_lab_pdf
        write_lab_pdf(report, pdf_path)
        json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
        return json_path, pdf_path
    # Lazy PDF imports: collector and preparation mode do not require ReportLab.
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallNote", fontName="Helvetica", fontSize=8, leading=11, spaceAfter=7))
    styles.add(ParagraphStyle(name="CellText", fontName="Helvetica", fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="HeaderCell", parent=styles["CellText"], textColor=colors.white))
    def p(value, style="SmallNote"):
        return Paragraph(escape(str(value)), styles[style])
    def table(rows, widths):
        result = Table([[p(cell, "HeaderCell" if index == 0 else "CellText") for cell in row] for index, row in enumerate(rows)], colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#edf3f7"), colors.white])]))
        return result
    policy = report["internal_policy"]
    story = [p("WINDOWS SERVER | OFFLINE REVIEW", "Title"), Spacer(1, 8),
        p("Internal lab criteria - saved exports only", "Heading2"),
        p("Not a KISA certification. No new live collection or full environment validation is claimed."),
        p("Generated: " + report["generated_at"]),
        p("Policy " + policy["version"] + " / " + policy["approval"]["status"] +
          " / approval attested: " + str(report["approval_attested"])),
        p("Missing settings remain null. A reported change is not a verified improvement when approval, evidence, or scope is incomplete.")]
    for side, source in zip(("BEFORE", "AFTER"), report["source_results"]):
        story += [p(side + " capture: " + str(source["results"][0]["collected_at"])),
            p("Measured SHA-256: " + str(source["sha256"])),
            p("Independent expected SHA-256: " + str(source["expected_sha256"])),
            p("Integrity: " + source["integrity"] + " / capture clock: " + source["collection_time_validation"]["status"])]
    story += [table([["Check", "Before", "After", "Strict comparison"]] +
                    [[row["check_id"], row["before_status"], row["after_status"], row["comparison_result"]] for row in report["changes"]],
                    [90, 100, 100, 217]), PageBreak(), p("PASSWORD POLICY | ACTUAL SAVED VALUES", "Title")]
    pw = policy["password"]
    story += [p("Internal proposal: minimum length >= " + str(pw["minimum_length"]) +
        "; complexity enabled; threshold exactly " + str(pw["lockout_threshold"]) +
        "; duration/reset minutes " + str(pw["duration_minutes"]) + "/" + str(pw["reset_minutes"])),
        p("No approval metadata has been invented. DRAFT or incomplete approval blocks policy verdicts.")]
    password_rows = [["Setting", "Before saved value", "After saved value"]]
    for row in report["changes"]:
        if row["check_id"] in {"WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004"}:
            for key, before in row["before_values"].items():
                password_rows.append([key, "NOT COLLECTED" if before is None else str(before),
                                      "NOT COLLECTED" if row["after_values"][key] is None else str(row["after_values"][key])])
    story += [table(password_rows, [207, 150, 150]), Spacer(1, 16), p("AUDIT POLICY | GUID-BASED SYSTEM SETTINGS", "Heading2"),
        p("Source: AuditQuerySystemPolicy. Success bit=1, failure bit=2, explicit none=4. Display names are explanatory only.")]
    story += [table([["Subcategory", "Stable GUID", "Success", "Failure"]] +
                    [[name, guid, "Required" if policy["audit"][guid]["success"] else "Optional",
                      "Required" if policy["audit"][guid]["failure"] else "Optional"] for guid, name in AUDIT_GUIDS.items()], [130, 247, 65, 65]),
        p("Saved legacy parser_verified=false does not contain subcategory evidence. Recollection is required. System flags alone do not establish actual event delivery."), PageBreak(),
        p("FINDINGS AND REVIEW CONDITIONS", "Title")]
    for row in report["changes"]:
        criterion = next(item["expected_condition"] for item in report["source_results"][1]["results"] if item["check_id"] == row["check_id"])
        story += [KeepTogether([p(row["check_id"] + " / " + row["after_status"], "Heading2"),
            p("Criterion: " + criterion),
            p("Strict comparison: " + row["comparison_result"]),
            p("Before: " + json.dumps(row["before_values"], sort_keys=True)),
            p("After: " + json.dumps(row["after_values"], sort_keys=True)),
            p("Unmet: " + (", ".join(row["unmet_conditions"]) or "none recorded")),
            p("Recommendation: " + row["recommendation"]), Spacer(1, 7)])]
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont("Helvetica", 8); canvas.setFillColor(colors.HexColor("#526274"))
        canvas.drawString(44, 25, "Infrastructure Security Scanner | Windows lab | Offline reanalysis")
        canvas.drawRightString(A4[0] - 44, 25, str(doc.page)); canvas.restoreState()
    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, rightMargin=44, leftMargin=44, topMargin=38, bottomMargin=42)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    return json_path, pdf_path
