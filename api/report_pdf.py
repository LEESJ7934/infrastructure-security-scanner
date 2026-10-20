"""Render a supplied report snapshot with ReportLab; no DB or network access."""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (HRFlowable, LongTable, Paragraph, SimpleDocTemplate,
                               Spacer, TableStyle)

NAVY = colors.HexColor("#182B44")
TEAL = colors.HexColor("#126B75")
INK = colors.HexColor("#25354A")
MUTED = colors.HexColor("#53647A")
LINE = colors.HexColor("#D8E1EB")
PALE = colors.HexColor("#F2F6FA")


def _body_font():
    # Use installed Korean fonts when available. No font file is shipped/downloaded.
    if "ReportKorean" in pdfmetrics.getRegisteredFontNames():
        return "ReportKorean"
    for path in (Path("C:/Windows/Fonts/malgun.ttf"),
                 Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf")):
        if path.is_file():
            pdfmetrics.registerFont(TTFont("ReportKorean", str(path)))
            return "ReportKorean"
    name = "HYSMyeongJo-Medium"
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(name))
    return name


def _text(value):
    if value is None or value == "":
        return "N/A"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]", "?", str(value))
    return escape(value).replace("\n", "<br/>")


def render_report_pdf(snapshot, output_path):
    """Paginated, wrapping content. Evidence text is escaped, never treated as HTML."""
    font = _body_font()
    body = ParagraphStyle("Body", fontName=font, fontSize=9, leading=13, textColor=INK,
                          spaceAfter=5, wordWrap="CJK", splitLongWords=True, alignment=TA_LEFT)
    small = ParagraphStyle("Small", parent=body, fontSize=8, leading=11, spaceAfter=2)
    heading = ParagraphStyle("Heading", fontName="Helvetica-Bold", fontSize=13, leading=17,
                             textColor=NAVY, spaceBefore=16, spaceAfter=8, keepWithNext=True)
    subheading = ParagraphStyle("Subheading", parent=body, fontSize=11, leading=15,
                                textColor=TEAL, spaceBefore=10, spaceAfter=6, keepWithNext=True)
    cell_header = ParagraphStyle("CellHeader", parent=small, fontName="Helvetica-Bold", textColor=colors.white)
    title = ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=23, leading=28,
                           textColor=NAVY, spaceAfter=9)
    width, _height = A4
    usable = width - 84
    story = []

    def p(value, style=body):
        return Paragraph(_text(value), style)

    def section(number, name):
        story.append(Paragraph(f"{number:02d}  {name}", heading))
        rule = HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=6)
        rule.keepWithNext = True
        story.append(rule)

    def fields(items):
        # Separate paragraphs allow even very long reasons/history values to split across pages.
        for key, value in items:
            caption = _text(str(key).replace("_", " ").upper())
            story.append(Paragraph(
                f'<font name="Helvetica-Bold" size="8" color="#53647A">{caption}:</font> {_text(value)}', body))

    def table(headers, rows, widths):
        data = [[p(value, cell_header) for value in headers]]
        data.extend([[p(value, small) for value in row] for row in rows])
        obj = LongTable(data, colWidths=[usable * fraction for fraction in widths],
                        repeatRows=1, splitByRow=1, splitInRow=1, hAlign="LEFT", spaceAfter=8)
        obj.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("LINEBELOW", (0, 0), (-1, 0), 0.7, NAVY),
            ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(obj)

    assets = snapshot.get("assets", [])
    assets_by_uid = {asset.get("asset_uid"): asset for asset in assets}
    findings = [finding for asset in assets for finding in asset.get("findings", [])]
    cloud_findings = [finding for asset in assets for finding in asset.get("cloud_configuration_findings", [])]
    priority_order = {value: rank for rank, value in enumerate(("P1", "P2", "P3", "P4", "UNASSESSED"))}
    findings.sort(key=lambda finding: (priority_order.get(finding.get("effective_priority"), 4), finding["vuln_id"]))
    summary = snapshot.get("summary", {})
    story.append(Paragraph("Infrastructure Security Review", title))
    story.append(p("Stored observations, verification evidence and assessment context", small))
    story.append(Spacer(1, 8))
    section(1, "Report Metadata")
    fields([("generated_at_utc", snapshot.get("generated_at")), ("selection", snapshot.get("selection")),
            ("report_basis", "Read-only V6-capable DB snapshot. This command does not scan, verify or refresh external intelligence.")])

    section(2, "Executive Summary")
    table(["Assets", "Open ports", "CVE findings", "AWS config", "CVE highest"],
          [[summary.get("asset_count"), summary.get("open_port_count"), summary.get("finding_count"),
            summary.get("cloud_configuration_finding_count", 0), summary.get("highest_priority", "UNASSESSED")]],
          [0.14, 0.16, 0.20, 0.20, 0.30])
    story.append(p("Status counts", subheading))
    statuses = list(summary.get("status_counts", {}).items())
    status_rows = []
    for index in range(0, len(statuses), 2):
        left = statuses[index]
        right = statuses[index + 1] if index + 1 < len(statuses) else ("N/A", None)
        status_rows.append([left[0], left[1], right[0], right[1]])
    table(["Status", "Count", "Status", "Count"], status_rows or [["N/A", 0, "N/A", 0]], [0.38, 0.12, 0.38, 0.12])
    for title_label, key in (("CVE effective priority counts", "priority_counts"),
                             ("AWS configuration priority counts", "cloud_priority_counts"),
                             ("Assessment freshness", "assessment_freshness_counts")):
        story.append(p(title_label, subheading))
        counts = summary.get(key, {}) or {"N/A": 0}
        table(list(counts), [list(counts.values())], [1 / len(counts)] * len(counts))
    story.append(p(summary.get("coverage_note", "No stored findings does not establish security.")))
    story.append(p(summary.get("freshness_note", "External sources were not refreshed.")))
    story.append(p("STALE and MISSING assessments contribute UNASSESSED to current priority totals."))

    section(3, "Scope / Scan Information")
    if not snapshot.get("scans"):
        story.append(p("N/A - no linked stored scan information."))
    for scan in snapshot.get("scans", []):
        story.append(p(f"Scan {scan.get('scan_id', 'N/A')}", subheading))
        fields((key, scan.get(key)) for key in ("scan_id", "scan_uid", "status", "scan_type", "requested_targets",
                                               "target", "port_range", "started_at", "finished_at"))
        fields(("scope_" + key, value) for key, value in scan.get("scope", {}).items())

    section(4, "Asset Information")
    if not assets:
        story.append(p("N/A - no linked stored assets."))
    for asset in assets:
        story.append(p(asset.get("asset_name") or asset.get("asset_uid"), subheading))
        fields((key, asset.get(key)) for key in ("asset_uid", "host_ip", "host_name", "asset_name", "asset_type",
                                                "environment", "criticality", "owner", "business_unit", "data_classification",
                                                "handles_personal_data", "internet_exposed", "lifecycle_status", "first_seen", "last_seen"))

    section(5, "AWS Cloud Context / Configuration Findings")
    cloud_assets = [asset for asset in assets if asset.get("cloud")]
    if not cloud_assets:
        story.append(p("N/A - no linked AWS cloud context for the selected assets."))
    for asset in cloud_assets:
        cloud = asset.get("cloud") or {}
        story.append(p(asset.get("asset_name") or asset.get("asset_uid"), subheading))
        fields((key, cloud.get(key)) for key in ("provider", "account_id", "region", "resource_type", "resource_id",
                                                "vpc_id", "subnet_id", "private_ip", "public_ip", "instance_state",
                                                "last_discovered_at"))
        current = asset.get("cloud_configuration_findings", [])
        if current:
            table(["Rule", "Severity", "Priority", "Public IP", "Title"],
                  [[f.get("rule_id"), f.get("severity"), f.get("priority"), f.get("public_address_present"), f.get("title")]
                   for f in current], [0.16, 0.14, 0.14, 0.16, 0.40])
            for finding in current:
                story.append(p(f"{finding.get('rule_id')} evidence", subheading))
                fields((key, finding.get(key)) for key in ("category", "status", "severity", "priority",
                                                            "public_address_present", "first_detected_at",
                                                            "last_detected_at", "observations", "remediation"))
                fields([("evidence", finding.get("evidence")),
                        ("reachability_note", "Security Group breadth and public-address presence are context only; end-to-end Internet reachability is not asserted.")])
        else:
            story.append(p("No OPEN AWS configuration findings stored for this cloud asset."))

    section(6, "Open Ports")
    open_rows = [[asset.get("host_ip"), f"{port.get('port')}/{port.get('protocol')}", port.get("service"),
                  port.get("product"), port.get("version"), port.get("last_scan_id")]
                 for asset in assets for port in asset.get("ports", []) if port.get("state") == "open"]
    if open_rows:
        table(["Host", "Port / proto", "Service", "Product", "Version", "Scan"], open_rows,
              [0.22, 0.17, 0.13, 0.22, 0.16, 0.10])
    else:
        story.append(p("No current open port observations. This is not proof that all ports are closed or safe."))
    story.append(p("Findings on currently observed closed/filtered endpoints retain their stored review status; port closure alone does not close a finding."))

    section(7, "CVE Findings Summary")
    if findings:
        table(["CVE / ID", "Status", "Priority", "Action", "Freshness"],
              [[f"{f.get('cve_id')} / {f['vuln_id']}", f.get("status"), f.get("effective_priority"),
                f.get("effective_action"), f.get("assessment_freshness")] for f in findings],
              [0.29, 0.22, 0.16, 0.16, 0.17])
    else:
        story.append(p("No stored reviewed findings for these current port observations; this does not establish security."))

    section(8, "CVE Finding Details")
    for finding in findings:
        story.append(p(f"{finding.get('cve_id')} / Finding {finding['vuln_id']}", subheading))
        fields((key, finding.get(key)) for key in ("title", "source", "status", "severity", "effective_priority",
                                                   "effective_action", "assessment_freshness", "freshness_reasons",
                                                   "first_detected_at", "last_detected_at", "verified_at", "closed_at"))
        fields([("endpoint", finding.get("endpoint"))])
        current_asset = assets_by_uid.get(finding.get("endpoint", {}).get("asset_uid"), {})
        fields([("current_asset_criticality", current_asset.get("criticality"))])
        assessment = finding.get("assessment") or {}
        fields([("stored_cvss", assessment.get("cvss_score")), ("stored_epss_score", assessment.get("epss_score")),
                ("stored_epss_percentile", assessment.get("epss_percentile")), ("stored_kev", assessment.get("kev_status")),
                ("assessed_asset_criticality", assessment.get("asset_criticality")),
                ("stored_matched_rules", assessment.get("details", {}).get("matched_rules")),
                ("stored_reason", assessment.get("details", {}).get("reason"))])
    if not findings:
        story.append(p("N/A"))

    section(9, "CVE Verification Evidence")
    for finding in findings:
        story.append(p(f"{finding.get('cve_id')} / Finding {finding['vuln_id']}", subheading))
        if not finding.get("evidence"):
            story.append(p("MISSING - no stored verification or mapping evidence."))
        for evidence in finding.get("evidence", []):
            fields((key, evidence.get(key)) for key in ("evidence_id", "checker", "evidence_type", "sha256", "collected_at", "details_status", "parse_error"))
            fields(evidence.get("details", {}).items())
    if not findings:
        story.append(p("N/A"))

    section(10, "CVE Remediation History")
    for finding in findings:
        story.append(p(f"{finding.get('cve_id')} / Finding {finding['vuln_id']}", subheading))
        if not finding.get("history"):
            story.append(p("MISSING - no stored remediation history."))
        for event in finding.get("history", []):
            fields((key, event.get(key)) for key in ("from_status", "to_status", "action_type", "reason", "changed_by", "changed_at"))
    if not findings:
        story.append(p("N/A"))

    section(11, "CVE Risk Assessment / Provenance")
    for finding in findings:
        story.append(p(f"{finding.get('cve_id')} / Finding {finding['vuln_id']}", subheading))
        if not finding.get("assessment"):
            story.append(p("MISSING - effective priority is UNASSESSED."))
            continue
        if finding.get("assessment_freshness") != "CURRENT":
            story.append(p("Historical assessment below is STALE. Its stored priority/action are not current conclusions."))
        assessment = finding["assessment"]
        fields((key, value) for key, value in assessment.items() if key not in {"details", "provenance", "vuln_id"})
        fields(assessment.get("details", {}).items())
        for provider, metadata in assessment.get("provenance", {}).items():
            story.append(p(provider.upper() + " source", subheading))
            fields(metadata.items()) if isinstance(metadata, dict) else story.append(p("N/A"))
        story.append(p("CISA due_date is source metadata, not an SLA imposed on this organization."))
    if not findings:
        story.append(p("N/A"))

    if snapshot.get("lab_comparison"):
        comparison = snapshot["lab_comparison"]
        section(12, "Controlled Laboratory Comparison")
        fields([("baseline_scan_id", comparison.get("scan_ids", {}).get("LOCAL_BASELINE")),
                ("ec2_scan_id", comparison.get("scan_ids", {}).get("EC2_LAB")),
                ("scope", "Stored lab configuration observations only; missing means NOT_TESTED.")])
        story.append(p(comparison.get("disclaimer", "Independent environments; not remediation before/after.")))
        for env_name, group in comparison.get("environments", {}).items():
            story.append(p(env_name, subheading))
            for check, records in group.get("by_check", {}).items():
                if not records:
                    story.append(p(check + ": NOT_TESTED", small))
                    continue
                for row in records:
                    fields([("check", check), ("execution_status", row.get("execution_status")),
                            ("finding_status", row.get("finding_status")),
                            ("observed_at", row.get("observed_at")),
                            ("evidence_sha256", row.get("evidence_sha256")),
                            ("evidence_integrity", row.get("evidence_integrity")),
                            ("risk", row.get("risk")), ("recommendation", row.get("recommendation"))])
                    fields([("evidence", row.get("evidence"))])
        section(13, "Peer Environment CVE Findings")
        peer = snapshot.get("peer_report") or {}
        for scan in peer.get("scans", []):
            fields([("ec2_scan", scan)])
        for asset in peer.get("assets", []):
            story.append(p(asset.get("asset_name") or asset.get("asset_uid") or "Asset", subheading))
            for finding in asset.get("findings", []):
                fields([("cve_id", finding.get("cve_id")),
                        ("status", finding.get("status")),
                        ("effective_priority", finding.get("effective_priority")),
                        ("assessment_freshness", finding.get("assessment_freshness"))])
        story.append(p("Configuration findings never imply CVE confirmation. CVE details for both scans are preserved in the JSON snapshot."))

    section(14 if snapshot.get("lab_comparison") else 12, "Report Integrity")
    fields([("snapshot_sha256", snapshot.get("integrity", {}).get("snapshot_sha256")),
            ("digest_basis", "Canonical JSON with generated_at and integrity.snapshot_sha256 excluded."),
            ("integrity_limit", "The hash identifies snapshot content. It is not a signature or proof of source authenticity.")])

    def page_frame(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(42, 37, width - 42, 37)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(42, 25, "Infrastructure Security Review | Current-state snapshot")
        canvas.drawRightString(width - 42, 25, f"Page {doc.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=42, leftMargin=42,
                                 topMargin=42, bottomMargin=50, title="Infrastructure Security Review",
                                 author="Port Scanner", pageCompression=1)
    document.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return str(output_path)
