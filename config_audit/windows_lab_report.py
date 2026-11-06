"""Portfolio-focused LAB PDF; strict evidence review is an advanced section."""
import json
from xml.sax.saxutils import escape

from .windows_lab import MANUAL_KEYS


def write_lab_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="LabBody", fontName="Helvetica", fontSize=9, leading=13, spaceAfter=7))
    styles.add(ParagraphStyle(name="LabCell", fontName="Helvetica", fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="LabHeader", parent=styles["LabCell"], textColor=colors.white))
    def p(value, style="LabBody"): return Paragraph(escape(str(value)), styles[style])
    def table(rows, widths):
        result = Table([[p(value, "LabHeader" if i == 0 else "LabCell") for value in row] for i, row in enumerate(rows)],
                       colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eef4f7"), colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
        return result
    def shown(row, value):
        if value is None: return "Not collected"
        if row["check_id"] == "WIN-LAB-009": return "GUID evidence missing" if not value.get("subcategories") else "GUID masks captured"
        if row["check_id"] == "WIN-LAB-005" and value.get("present") is False:
            features = [value.get(key) for key in ("print_services_installed", "print_server_installed")]
            feature_text = "absent" if all(item is False for item in features) else "installed" if any(item is True for item in features) else "not confirmed"
            return "Spooler absent; print features " + feature_text + "; printing " + ("unnecessary" if value.get("required") is False else "need not confirmed")
        keep = MANUAL_KEYS[row["check_id"]]
        return "; ".join(key + "=" + ("unknown" if item is None else str(item)) for key, item in value.items() if key in keep) or "Not confirmed"
    progress = {"LAB_REMEDIATION_AND_RETEST_COMPLETE": "Remediated + retested",
                "UNCHANGED_PASS": "Compliant maintained", "CURRENT_LAB_PASS": "Current setting confirmed",
                "ACTION_REQUIRED": "Action required", "NOT_VERIFIED": "Not verified"}
    source = {"automatic_saved_json":"Automatic JSON", "user_powershell_confirmation":"User PowerShell",
              "combined_automatic_and_manual":"JSON + user confirmation"}
    story = [p("WINDOWS SERVER 2022", "Title"), p("PERSONAL LAB | SECURITY IMPROVEMENTS", "Heading2"),
        p("Saved VM exports and user-confirmed PowerShell checks. Internal LAB criteria only; not KISA or customer certification."),
        p("PASS: " + str(report["summary"].get("PASS", 0)) + " / 9     FAIL: " + str(report["summary"].get("FAIL", 0)) +
          "     Pending: " + str(9-report["summary"].get("PASS",0)-report["summary"].get("FAIL",0)), "Heading2"),
        p(str(report["remediation_completed_count"]) + " remediation and retest scenarios completed under personal LAB criteria."),
        p("Generated: " + report["generated_at"] + " | Rule version: " + report["criteria"]["rule_version"]), Spacer(1, 8)]
    story += [table([["Check", "Personal LAB criterion", "Status", "Verification method"]] +
                    [[row["check_id"], row["criterion"], row["status"], source[row["assessment_basis"]]] for row in report["results"]],
                    [75, 235, 87, 110]), Spacer(1, 10),
        p("No organization approval document is required in LAB mode. Unknown settings stay unverified. Strict comparison remains available separately."),
        PageBreak(), p("BEFORE / AFTER | SETTINGS", "Title")]
    story += [table([["Check", "Before settings", "After settings", "LAB outcome / method"]] +
        [[row["check_id"], shown(row,row["before_values"]), shown(row,row["after_values"]),
          progress[row["lab_remediation_status"]] + "; " + source[row["assessment_basis"]]] for row in report["results"]],
        [75, 145, 150, 137]), Spacer(1, 10),
        p("Unknown values are preserved as unknown. Manual and automatic details are separately available in the JSON and source-channel section.")]
    story += [PageBreak(), p("REMEDIATION AND RETEST", "Title")]
    for row in report["results"]:
        if not row["remediation_complete"]: continue
        story += [p(row["check_id"] + " - COMPLETE (user-confirmed LAB retest)", "Heading2"),
            p(shown(row, row["before_values"]) + "  ->  " + shown(row, row["after_values"])),
            p("Source: user PowerShell confirmation. Automatic saved values remain in their original channel.")]
    story += [p("The SMB signing baseline is an earlier manual scenario. The newer JSON baseline already has signing enabled; it was not rewritten to False."),
        p("Manual test timestamps are unspecified and have not been invented. The original PowerShell transcript is not attached."),
        p("AUDIT SETTINGS | PENDING ACTUAL VALUES", "Heading2")]
    audit = next(row for row in report["results"] if row["check_id"] == "WIN-LAB-009")
    story += [table([["Subcategory", "Success / failure required", "Actual result"]] +
        [[row["name"], str(row["expected"]["success"]) + " / " + str(row["expected"]["failure"]), row["status"]]
         for row in audit["audit_subcategories"]], [190, 190, 127]),
        p("Collect the five GUID-based system policy masks. Failures will be listed per subcategory; only settings meeting the LAB criteria can become PASS."),
        PageBreak(), p("AUTOMATIC / MANUAL CHANNELS", "Title"),
        p("User confirmation fills the LAB assessment, not missing fields in the original JSON. Conflicting current values block a LAB PASS.")]
    story += [table([["Check", "Automatic after status", "LAB after status", "Source"]] +
        [[row["check_id"], row["automatic"]["after"]["status"], row["status"], source[row["assessment_basis"]]]
        for row in report["results"]], [75, 140, 100, 192]), Spacer(1, 12),
        p("ADVANCED VERIFICATION | STRICT MODE PRESERVED", "Heading2")]
    advanced = report.get("advanced_validation", {})
    if "comparison" in advanced:
        story += [p("Strict comparison summary: " + json.dumps(advanced["comparison"]["summary"], sort_keys=True)),
            p("DRAFT approval, independent expected hashes and exact timestamps affect this advanced view, not the personal LAB result.")]
        for side, item in zip(("Before", "After"), advanced["source_results"]):
            story += [p(side + " capture: " + str(item["results"][0]["collected_at"]) + " | Integrity: " + item["integrity"]),
                      p("Measured SHA-256: " + str(item["sha256"]))]
    story += [p("Full strict results, original automatic observations, manual scenarios, per-field source labels and audit requirements are included in the JSON report."),
              p("Windows settings and the original exports were not modified by report generation.")]
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont("Helvetica", 8); canvas.setFillColor(colors.HexColor("#526274"))
        canvas.drawString(44, 25, "Infrastructure Security Scanner | Personal LAB portfolio")
        canvas.drawRightString(A4[0]-44, 25, str(doc.page)); canvas.restoreState()
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=44, rightMargin=44, topMargin=38, bottomMargin=42).build(story, onFirstPage=footer, onLaterPages=footer)
