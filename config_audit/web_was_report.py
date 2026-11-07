"""Offline WEB/WAS PDF adapter using existing report font/escaping helpers."""
from .collectors.web_was import as_snapshot


def write_pdf(report, path):
    from api.report_pdf import _body_font, _text, NAVY, PALE, LINE
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak, KeepTogether
    font = _body_font()
    body = ParagraphStyle("WebBody", fontName=font, fontSize=9, leading=13, spaceAfter=7, wordWrap="CJK")
    title = ParagraphStyle("WebTitle", parent=body, fontSize=19, leading=26, textColor=NAVY, spaceAfter=12)
    head = ParagraphStyle("WebHead", parent=body, fontSize=13, leading=19, textColor=NAVY, spaceBefore=10)
    cell = ParagraphStyle("WebCell", parent=body, fontSize=8, leading=12)
    def p(text, style=body): return Paragraph(_text(text), style)
    def table(rows, widths):
        t = LongTable([[p(v, cell) for v in row] for row in rows], colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D8E8F2")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), .3, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        return t
    synthetic = report["origin"] == "synthetic"
    story = [p("WEB / WAS SECURITY LAB", title),
             p("합성 테스트 전용 - 실제 장비 진단 결과 아님" if synthetic else "실행 전 준비 보고서 - 실제 진단 미수행" if report["bundle"] is None else "로컬 Docker LAB 읽기 전용 진단" , head),
             p("Mode: LAB | Internal project criteria; no KISA certification claim."),
             p("Generated: " + report["generated_at"]),
             p("Collected: " + (report["bundle"]["collected_at"] if report["bundle"] else "NOT_TESTED")),
             p("Rule version: " + report["rule_version"]), p("Summary: " + str(report["summary"])),
             p("Nginx to Tomcat HTTP: " + report["http_verification"]["status"]), Spacer(1, 8),
             table([["Check", "Product / version", "Status", "LAB criterion"]] +
                   [[r["check_id"], r["product"] + " / " + str(r["version"] or "unknown"), r["status"], r["expected_condition"]] for r in report["results"]], [88, 105, 85, 233]),
             PageBreak(), p("OBSERVATIONS AND RETEST", title)]
    comparison = {r["check_id"]: r for r in report.get("comparison", {}).get("results", [])}
    for row in report["results"]:
        block = [p(row["check_id"] + " | " + row["status"], head), p("Observed: " + str(row["observed_value"])),
                  p("Method: " + row["verification_method"]), p("Recommendation: " + row["recommendation"])]
        if row["check_id"] in comparison:
            c = comparison[row["check_id"]]
            block += [p("Before: " + str(c["before_values"]) + " | After: " + str(c["after_values"])),
                      p("Transition: " + c["before_status"] + " -> " + c["after_status"] + " | " + c["comparison_result"])]
        story.append(KeepTogether(block))
    story += [p("SCOPE AND LIMITATIONS", head), p("Fixed LAB containers, explicit configuration and named HTTP paths only. Unknown values are never inferred as PASS."),
              p("Synthetic transitions are not completed remediation. Image pulls/builds and runtime checks require a separate user execution step."),
              p("Raw configurations, credentials, headers and log payloads are not included. A measured hash is not source authentication.")]
    def footer(canvas, doc):
        canvas.setFont(font, 8); canvas.drawString(42, 24, "Infrastructure Security Scanner | LAB")
        canvas.drawRightString(A4[0]-42, 24, str(doc.page))
    destination = path if hasattr(path, "write") else str(path)
    SimpleDocTemplate(destination, pagesize=A4, leftMargin=42, rightMargin=42, topMargin=36, bottomMargin=40).build(story, onFirstPage=footer, onLaterPages=footer)


def common_snapshot(report, snapshot_id):
    return as_snapshot(report, snapshot_id).to_dict()
