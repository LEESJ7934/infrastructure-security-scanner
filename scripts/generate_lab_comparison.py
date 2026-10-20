"""Export recorded laboratory configuration checks. Does not scan or contact targets."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from db.lab_repository import read_observations


CHECKS = ("FTP_ANONYMOUS", "SSH_AUTH_POLICY", "HTTP_SECURITY_HEADERS", "DVWA_SQLI", "NUCLEI")


def _render_row(row):
    details = row["evidence_json"]
    if isinstance(details, (bytes, str)):
        details = json.loads(details)
    canonical = json.dumps(details, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    actual = hashlib.sha256(canonical.encode()).hexdigest()
    return {
        "check": row["check_name"], "asset_uid": row["asset_uid"],
        "environment": row["environment_label"], "execution_status": row["execution_status"],
        "finding_status": row["finding_status"], "observed_at": str(row["observed_at"]),
        "evidence_sha256": row["evidence_sha256"],
        "evidence_integrity": "MATCH" if actual == row["evidence_sha256"] else "MISMATCH",
        "evidence": details,
    }


def build_comparison(rows):
    """No observed service / no row is UNKNOWN, never safe."""
    rendered = [_render_row(r) for r in rows]
    by_env = {}
    for environment in ("LOCAL_BASELINE", "EC2_LAB"):
        items = [r for r in rendered if r["environment"] == environment]
        by_env[environment] = {
            "observations": items,
            "by_check": {
                name: [r for r in items if r["check"] == name] for name in CHECKS
            },
            "coverage": {name: "OBSERVED" if any(r["check"] == name for r in items)
                         else "NOT_TESTED" for name in CHECKS}
        }
    return {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": "Recorded results only. No record is NOT_TESTED, never a safe verdict. No CVE is proven by a configuration result.",
            "environments": by_env}


def export_report(data, output_json, output_pdf=None):
    output_json = Path(output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if output_pdf:
        from api.report_pdf import _body_font
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from xml.sax.saxutils import escape
        font = _body_font()
        style = ParagraphStyle("LabEvidence", fontName=font, fontSize=9, leading=13,
                               spaceAfter=7, wordWrap="CJK")
        story = [Paragraph("Laboratory Configuration Comparison", style), Spacer(1, 12)]
        for env, item in data["environments"].items():
            story.append(Paragraph(escape(env), style))
            for check, records in item["by_check"].items():
                if not records:
                    story.append(Paragraph(escape(check + ": NOT_TESTED"), style))
                for record in records:
                    # Render a bounded summary without exposing raw credentials or cookies.
                    detail = f"{check}: {record['execution_status']} / {record['finding_status']} / hash {record['evidence_sha256']} / integrity {record['evidence_integrity']}"
                    story.append(Paragraph(escape(detail), style))
        story.append(Paragraph("Observation absence never proves safety. Review individual evidence in JSON.",style))
        target = Path(output_pdf)
        target.parent.mkdir(parents=True,exist_ok=True)
        SimpleDocTemplate(str(target), pagesize=A4).build(story)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--scan-id", type=int)
    selection.add_argument("--asset-id")
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--pdf", type=Path)
    args = parser.parse_args(argv)
    rows = read_observations(scan_id=args.scan_id,asset_uid=args.asset_id)
    data = build_comparison(rows)
    export_report(data,args.json,args.pdf)
    print(json.dumps({"json": str(args.json), "pdf": str(args.pdf) if args.pdf else None,
                      "observation_count": len(rows)},ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
