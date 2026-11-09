"""Generate offline integrated JSON/PDF artifacts; no VM, DB, API or collector calls."""

import argparse
import json
from pathlib import Path
import sys

from config_audit.final_report import FinalReportError, generate_final_report


class ReportParser(argparse.ArgumentParser):
    def error(self, message):
        raise FinalReportError("arguments_invalid")


def main(argv=None):
    parser = ReportParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, help="Project reports/ subdirectory; defaults to reports/day5")
    try:
        args = parser.parse_args(argv)
        result = generate_final_report(args.project_root, args.output_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 2 if result['completion_status'] == 'PARTIAL' else 0
    except Exception:
        # Do not echo OS paths, raw responses or credential-bearing input errors.
        print(json.dumps({"error_code": "day5_report_failed", "message": "오프라인 입력·폰트·출력 경로를 확인하세요."}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
