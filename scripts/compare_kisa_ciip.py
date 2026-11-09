"""Read-only selected KISA recommendation comparison of existing LAB reports.

Run from repo root:
python -m scripts.compare_kisa_ciip --linux-report <saved-json> --windows-report <saved-json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from config_audit.kisa_ciip_review import KisaReviewInputError, review

MAX_BYTES = 4 * 1024 * 1024


def _unique(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc:
            raise KisaReviewInputError("duplicate_json_key")
        doc[key] = value
    return doc


def load_report(path):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise KisaReviewInputError("input_size_limit")
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
        if not isinstance(doc, dict):
            raise KisaReviewInputError("invalid_report_shape")
        return doc, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, KisaReviewInputError):
            raise
        raise KisaReviewInputError("invalid_or_unavailable_json") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare selected KISA guide recommendations to saved LAB results without changing them")
    parser.add_argument("--linux-report", help="saved linux_mysql_lab.audit() JSON report")
    parser.add_argument("--windows-report", help="saved windows_lab.build_lab_view() JSON report")
    args = parser.parse_args(argv)
    if not args.linux_report and not args.windows_report:
        parser.error("provide at least one saved LAB report")
    try:
        linux = load_report(args.linux_report) if args.linux_report else None
        windows = load_report(args.windows_report) if args.windows_report else None
        result = review(linux=linux[0] if linux else None, windows=windows[0] if windows else None)
        result["input_sha256"] = {key: value[1] for key, value in (("linux", linux), ("windows", windows)) if value}
        # ASCII-safe JSON works on Windows consoles even when stdout is cp1252.
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
        return 0
    except KisaReviewInputError as exc:
        print("[ERROR] " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
