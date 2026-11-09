"""Render an explicitly reviewed ledger; no collection or PASS promotion."""
import argparse
import json
from pathlib import Path
from config_audit.kisa_selected_report import write_pdf
from config_audit.reporting import unique_object


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=Path('docs/kisa-2026-final-scope-result.json'))
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = json.loads(args.input.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    with args.output.open('xb') as stream:
        write_pdf(report, stream)


if __name__ == '__main__':
    main()
