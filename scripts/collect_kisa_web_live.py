"""Collect actual selected WEB/WAS evidence from the fixed existing Docker LAB."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.kisa_web_live import collect


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    raw, packet, report = collect()
    for name, data in [('web-live-raw.json', raw), ('observations.json', packet), ('assessment.json', report)]:
        with (args.output_dir/name).open('x', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    print(json.dumps(report['summary']))


if __name__ == '__main__':
    main()
