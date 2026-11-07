"""Preparation/offline import by default; opt-in fixed local Docker reads."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.linux_mysql_lab import LabInputError, PROFILES, audit, collect_docker, compare, load, synthetic_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description='Linux/MySQL personal LAB audit; no configuration changes')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--execute', action='store_true')
    source.add_argument('--input-json')
    source.add_argument('--demo', choices=('before','after'), help='Explicit synthetic fixtures, not actual diagnosis')
    parser.add_argument('--synthetic', action='store_true', help='Required for saved synthetic inputs')
    parser.add_argument('--baseline-json')
    parser.add_argument('--lab-profile', choices=tuple(PROFILES), default='current', help='Only the preserved current LAB or the separate replay LAB')
    parser.add_argument('--output')
    parser.add_argument('--pdf')
    args = parser.parse_args(argv)
    json_saved = False
    try:
        if args.synthetic and not args.input_json: raise LabInputError('synthetic_input_required')
        for path in (args.output, args.pdf):
            if path and (Path(path).exists() or Path(path).is_symlink()): raise LabInputError('new_output_path_required')
        if args.output and args.pdf and Path(args.output).resolve() == Path(args.pdf).resolve(): raise LabInputError('distinct_outputs_required')
        bundle = collect_docker(PROFILES[args.lab_profile]) if args.execute else load(args.input_json)[0] if args.input_json else synthetic_bundle(args.demo) if args.demo else None
        report = audit(bundle, synthetic=bool(args.demo or args.synthetic))
        if args.baseline_json:
            try: compare(report, args.baseline_json)
            except LabInputError as error:
                # A missing/invalid baseline must never discard current evidence.
                # Do not invent a baseline or silently report an improvement.
                report['comparison'] = {'status': 'UNAVAILABLE', 'error_code': str(error),
                    'results': [], 'summary': {}, 'baseline_not_substituted': True}
        # Persist current evidence before optional PDF generation.
        if args.output:
            with Path(args.output).open('x', encoding='utf-8') as stream: json.dump(report, stream, indent=2, ensure_ascii=False)
            json_saved = True
        if args.pdf:
            from config_audit.linux_mysql_report import write_pdf
            with Path(args.pdf).open('xb') as stream: write_pdf(report, stream)
        print(json.dumps({'mode': report['mode'], 'origin': report['origin'], 'summary': report['summary'],
            'json_saved': json_saved, 'comparison_status': report.get('comparison', {}).get('status', 'AVAILABLE' if 'comparison' in report else 'NOT_REQUESTED'),
            'comparison_error_code': report.get('comparison', {}).get('error_code'),
            'comparison_summary': report.get('comparison', {}).get('summary')}, ensure_ascii=False))
        return 0
    except LabInputError as e:
        print(json.dumps({'status': 'ERROR', 'error_code': str(e), 'json_saved': json_saved})); return 2
    except (OSError, ValueError, TypeError, ImportError):
        print(json.dumps({'status': 'ERROR', 'error_code': 'linux_mysql_audit_failed', 'json_saved': json_saved})); return 2


if __name__ == '__main__': raise SystemExit(main())
