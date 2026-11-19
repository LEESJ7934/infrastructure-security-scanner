"""Evaluate explicit sanitized authenticated evidence offline; no collection."""
import argparse
import json
from pathlib import Path
from config_audit.supplemental import assess
from config_audit.reporting import unique_object
from asset_management.audit_binding import bind_audit_results


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--asset-bindings',type=Path,help='Explicit domain-ID to inventory-UUID crosswalk; no IP inference or DB writes')
    args=parser.parse_args(argv)
    try:
        with args.input.open('rb') as stream:raw=stream.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:raise ValueError('input_too_large')
        report=assess(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique_object))
        if args.asset_bindings:
            with args.asset_bindings.open('rb') as stream:binding=stream.read(2*1024*1024+1)
            if len(binding)>2*1024*1024:raise ValueError('bindings_too_large')
            report=bind_audit_results(report,json.loads(binding.decode('utf-8-sig'),object_pairs_hook=unique_object))
        # Exclusive creation: existing evidence and reports are never replaced.
        with args.output.open('x',encoding='utf-8') as stream:
            json.dump(report,stream,ensure_ascii=False,indent=2,allow_nan=False)
        return 0
    except (OSError,ValueError,TypeError,KeyError):
        print('supplemental_input_or_output_invalid')
        return 1


if __name__=='__main__':raise SystemExit(main())
