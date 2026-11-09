"""Adapt explicit Windows LAB exports; never label offline input VERIFIED_LAB."""
import argparse
import json
from pathlib import Path
from config_audit.kisa_2026 import PROFILE, assess
from config_audit.reporting import unique_object


def adapt(source, reference):
    if source.get('source') != 'current_standalone_windows_vm_secedit_export':
        raise ValueError('unexpected_windows_source')
    rows = source.get('results', [])
    if len(rows) != 1 or rows[0].get('check_id') != 'WIN-LAB-004':
        raise ValueError('unexpected_windows_checks')
    controls = source.get('after_controls', {})
    values = {'W-02': {k: controls.get(k) for k in ('guest_disabled', 'sid_501_identified')},
              'W-64': {'active_profiles': controls.get('active_profiles')},
              'W-04': rows[0].get('after_values'), 'W-08': rows[0].get('after_values')}
    return {'profile': PROFILE, 'observations': [dict(kisa_id=id, asset_id='windows',
        source_kind='SAVED_LAB', collection_status='COLLECTED', value=value,
        product_version=source.get('product_version'), collected_at=source.get('collected_at'),
        evidence_reference=reference) for id, value in values.items()]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path)
    args = p.parse_args()
    source = json.loads(args.input.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    print(json.dumps(assess(adapt(source, args.input.name)), ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
