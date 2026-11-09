"""Frozen 16-item LAB profile. Offline evaluation is never proof of live origin.

Reuses AuditRule/Observation/evaluate; source files and historical LAB verdicts
are immutable inputs. No network, shell, configuration or cloud mutations.
"""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import re

from .engine import evaluate
from .models import AuditAsset, AuditRule, Observation
from .kisa_ciip_review import review_linux, review_windows

PROFILE = 'KISA-2026-SELECTED-1.0'
ROOT = Path(__file__).resolve().parents[1]
STATUSES = ('PASS', 'FAIL', 'NEEDS_REVIEW', 'NOT_TESTED', 'NOT_APPLICABLE', 'ERROR')
VERSIONS = {'linux': r'24\.04', 'windows': r'10\.0\.20348(?:\.[0-9]+)?',
            'nginx': r'1\.30\.6', 'tomcat': r'10\.1\.61', 'mysql': r'8\.4\.13'}


def catalog():
    return json.loads((ROOT / 'rules/kisa-2026-selected.json').read_text(encoding='utf-8'))


def flags(value, expected):
    """Unknown/missing fields cannot satisfy a criterion; false wins over missing."""
    if not isinstance(value, dict):
        return None
    checks = [value.get(key) is wanted if type(value.get(key)) is bool else None
              for key, wanted in expected.items()]
    return False if False in checks else None if None in checks else True


def condition(kisa_id, value):
    if not isinstance(value, dict):
        return None
    if kisa_id == 'U-18':
        report = {'mode': 'LAB', 'results': [{'check_id': 'LINUX-LAB-003',
                  'status': 'NEEDS_REVIEW', 'observed_value': [dict(value, path='/etc/shadow')]}]}
        status = review_linux(report)[0]['kisa_recommendation_result']
        return {'PASS': True, 'FAIL': False}.get(status)
    if kisa_id in ('W-04', 'W-08'):
        report = {'mode': 'LAB', 'results': [{'check_id': 'WIN-LAB-004',
                  'status': 'NEEDS_REVIEW', 'after_values': value}]}
        status = next(r for r in review_windows(report) if r['kisa_id'] == kisa_id)['kisa_recommendation_result']
        # A disabled threshold invalidates the duration's security effect too.
        if kisa_id == 'W-08' and (type(value.get('lockout_threshold')) is not int
                                 or value['lockout_threshold'] <= 0):
            return False if value.get('lockout_threshold') == 0 else None
        return {'PASS': True, 'FAIL': False}.get(status)
    if kisa_id == 'W-64':
        profiles = value.get('active_profiles')
        if not isinstance(profiles, dict) or set(profiles) != {'Domain', 'Private', 'Public'}:
            return None
        return flags(profiles, {name: True for name in profiles})
    return flags(value, catalog()['conditions'][kisa_id])


def assess(packet):
    """Evaluate declared observations, keeping synthetic/manual provenance visible.

    A caller's VERIFIED_LAB label is deliberately rejected. This offline adapter
    cannot authenticate equipment origin and never increments verified_lab_pass.
    """
    if not isinstance(packet, dict) or packet.get('profile') != PROFILE:
        raise ValueError('kisa_profile_invalid')
    supplied = packet.get('observations', [])
    if not isinstance(supplied, list):
        raise ValueError('kisa_observations_invalid')
    specs = catalog()['items']
    allowed = {(r['id'], asset) for r in specs for asset in r['assets']}
    indexed = {}
    for row in supplied:
        if not isinstance(row, dict):
            raise ValueError('kisa_row_invalid')
        key = (row.get('kisa_id'), row.get('asset_id'))
        if key not in allowed or key in indexed:
            raise ValueError('kisa_unknown_or_duplicate_target')
        if row.get('source_kind') not in ('SYNTHETIC', 'SAVED_LAB', 'MANUAL_LAB'):
            raise ValueError('kisa_source_kind_invalid')
        indexed[key] = row
    checked = datetime.now(timezone.utc)
    items = []
    for spec in specs:
        assets = []
        for asset_id in spec['assets']:
            source = indexed.get((spec['id'], asset_id), {})
            source_status = source.get('collection_status', 'NOT_TESTED')
            if source_status not in ('COLLECTED', 'NOT_TESTED', 'ERROR'):
                raise ValueError('kisa_collection_status_invalid')
            value = source.get('value') if source_status == 'COLLECTED' else None
            meta_ok = isinstance(source.get('product_version'), str) and bool(source['product_version'].strip())
            if asset_id in VERSIONS:
                meta_ok = meta_ok and re.fullmatch(VERSIONS[asset_id], source.get('product_version', '')) is not None
            try:
                time = datetime.fromisoformat(source.get('collected_at', ''))
                meta_ok = meta_ok and time.utcoffset() is not None and time <= checked
            except (ValueError, TypeError):
                meta_ok = False
            meta_ok = meta_ok and isinstance(source.get('evidence_reference'), str) and bool(source['evidence_reference'].strip())
            def predicate(v, item=spec['id'], valid=meta_ok):
                result = condition(item, v)
                return result if valid or result is False else None
            result = evaluate(AuditAsset(asset_id, asset_id, source.get('product_version')),
                AuditRule(spec['id'], PROFILE, spec['criterion'], spec['remediation'],
                          condition=predicate, standard_reference=f"KISA 2026 p.{spec['page']}"),
                Observation(value, source.get('evidence_reference'), source_status == 'ERROR'),
                execution_id='offline-selected-review', checked_at=checked)
            assets.append({**result.to_safe_dict(), 'product_version': source.get('product_version'),
                'collected_at': source.get('collected_at'), 'source_kind': source.get('source_kind'),
                'evidence_reference': source.get('evidence_reference'),
                'evidence_origin_verification': 'NOT_INDEPENDENTLY_VERIFIED'})
        # Every frozen asset must pass; no missing Tomcat hidden by passing Nginx.
        states = [r['status'] for r in assets]
        status = next((s for s in ('ERROR', 'FAIL', 'NEEDS_REVIEW', 'NOT_TESTED') if s in states), 'PASS')
        items.append({'kisa_id': spec['id'], 'title': spec['title'], 'page': spec['page'],
                      'status': status, 'assets': assets})
    return {'profile': PROFILE, 'mode': 'OFFLINE_REASSESSMENT', 'assessed_at': checked.isoformat(),
            'scope_denominator': 16, 'results': items,
            'summary': {s: Counter(r['status'] for r in items)[s] for s in STATUSES},
            'verified_lab_pass': 0, 'verified_lab_pass_percent': 0,
            'limitations': ['Offline observation verdicts are not authenticated live measurements.',
                           'Historical verified workflow results are tracked separately by run and asset.',
                           'No excluded discipline is counted as PASS.']}
