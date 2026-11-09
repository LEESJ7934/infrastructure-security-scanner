"""Synthetic rule boundaries and provenance, never reported as LAB measurements."""
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import unittest
from config_audit.kisa_2026 import PROFILE, assess, catalog, condition
from scripts.adapt_kisa_windows_selected import adapt


def observation(id, asset, value, **changes):
    row = dict(kisa_id=id, asset_id=asset, value=value, collection_status='COLLECTED',
               source_kind='SYNTHETIC', product_version={'windows': '10.0.20348', 'nginx': '1.30.6'}.get(asset, '24.04'),
               collected_at='2026-01-01T00:00:00Z', evidence_reference='synthetic-fixture')
    row.update(changes)
    return row


def packet(*rows):
    return {'profile': PROFILE, 'observations': list(rows)}


class SelectedProfileTests(unittest.TestCase):
    def test_frozen_scope_and_missing_targets(self):
        result = assess(packet())
        self.assertEqual(result['scope_denominator'], 16)
        self.assertEqual(result['summary']['NOT_TESTED'], 16)
        self.assertEqual(len({r['id'] for r in catalog()['items']}), 16)

    def test_each_required_boolean_missing_false_or_wrong_type(self):
        for id, flags in catalog()['conditions'].items():
            self.assertTrue(condition(id, flags), id)
            for key in flags:
                with self.subTest(id=id, key=key):
                    missing = dict(flags); del missing[key]
                    self.assertIsNone(condition(id, missing))
                    self.assertFalse(condition(id, dict(flags, **{key: False})))
                    self.assertIsNone(condition(id, dict(flags, **{key: 1})))

    def test_shadow_permissions_and_types(self):
        base = dict(uid=0, mode=0o400, regular=True, symlink=False)
        self.assertTrue(condition('U-18', base))
        for mode in (0o640, 0o044, 0o401, -1):
            self.assertFalse(condition('U-18', dict(base, mode=mode)))
        self.assertIsNone(condition('U-18', dict(base, uid=False)))

    def test_lockout_boundaries(self):
        for n, expected in ((0, False), (1, True), (5, True), (6, False)):
            self.assertIs(condition('W-04', dict(lockout_threshold=n)), expected)
        base = dict(lockout_threshold=5, lockout_duration=60, reset_minutes=60)
        self.assertTrue(condition('W-08', base))
        for key in ('lockout_duration', 'reset_minutes'):
            self.assertFalse(condition('W-08', dict(base, **{key: 59})))
        self.assertFalse(condition('W-08', dict(base, lockout_threshold=0)))

    def test_all_effective_firewall_profiles_required(self):
        profiles = dict(Domain=True, Public=True, Private=True)
        self.assertTrue(condition('W-64', dict(active_profiles=profiles)))
        self.assertFalse(condition('W-64', dict(active_profiles=dict(profiles, Public=False))))
        self.assertIsNone(condition('W-64', dict(active_profiles={'Public': True})))

    def test_metadata_missing_never_passes_and_preserves_input(self):
        row = observation('W-02', 'windows', dict(guest_disabled=True, sid_501_identified=True))
        original = deepcopy(row)
        for key in ('collected_at', 'product_version', 'evidence_reference'):
            bad = dict(row); del bad[key]
            result = assess(packet(bad))
            self.assertEqual(result['summary']['NEEDS_REVIEW'], 1)
        self.assertEqual(original, row)
        self.assertEqual(assess(packet(row))['verified_lab_pass'], 0)
        self.assertEqual(assess(packet(row))['summary']['PASS'], 1)
        self.assertEqual(assess(packet(dict(row, product_version='unknown')))['summary']['NEEDS_REVIEW'], 1)

    def test_errors_take_precedence_and_synthetic_is_not_verified(self):
        row = observation('W-02', 'windows', dict(guest_disabled=True, sid_501_identified=True), collection_status='ERROR')
        self.assertEqual(assess(packet(row))['summary']['ERROR'], 1)
        with self.assertRaises(ValueError):
            assess(packet(dict(row, source_kind='VERIFIED_LAB')))

    def test_duplicate_unknown_and_wrong_profile_rejected(self):
        row = observation('W-02', 'windows', {})
        for data in (packet(row, row), packet(dict(row, asset_id='customer-production')),
                     packet(dict(row, kisa_id='N-06')), dict(profile='KISA-2025')):
            with self.assertRaises(ValueError):
                assess(data)

    def test_nginx_cannot_hide_uncollected_tomcat(self):
        row = observation('WEB-04', 'nginx', catalog()['conditions']['WEB-04'])
        result = assess(packet(row))
        web = next(r for r in result['results'] if r['kisa_id'] == 'WEB-04')
        self.assertEqual(web['status'], 'NOT_TESTED')
        self.assertEqual(web['assets'][0]['status'], 'PASS')

    def test_four_windows_controls_adapter(self):
        source = dict(source='current_standalone_windows_vm_secedit_export',
            product_version='10.0.20348', collected_at='2026-01-01T00:00:00Z',
            after_controls=dict(guest_disabled=True, sid_501_identified=True,
                                active_profiles=dict(Domain=True, Private=True, Public=True)),
            results=[dict(check_id='WIN-LAB-004', after_values=dict(lockout_threshold=5, lockout_duration=60, reset_minutes=60))])
        result = assess(adapt(source, 'synthetic-export.json'))
        self.assertEqual(result['summary']['PASS'], 4)
        self.assertEqual(result['summary']['NOT_TESTED'], 12)
        self.assertEqual(result['verified_lab_pass'], 0)

    def test_pdf_preserves_ledger_counts_and_incomplete_states(self):
        from config_audit.kisa_selected_report import write_pdf
        from pypdf import PdfReader
        ledger = json.loads((Path(__file__).resolve().parents[1] / 'docs/kisa-2026-final-scope-result.json').read_text(encoding='utf-8'))
        stream = BytesIO()
        write_pdf(ledger, stream)
        text = '\n'.join(p.extract_text() for p in PdfReader(stream).pages)
        self.assertIn('37.5%', text)
        self.assertIn('WEB-04 | NOT_TESTED', text)
        self.assertIn('CA-09 | NOT_TESTED', text)
        self.assertIn('W-64 | PASS', text)

    def test_pdf_rejects_wrong_denominator_or_promoted_offline_sources(self):
        from config_audit.kisa_selected_report import write_pdf
        ledger = json.loads((Path(__file__).resolve().parents[1] / 'docs/kisa-2026-final-scope-result.json').read_text(encoding='utf-8'))
        for kind in ('count', 'source', 'id'):
            bad = deepcopy(ledger)
            if kind == 'count': bad['summary']['PASS'] = 16
            elif kind == 'source': bad['results'][0]['source_kind'] = 'SYNTHETIC'
            else: bad['results'][0]['kisa_id'] = 'N-06'
            with self.assertRaises(ValueError):
                write_pdf(bad, BytesIO())


if __name__ == '__main__':
    unittest.main()
