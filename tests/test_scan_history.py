"""Observation provenance and current relevance regressions; no network/real DB."""
import copy
from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import MagicMock, patch

from db.scan_history import (ScanImportConflict, db_timestamp, execution_digest, existing_execution,
                             identity_digest, namespace_for, safe_document)
from db.save_scan_results import determine_scan_status
from api.analysis_report import finding_relevance, json_value


class ScanHistoryContractTests(unittest.TestCase):
    def test_pdf_separates_stored_history_from_current_counts_and_prints_errors(self):
        import tempfile
        from pathlib import Path
        from pypdf import PdfReader
        from test_analysis_report import FixtureDB, ASSET
        from api.analysis_report import build_report_snapshot
        from api.report_pdf import render_report_pdf
        db=FixtureDB()
        db.data['ports'][0].update(product='nginx',version='1.30.6')
        db.data['findings'][0]['status']='CONFIRMED'
        with patch('api.analysis_report.get_connection',db.connect):snapshot=build_report_snapshot(asset_uid=ASSET)
        snapshot['assets'][0]['ports'].append({'port':19000,'protocol':'tcp','state':'error','reason':'permission_denied'})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.pdf';render_report_pdf(snapshot,path)
            text='\n'.join(page.extract_text() or '' for page in PdfReader(path).pages)
        self.assertIn('Stored CVE records',text)
        self.assertIn('CURRENTLY APPLICABLE FINDING COUNT',text)
        self.assertIn('permission_denied',text)
        self.assertEqual(snapshot['summary']['status_counts']['CONFIRMED'],0)

    def test_aware_kst_converts_to_utc_but_legacy_wall_clock_is_not_guessed(self):
        value = datetime(2026, 11, 19, 15, tzinfo=timezone(timedelta(hours=9)))
        self.assertEqual(db_timestamp(value, declared_basis='UTC'), datetime(2026, 11, 19, 6))
        self.assertEqual(db_timestamp('2026-11-19T15:00:00'), datetime(2026, 11, 19, 15))
        self.assertEqual(json_value(datetime(2026, 11, 19, 15)), '2026-11-19T15:00:00')
        self.assertEqual(json_value(value), '2026-11-19T06:00:00Z')
        with self.assertRaises(ValueError): db_timestamp('2026-11-19T15:00:00', declared_basis='UTC')

    def test_safe_import_does_not_retain_folded_session_headers_or_nested_secret(self):
        source = {'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nSet-Cookie: session=fixture-secret\r\n continuation-secret\r\n\r\n',
                  'fingerprint': {'Authorization': 'fixture-secret'}}
        result = safe_document(source)
        self.assertNotIn('fixture-secret', str(result)); self.assertNotIn('continuation-secret', str(result))
        self.assertIn('Apache/2.4.49', result['banner'])
        self.assertIn('fixture-secret', source['banner'])  # caller source not mutated

    def test_execution_digest_ignores_only_storage_receipt_not_observation_changes(self):
        source = {'scan_id': 'one', 'targets': [{'results': [{'port': 80, 'state': 'open'}]}]}
        receipt = copy.deepcopy(source); receipt['storage'] = {'history_capability': 'IMMUTABLE_V8'}
        self.assertEqual(execution_digest(source), execution_digest(receipt))
        receipt['targets'][0]['results'][0]['state'] = 'closed'
        self.assertNotEqual(execution_digest(source), execution_digest(receipt))

    def test_same_uid_different_execution_conflicts_before_mutation(self):
        conn = MagicMock(); cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = {'scan_id': 7, 'execution_sha256': 'original'}
        self.assertEqual(existing_execution(conn, 'one', 'original'), 7)
        with self.assertRaises(ScanImportConflict): existing_execution(conn, 'one', 'different')
        self.assertTrue(all(call.args[0].startswith('SELECT') for call in cursor.execute.call_args_list))

    def test_explicit_namespaces_are_stable_not_derived_from_current_scan(self):
        self.assertEqual(namespace_for({}), 'legacy')
        self.assertEqual(namespace_for({'asset_namespace': 'customer-a/aws/vpc-123'}), 'customer-a/aws/vpc-123')
        with self.assertRaises(ValueError): namespace_for({'asset_namespace': '../ space'})

    def test_observation_identity_ignores_http_date_but_tracks_product_and_banner_change(self):
        row = {'port': 80, 'protocol': 'tcp', 'state': 'open', 'product': 'apache_http_server', 'version': '2.4.49',
               'banner': 'HTTP/1.1 200 OK\r\nDate: first\r\nServer: Apache/2.4.49\r\n\r\n'}
        new = {**row, 'banner': row['banner'].replace('first', 'second')}
        self.assertEqual(identity_digest(row), identity_digest(new))
        self.assertNotEqual(identity_digest(row), identity_digest({**new, 'product': 'nginx'}))
        self.assertNotEqual(identity_digest(row), identity_digest({**new, 'banner': new['banner'].replace('200', '403')}))

    def test_errors_and_partial_attempts_affect_scan_completion(self):
        self.assertEqual(determine_scan_status([{'results': [{'state': 'closed'}]}]), 'COMPLETED')
        self.assertEqual(determine_scan_status([{'results': [{'state': 'error', 'error_code': 'permission'}]}]), 'FAILED')
        self.assertEqual(determine_scan_status([{'results': [{'state': 'open'}, {'state': 'unknown'}]}]), 'PARTIAL')
        self.assertEqual(determine_scan_status([{'results': [{'state': 'open|filtered'}]}]), 'COMPLETED')

    def test_udp_icmp_closed_is_a_completed_observation_not_collection_failure(self):
        from scanner.utils import socket_error
        import errno
        state, reason, code = socket_error(ConnectionRefusedError(errno.ECONNREFUSED, 'refused'), udp=True)
        self.assertEqual((state, reason, code), ('closed', 'icmp_port_unreachable', None))
        self.assertEqual(determine_scan_status([{'results': [{'state': state, 'error_code': code}]}]), 'COMPLETED')

    def test_service_replacement_missing_version_partial_and_closed_cannot_remain_current(self):
        finding = {'source': 'catalog:apache:cve-2021-42013', 'cve_id': 'CVE-2021-42013', 'status': 'CONFIRMED'}
        endpoint = {'state': 'open', 'product': 'apache_http_server', 'version': '2.4.50', 'last_scan_id': 3}
        self.assertEqual(finding_relevance(finding, endpoint, latest_asset_scan=3)[0], 'CURRENT')
        for change, expected in [({'product': 'nginx'}, 'STALE'), ({'version': '2.4.68'}, 'STALE'),
                                 ({'version': None}, 'NOT_REOBSERVED'), ({'state': 'closed'}, 'STALE'),
                                 ({'state': 'error'}, 'NOT_REOBSERVED')]:
            with self.subTest(change=change):
                self.assertEqual(finding_relevance(finding, {**endpoint, **change}, latest_asset_scan=3)[0], expected)
        self.assertEqual(finding_relevance(finding, endpoint, latest_asset_scan=4)[0], 'NOT_REOBSERVED')


if __name__ == '__main__': unittest.main()
