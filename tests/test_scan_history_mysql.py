"""Opt-in V8 integration in a reviewer-owned isolated MySQL only.

No database/schema lifecycle commands here. The caller applies init/V7/V8 to its
own disposable database, supplies REVIEW_MYSQL_* and explicitly opts in. Existing
records are never deleted; each test uses a new identity namespace and run UIDs.
"""
import copy
from datetime import datetime, timedelta, timezone
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from db.save_scan_results import save_scan_results
from db.scan_history import ScanImportConflict, get_observations, read_snapshot, link_finding
from db.query_helpers import get_all_ports
from analysis.vuln_mapper import analyze_ports
from analysis.save_vulns import save_vulns
from api.analysis_report import build_report_snapshot


@unittest.skipUnless(os.environ.get('REVIEW_MYSQL_ISOLATED') == '1', 'Explicit isolated V8 MySQL not selected')
class IsolatedHistoryMySQLTests(unittest.TestCase):
    def test_storage_failure_rolls_back_then_saved_json_reimports_idempotently(self):
        import tempfile
        from pathlib import Path
        import contextlib, io, json
        from scanner.artifacts import write_scan_artifact
        from scripts.import_scan_results import main as import_main
        document=self.document([{'port':80,'protocol':'tcp','state':'closed'}])
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'observation.json'
            write_scan_artifact(document,path)
            original=path.read_bytes()
            with patch('db.save_scan_results.save_observation',side_effect=RuntimeError('injected_write_failure')):
                with self.assertRaises(RuntimeError):save_scan_results(document)
            with self.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT COUNT(*) FROM scans WHERE scan_uid=%s',(document['scan_id'],))
                    self.assertEqual(cur.fetchone()[0],0)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(import_main(['--input',str(path)]),0)
                self.assertEqual(import_main(['--input',str(path)]),0)
            self.assertEqual(path.read_bytes(),original)
            with self.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT COUNT(*) FROM scans WHERE scan_uid=%s',(document['scan_id'],))
                    self.assertEqual(cur.fetchone()[0],1)

    def connection(self):
        import mysql.connector
        host = os.environ['REVIEW_MYSQL_HOST']; port = int(os.environ['REVIEW_MYSQL_PORT'])
        if host != '127.0.0.1' or port == 3306:
            raise RuntimeError('Only an explicitly isolated loopback non-default MySQL port is accepted')
        return mysql.connector.connect(host=host, port=port, user=os.environ.get('REVIEW_MYSQL_USER', 'root'),
            password=os.environ['REVIEW_MYSQL_PASSWORD'], database=os.environ.get('REVIEW_MYSQL_DATABASE', 'port_scan'), autocommit=False)

    def document(self, rows, second=0):
        t = self.now + timedelta(seconds=second)
        return {'scan_id': 'history-review-' + uuid4().hex, 'scan_type': 'tcp+udp', 'asset_namespace': self.namespace,
            'time_basis': 'UTC', 'started_at': t.isoformat(), 'finished_at': (t + timedelta(milliseconds=10)).isoformat(),
            'port_range': ','.join(str(r['port']) for r in rows), 'requested_port_range': '53,80-83',
            'targets': [{'ip': '127.0.0.1', 'results': rows,
                         'coverage': {'requested_ports': [53,80,81,82,83], 'complete': all(r['state'] != 'not_tested' for r in rows)}}]}

    def setUp(self):
        self.now = datetime.now(timezone.utc); self.namespace = 'review/' + uuid4().hex
        self.stack = __import__('contextlib').ExitStack(); self.addCleanup(self.stack.close)
        for module in ('db.save_scan_results', 'db.query_helpers', 'analysis.save_vulns', 'api.analysis_report'):
            self.stack.enter_context(patch(module + '.get_connection', side_effect=self.connection))
        self.stack.enter_context(patch('db.save_scan_results.resolve_hostname', return_value=None))

    def test_history_roundtrip_idempotency_service_change_namespace_and_partial_scan(self):
        http = {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http',
            'product': 'apache_http_server', 'version': '2.4.49',
            'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nSet-Cookie: fixture-secret\r\n\r\n'}
        initial = self.document([http, {'port': 81, 'protocol': 'tcp', 'state': 'closed'},
            {'port': 53, 'protocol': 'udp', 'state': 'open|filtered'},
            {'port': 82, 'protocol': 'tcp', 'state': 'error', 'error_code': 'permission_denied'},
            {'port': 83, 'protocol': 'tcp', 'state': 'not_tested'}])
        first_id = save_scan_results(initial)
        self.assertEqual(save_scan_results(initial), first_id)
        changed_uid = copy.deepcopy(initial); changed_uid['targets'][0]['results'][0]['state'] = 'closed'
        with self.assertRaises(ScanImportConflict): save_scan_results(changed_uid)
        with self.connection() as conn:
            rows = get_observations(conn, scan_id=first_id)
            self.assertEqual(len(rows), 5)
            self.assertEqual({r['state'] for r in rows}, {'open','closed','open|filtered','error','not_tested'})
            self.assertNotIn('fixture-secret', str(rows)); self.assertNotIn('fixture-secret', str(read_snapshot(conn, first_id)))
            asset = rows[0]['asset_uid']
        candidates = analyze_ports(get_all_ports(scan_id=first_id))['candidates']
        self.assertEqual(len(candidates), 2)
        ids = save_vulns(candidates)
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE vulns SET status='CONFIRMED' WHERE id=%s", (ids[0],))
            link_finding(conn, ids[0], candidates[0]['observation_id'], relation='VERIFIED'); conn.commit()
        same = build_report_snapshot(asset_uid=asset)
        confirmed = next(f for f in same['assets'][0]['findings'] if f['vuln_id'] == ids[0])
        self.assertEqual(confirmed['historical_status'], 'CONFIRMED')
        self.assertEqual(confirmed['verification_relevance'], 'CURRENT')
        newer = self.document([{**http, 'product': 'nginx', 'version': '1.30.6',
            'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.30.6\r\n\r\n'}], 2)
        save_scan_results(newer)
        with self.connection() as conn:
            current = get_observations(conn, asset_uid=asset, current=True)
            self.assertEqual({r['port'] for r in current}, {53,80,81,82})
            old = get_observations(conn, scan_id=first_id)
            self.assertEqual(next(r for r in old if r['port'] == 80)['product'], 'apache_http_server')
        report = build_report_snapshot(asset_uid=asset)
        finding = next(f for f in report['assets'][0]['findings'] if f['vuln_id'] == ids[0])
        self.assertEqual(finding['status'], 'CONFIRMED')
        self.assertEqual(finding['current_relevance'], 'STALE')
        self.assertIsNone(finding['effective_status'])
        self.assertEqual(report['summary']['status_counts']['CONFIRMED'], 0)
        self.assertEqual(report['summary']['historical_status_counts']['CONFIRMED'], 1)
        replay = build_report_snapshot(scan_id=first_id)
        self.assertEqual(replay['history_capability'], 'IMMUTABLE_V8')
        self.assertEqual(next(p for p in replay['assets'][0]['ports'] if p['port'] == 80)['product'], 'apache_http_server')
        # An older run imported later is history, never the new current service.
        older = self.document([http], -5); save_scan_results(older)
        with self.connection() as conn:
            current = get_observations(conn, asset_uid=asset, current=True)
            self.assertEqual(next(r for r in current if r['port'] == 80)['product'], 'nginx')
        after_old_import=build_report_snapshot(asset_uid=asset)
        self.assertEqual(next(f for f in after_old_import['assets'][0]['findings'] if f['vuln_id']==ids[0])['current_relevance'],'STALE')
        legacy=self.document([http],5);legacy.pop('time_basis')
        legacy['started_at']='2099-01-01T15:00:00';legacy['finished_at']='2099-01-01T15:00:01'
        save_scan_results(legacy)
        with self.connection() as conn:
            current=get_observations(conn,asset_uid=asset,current=True)
            self.assertEqual(next(r for r in current if r['port']==80)['product'],'nginx')
        other = self.document([http], 3); other['asset_namespace'] = self.namespace + '/other-vpc'
        other_id = save_scan_results(other)
        with self.connection() as conn:
            separate = get_observations(conn, scan_id=other_id)
            self.assertNotEqual(separate[0]['asset_uid'], asset)
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM scan_port_observations WHERE scan_id=%s', (first_id,))
                self.assertEqual(cur.fetchone()[0], 5)


if __name__ == '__main__': unittest.main()
