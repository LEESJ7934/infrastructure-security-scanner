"""Opt-in populated V7 upgrade in a new schema of a disposable review MySQL.

Requires explicit REVIEW_MYSQL_ISOLATED=1 and loopback non-default port. Creates
only a random review_upgrade_* schema; never migrates the configured database.
The owner disposes of the entire temporary review container after validation.
"""
from datetime import datetime
import os
from pathlib import Path
import unittest
from uuid import uuid4


@unittest.skipUnless(os.environ.get('REVIEW_MYSQL_ISOLATED')=='1','Explicit disposable migration MySQL not selected')
class PopulatedV7MigrationTests(unittest.TestCase):
    def test_upgrade_preserves_legacy_review_times_and_does_not_fabricate_observations(self):
        import mysql.connector
        from db.query_helpers import insert_scan, upsert_host, upsert_port, upsert_vuln
        from db.scan_history import supports_history
        from api.analysis_report import json_value
        host=os.environ['REVIEW_MYSQL_HOST'];port=int(os.environ['REVIEW_MYSQL_PORT'])
        if host!='127.0.0.1' or port==3306:raise RuntimeError('Disposable loopback non-default DB required')
        args=dict(host=host,port=port,user=os.environ.get('REVIEW_MYSQL_USER','root'),password=os.environ['REVIEW_MYSQL_PASSWORD'],autocommit=False)
        schema='review_upgrade_'+uuid4().hex
        root=Path(__file__).resolve().parents[1]
        with mysql.connector.connect(**args) as conn:
            with conn.cursor() as cur:
                for name in ('init.sql','migration_v7.sql'):
                    sql=(root/'sql'/name).read_text(encoding='utf-8-sig').replace('port_scan',schema)
                    cur.execute(sql)
                    while cur.nextset():pass
            at=datetime(2026,11,19,15,0,0)
            scan=insert_scan(conn,'legacy-'+uuid4().hex,'127.0.0.1','tcp','80',at,at,'COMPLETED')
            asset=upsert_host(conn,'127.0.0.1',last_scan_id=scan)
            endpoint=upsert_port(conn,asset,80,'tcp',service='http',version='2.4.49',banner='HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n',last_scan_id=scan,state='open',product='apache_http_server')
            finding=upsert_vuln(conn,endpoint,'CVE-2021-42013','Legacy confirmed fixture','CRITICAL',status='CONFIRMED',source='catalog:apache:cve-2021-42013')
            conn.commit()
            self.assertFalse(supports_history(conn))
            with conn.cursor() as cur:
                cur.execute((root/'sql/migration_v8.sql').read_text(encoding='utf-8-sig'))
                while cur.nextset():pass
            conn.commit()
        with mysql.connector.connect(database=schema,**args) as conn:
            self.assertTrue(supports_history(conn))
            with conn.cursor() as cur:
                cur.execute('SELECT status FROM vulns WHERE id=%s',(finding,));self.assertEqual(cur.fetchone()[0],'CONFIRMED')
                cur.execute('SELECT started_at FROM scans WHERE id=%s',(scan,));saved=cur.fetchone()[0]
                self.assertEqual(saved,at);self.assertNotIn('Z',json_value(saved))
                cur.execute('SELECT asset_namespace FROM hosts WHERE id=%s',(asset,));self.assertEqual(cur.fetchone()[0],'legacy')
                for table in ('scan_run_snapshots','scan_port_observations','finding_observation_links'):
                    cur.execute('SELECT COUNT(*) FROM '+table);self.assertEqual(cur.fetchone()[0],0)


if __name__=='__main__':unittest.main()
