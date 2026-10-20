"""Final-stage safety gates and same-service retest composition; no AWS access."""
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from db.lab_repository import make_observation
from scripts.generate_lab_comparison import build_comparison
from scripts.prepare_nuclei import prepare
from scripts.run_lab_special import run_special
from scripts.verify_safe_sql_baseline import verify_safe_lookup
from verification.reviewed_nuclei import execute_reviewed, NucleiExecutionError
from test_import_ec2_dvwa_evidence import SCOPE, PORT


class FinalNucleiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / 'safe.yaml').write_text('id: safe\n')
        (base / 'nuclei').write_bytes(b'test binary')
        self.params = dict(nuclei_binary=str(base/'nuclei'), template_root=str(base),
                           template_allowlist={'safe.yaml': hashlib.sha256(b'id: safe\n').hexdigest()},
                           template_name='safe.yaml', origin='http://127.0.0.1:8080',
                           approved_ips={'127.0.0.1'}, expected_binary_sha256=hashlib.sha256(b'test binary').hexdigest())
        self.row = {'template-id': 'safe', 'info': {'severity': 'info'}, 'matched-at': 'http://127.0.0.1:8080/'}

    def responses(self, row=None):
        return [subprocess.CompletedProcess([],0,'v3.11.1',''),
                subprocess.CompletedProcess([],0,json.dumps(row or self.row),'')]

    @patch('verification.reviewed_nuclei.subprocess.run')
    def test_binary_hash_before_any_process(self, run):
        with self.assertRaises(ValueError): execute_reviewed(**{**self.params, 'expected_binary_sha256': '0'*64})
        run.assert_not_called()

    @patch('verification.reviewed_nuclei.subprocess.run')
    def test_wrong_version_prevents_scan(self, run):
        run.return_value = subprocess.CompletedProcess([],0,'v9.0.0','')
        with self.assertRaises(NucleiExecutionError): execute_reviewed(**self.params)
        self.assertEqual(run.call_count,1)

    @patch('verification.reviewed_nuclei.subprocess.run')
    def test_jsonl_matches_selected_origin_and_omits_raw_secrets(self, run):
        self.row['response'] = 'fake-sensitive-response'
        run.side_effect = self.responses()
        result = execute_reviewed(**self.params)
        self.assertEqual(result['finding_status'],'POTENTIAL')
        self.assertEqual(result['version_output'],'v3.11.1')
        self.assertNotIn('fake-sensitive', str(result))
        self.assertFalse(result['raw_jsonl_retained'])
        for flag in ('-disable-redirects','-omit-raw','-no-stdin'):
            self.assertIn(flag, run.call_args.args[0])

    @patch('verification.reviewed_nuclei.subprocess.run')
    def test_wrong_template_port_host_query_are_rejected(self, run):
        rows = [{**self.row, 'template-id':'other'}] + [
            {**self.row,'matched-at':x} for x in ('http://127.0.0.1:8081/', 'http://192.0.2.1:8080/',
                                               'http://127.0.0.1:8080/?token=private')]
        for row in rows:
            run.side_effect = self.responses(row)
            with self.subTest(row=row), self.assertRaises(NucleiExecutionError): execute_reviewed(**self.params)

    @patch('verification.reviewed_nuclei.subprocess.run')
    def test_timeout_and_nonzero_are_not_secure(self, run):
        for response in (subprocess.TimeoutExpired('nuclei',1), subprocess.CompletedProcess([],1,'','')):
            run.side_effect = [self.responses()[0], response]
            result = execute_reviewed(**self.params)
            self.assertEqual((result['execution_status'],result['finding_status']),('ERROR','INCONCLUSIVE'))

    @patch('scripts.run_lab_special.get_all_ports', return_value=[PORT])
    @patch('scripts.run_lab_special.insert_observation', return_value=8)
    @patch('scripts.run_lab_special.execute_reviewed')
    def test_sanitized_jsonl_export_hash_is_bound_to_v7(self, execute, insert, ports):
        execute.return_value = {'execution_status':'SUCCESS','finding_status':'POTENTIAL',
                                'reason':'reviewed match','results':[{'template_id':'safe','severity':'info','matched_at_sha256':'a'*64}]}
        output = Path(self.tmp.name)/'result.jsonl'
        run_special(scope=SCOPE,scan_id=7,port_id=PORT['port_id'],environment='EC2_LAB',check='NUCLEI',
                    nuclei_binary='mocked',template_root='lab/nuclei',template_name='safe.yaml',reviewed_sha256='a'*64,
                    jsonl_output=output)
        evidence = json.loads(insert.call_args.args[0]['evidence_json'])
        self.assertEqual(evidence['details']['sanitized_jsonl_sha256'],hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(json.loads(output.read_text())['template_id'],'safe')

    def test_archive_mismatch_never_extracts(self):
        file = Path(self.tmp.name)/'fake.zip'
        file.write_bytes(b'not official')
        with self.assertRaises(ValueError): prepare(file,Path(self.tmp.name)/'out','linux_amd64')
        self.assertFalse((Path(self.tmp.name)/'out').exists())

    def test_verified_archive_extracts_only_expected_binary_and_preserves_existing(self):
        file = Path(self.tmp.name)/'fixture.zip'
        with zipfile.ZipFile(file,'w') as package:
            package.writestr('nuclei',b'fixture only')
            package.writestr('../unwanted',b'unwanted')
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        with patch.dict('scripts.prepare_nuclei.ARCHIVES',linux_amd64=digest):
            out = prepare(file,Path(self.tmp.name)/'out','linux_amd64')
            self.assertEqual(out['binary_sha256'],hashlib.sha256(b'fixture only').hexdigest())
            self.assertFalse((Path(self.tmp.name)/'unwanted').exists())
            with self.assertRaises(ValueError): prepare(file,Path(self.tmp.name)/'out','linux_amd64')

    @patch('scripts.run_lab_special.get_all_ports', return_value=[PORT])
    @patch('scripts.run_lab_special.insert_observation', return_value=8)
    @patch('scripts.run_lab_special.execute_reviewed', side_effect=ValueError('untrusted binary'))
    def test_runner_records_failure_as_not_tested_coverage(self, execute, insert, ports):
        result = run_special(scope=SCOPE,scan_id=7,port_id=PORT['port_id'],environment='EC2_LAB',check='NUCLEI',
                             nuclei_binary='not-executed',template_root='lab/nuclei',template_name='safe.yaml',reviewed_sha256='a'*64)
        self.assertEqual(result['execution_status'],'ERROR')
        report = build_comparison([insert.call_args.args[0]])
        self.assertEqual(report['environments']['EC2_LAB']['coverage']['NUCLEI'],'NOT_TESTED')


class RetestTests(unittest.TestCase):
    def rows(self):
        values = []
        for index,finding in enumerate(('CONFIRMED','NOT_DETECTED')):
            row = make_observation(port={**PORT,'port':21,'service':'ftp'},environment='EC2_LAB',
                check_name='FTP_ANONYMOUS',scope=SCOPE,
                observed_at=datetime(2026,10,20,10,index),
                result={'status':'POTENTIAL','details':{'finding_status':finding,
                        'remediation_context':{'runtime':'GITHUB_ACTIONS_DISPOSABLE_DOCKER'} if index else None}})
            values.append(row)
        return values

    def test_same_service_change_preserves_both_hashes_and_times(self):
        rows = self.rows()
        changes = build_comparison(rows)['retests']
        self.assertEqual(len(changes),1)
        self.assertEqual(changes[0]['before']['evidence_sha256'],rows[0]['evidence_sha256'])
        self.assertEqual(changes[0]['after']['evidence_sha256'],rows[1]['evidence_sha256'])
        self.assertEqual(changes[0]['change_record']['runtime'],'GITHUB_ACTIONS_DISPOSABLE_DOCKER')

    def test_different_scan_port_asset_environment_check_never_pair(self):
        for key,value in (('scan_id',8),('port_id',99),('asset_uid','other'),('environment_label','LOCAL_BASELINE'),('check_name','HTTP_SECURITY_HEADERS')):
            rows = self.rows()
            rows[1][key] = value
            self.assertEqual(build_comparison(rows)['retests'],[])

    def test_tampered_failed_or_simultaneous_retest_not_claimed(self):
        for key,value in (('evidence_sha256','0'*64),('execution_status','ERROR'),('observed_at',datetime(2026,10,20,10,0))):
            rows = self.rows()
            rows[1][key] = value
            self.assertEqual(build_comparison(rows)['retests'],[])

    def test_retest_pdf_shows_changes_and_docker_context(self):
        from api.report_pdf import render_report_pdf
        from test_generate_report import pdf_drawn_text
        rows = self.rows()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'retest.pdf'
            render_report_pdf({'assets':[],'scans':[],'runtime_context':'GITHUB_ACTIONS_DISPOSABLE_DOCKER',
                               'lab_comparison':build_comparison(rows)},path)
            text = pdf_drawn_text(path.read_bytes())
            for value in ('Same-service retest history','GITHUB_ACTIONS_DISPOSABLE_DOCKER',
                          'CONFIRMED','NOT_DETECTED',rows[0]['evidence_sha256'],rows[1]['evidence_sha256']):
                self.assertIn(value,text)

    def test_independent_sql_evidence_rejects_secrets_and_wrong_scan(self):
        from scripts.verify_safe_sql_baseline import validate_evidence
        data = {'application':'separate_parameterized_sqlite_lab','comparison_type':'INDEPENDENT_APPLICATION',
                'dvwa_remediated':False,'finding_status':'NOT_DETECTED','scan_id':11,'environment':'LOCAL_BASELINE',
                'steps':[{'label':label,'http_status':200,'result_rows':rows,'response_sha256':'a'*64}
                         for label,rows in (('normal',1),('injection_shaped',0))]}
        validate_evidence(data,11)
        with self.assertRaises(ValueError): validate_evidence(data,12)
        with self.assertRaises(ValueError): validate_evidence({**data,'cookie':'test'},11)

    def test_inconclusive_is_not_tested(self):
        row = make_observation(port=PORT,environment='EC2_LAB',check_name='NUCLEI',scope=SCOPE,
            result={'status':'POTENTIAL','details':{'finding_status':'INCONCLUSIVE'}})
        self.assertEqual(build_comparison([row])['environments']['EC2_LAB']['coverage']['NUCLEI'],'NOT_TESTED')

    @patch('scripts.verify_safe_sql_baseline.requests.Session')
    def test_safe_sql_is_an_independent_application_not_dvwa_remediation(self, session):
        normal = MagicMock(status_code=200,text='First name: Alex',content=b'First name: Alex')
        blocked = MagicMock(status_code=200,text='No results',content=b'No results')
        session.return_value.__enter__.return_value.get.side_effect = [normal,blocked]
        result = verify_safe_lookup('http://127.0.0.1:8081')
        self.assertFalse(result['dvwa_remediated'])
        self.assertEqual(result['comparison_type'],'INDEPENDENT_APPLICATION')


if __name__ == '__main__': unittest.main()
