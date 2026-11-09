"""End-to-end offline artifacts, Korean PDF text and unchanged historical inputs."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader

from api.report_pdf import render_day5_report_pdf, render_report_pdf
from config_audit.final_report import (FILES, INPUTS, FinalReportError, build_final_snapshot,
                                       content_sha256, generate_final_report, scrub)
from scripts.run_integrated_report import main

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pdf_text(path):
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


@unittest.skipUnless(all((ROOT / spec[0]).is_file() for spec in INPUTS), "Local ignored Day2/3 JSON inputs unavailable")
class LocalFinalReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'reports').mkdir(exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix='day5-test-', dir=ROOT/'reports')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.output = Path(cls.directory.name)
        manual = json.loads((ROOT/'evidence/day4/manual.json').read_text(encoding='utf-8-sig'))
        paths = {ROOT/spec[0] for spec in INPUTS}
        for record in manual['checks']:
            paths.update(ROOT/'evidence/day4'/s['path'] for s in record['sources'])
        for name in ('fw04-active-rules.txt', 'fw04-active-rules-detail.txt', 'fw04-rules.tar',
                     'fw05-wan-tcp22.json', 'fw05-wan-tcp22-retest.json'):
            paths.add(ROOT/'evidence/day4'/name)
        paths.update(ROOT/'lab/day3/artifacts'/name for name in ('day3.pcap','suricata-eve.json','suricata-fast.log'))
        cls.original_hashes = {path: digest(path) for path in paths}
        cls.result = generate_final_report(ROOT, cls.output)
        cls.snapshot = json.loads((cls.output/FILES['report']).read_text(encoding='utf-8'))
        cls.manifest = json.loads((cls.output/FILES['manifest']).read_text(encoding='utf-8'))
        cls.reader = PdfReader(cls.output/FILES['pdf'])
        cls.text = "\n".join(page.extract_text() or '' for page in cls.reader.pages)

    def test_actual_input_counts(self):
        self.assertEqual(self.snapshot['summary']['asset_count'], 5)
        self.assertEqual(self.snapshot['summary']['record_count'], 25)
        self.assertEqual(self.snapshot['summary']['unique_check_count'], 21)
        self.assertTrue(all(source['import_status']=='LOADED' for source in self.snapshot['inputs']))

    def test_one_snapshot_identity_in_every_artifact(self):
        identity, content = self.snapshot['report_id'], self.snapshot['content_sha256']
        self.assertEqual(self.manifest['report_id'], identity)
        self.assertEqual(self.manifest['report_content_sha256'], content)
        for kind in ('evidence','comparison'):
            value = json.loads((self.output/FILES[kind]).read_text(encoding='utf-8'))
            self.assertEqual(value['report_id'], identity)
            self.assertEqual(value['report_content_sha256'], content)
        compact=''.join(self.text.split())
        self.assertIn(content, compact)
        self.assertIn(identity, compact)

    def test_common_model_json_pdf_record_count_agree(self):
        count = sum(len(s['results']) for s in self.snapshot['diagnostics']['snapshots'])
        self.assertEqual(count, len(self.snapshot['details']))
        self.assertEqual(count, self.manifest['pdf']['record_count'])
        for row in self.snapshot['details']:
            self.assertEqual(self.text.count(row['record_id']), 1)

    def test_korean_headings_extract_and_font_is_embedded(self):
        for text in ('통합 인프라 보안', '결과보고서', '목차', '진단 개요', '세부 진단 결과', '증적 인덱스', '미검증 사항'):
            self.assertIn(text, self.text)
        self.assertNotIn('<br/>', self.text)
        self.assertNotIn('\ufffd', self.text)
        embedded=False
        for page in self.reader.pages:
            for ref in page['/Resources'].get('/Font', {}).values():
                font=ref.get_object()
                descriptor=font.get('/FontDescriptor')
                if descriptor and '/FontFile2' in descriptor.get_object():
                    embedded=True
        self.assertTrue(embedded)

    def test_fw04_fw05_review_preserved_without_automatic_result(self):
        rows={r['check_id']:r for r in self.snapshot['details'] if r['day']==4}
        self.assertNotIn('FW-01', rows)
        for check in ('FW-04','FW-05'):
            self.assertEqual(rows[check]['manual']['status'], 'NEEDS_REVIEW')
            self.assertIsNone(rows[check]['automatic'])

    def test_fw06_manual_pass_preserved(self):
        row=next(r for r in self.snapshot['details'] if r['check_id']=='FW-06')
        self.assertEqual(row['manual']['status'], 'PASS')
        self.assertIsNone(row['automatic'])
        restored=next(t for t in row['manual']['tests'] if t['scenario']=='restored')
        self.assertEqual(restored['packets_received'], 4)
        self.assertIsNone(row['expected_condition'])

    def test_day2_record_changes_distinct_from_strict_comparison(self):
        comparison=self.snapshot['comparison']
        self.assertEqual(comparison['summary']['UNVERIFIABLE'], 4)
        self.assertEqual(comparison['summary']['IMPROVED_OBSERVED'], 0)
        self.assertEqual(comparison['observed_transition_summary']['FAIL_TO_PASS'], 2)
        self.assertEqual(comparison['observed_transition_summary']['PASS_TO_PASS'], 2)
        self.assertEqual(set(comparison['unpaired_snapshot_ids']), {'day3-final','day4-manual'})

    def test_evidence_counts_recomputed_and_preserved(self):
        index=self.snapshot['diagnostics']['evidence_index']
        self.assertEqual(index['unique_local_files'],23)
        self.assertEqual(len(index['entries']),60)
        self.assertEqual(index['counts'], {'VERIFIED':15,'MISMATCH':0,'MISSING':0,'NOT_VERIFIED':33,'EXTERNAL_REFERENCE':12,'INVALID_REFERENCE':0})
        self.assertTrue(all(v==0 for v in self.snapshot['index_reference_difference']['counts'].values()))

    def test_no_duplicate_current_state_total(self):
        view=self.snapshot['summary']['selected_view']
        self.assertEqual(view['record_count'],21)
        self.assertEqual(view['automatic']['PASS'],16)
        self.assertEqual(view['manual']['PASS'],3)
        self.assertEqual(view['manual']['NEEDS_REVIEW'],2)
        original=[g for g in self.snapshot['summary']['by_snapshot_asset_channel'] if g['snapshot_id']=='day2-before']
        self.assertEqual(sum(g['status_counts']['FAIL'] for g in original),2)

    def test_definition_provenance_without_invented_risk_or_cve(self):
        ssh=next(r for r in self.snapshot['details'] if r['check_id']=='LAB-SSH-002')
        self.assertEqual(ssh['expected_condition'],'PermitRootLogin = no')
        self.assertEqual(ssh['recommendation_from_definition'],'Disable direct SSH root login.')
        self.assertTrue(ssh['definition']['source_reference'].startswith('scripts/run_day2_audit.py:'))
        self.assertTrue(all(r['definition'] for r in self.snapshot['details']))
        self.assertTrue(all(r['risk'] is None and r['observed_value'] is None for r in self.snapshot['details']))

    def test_file_hashes_and_nonrecursive_manifest(self):
        self.assertEqual(self.snapshot['content_sha256'],content_sha256(self.snapshot))
        self.assertNotIn(FILES['manifest'],[f['filename'] for f in self.manifest['artifacts']])
        for artifact in self.manifest['artifacts']:
            path=self.output/artifact['filename']
            self.assertEqual(artifact['file_sha256'],digest(path))
            self.assertEqual(artifact['size_bytes'],path.stat().st_size)
        self.assertNotEqual(digest(self.output/FILES['report']),self.snapshot['content_sha256'])

    def test_exported_index_and_comparison_equal_embedded_snapshot(self):
        index=json.loads((self.output/FILES['evidence']).read_text(encoding='utf-8'))
        comparison=json.loads((self.output/FILES['comparison']).read_text(encoding='utf-8'))
        self.assertEqual(index['evidence_index'],self.snapshot['diagnostics']['evidence_index'])
        self.assertEqual(comparison['comparison'],self.snapshot['comparison'])

    def test_pages_a4_and_split_tables(self):
        self.assertEqual(len(self.reader.pages),self.manifest['pdf']['page_count'])
        self.assertGreater(len(self.reader.pages),10)
        for page in self.reader.pages:
            self.assertAlmostEqual(float(page.mediabox.width),595.2756,places=2)
            self.assertAlmostEqual(float(page.mediabox.height),841.8898,places=2)
            self.assertGreater(len((page.extract_text() or '').strip()),100)
        repeated=sum('SHA-256 / 검증 상태' in (page.extract_text() or '') for page in self.reader.pages)
        self.assertGreater(repeated,1)

    def test_original_inputs_and_evidence_bytes_unchanged(self):
        self.assertEqual({p:digest(p) for p in self.original_hashes},self.original_hashes)

    def test_long_path_hash_and_reason_render_without_truncation(self):
        snapshot=deepcopy(self.snapshot)
        snapshot['details'][0]['automatic']['reason']='긴 사유와 조치 권고. '*450+'TEST-LONG-END'
        snapshot['diagnostics']['evidence_index']['entries'][0]['original_reference']='evidence/day4/'+('long-segment/'*120)+'LONG-PATH-END.txt'
        path=self.output/'long-test.pdf'
        result=render_day5_report_pdf(snapshot,path)
        compact=''.join(pdf_text(path).split())
        self.assertIn('TEST-LONG-END',compact)
        self.assertIn('LONG-PATH-END.txt',compact)
        self.assertGreater(result['page_count'],10)

    def test_pdf_defense_in_depth_for_credentials(self):
        snapshot=deepcopy(self.snapshot)
        snapshot['details'][0]['automatic']['reason']='Authorization: Bearer FAKE_TEST_SECRET'
        snapshot['details'][0]['api_key']='FAKE_KEY_VALUE'
        path=self.output/'redaction-test.pdf'
        render_day5_report_pdf(snapshot,path)
        text=pdf_text(path)
        self.assertNotIn('FAKE_TEST_SECRET',text)
        self.assertNotIn('FAKE_KEY_VALUE',text)
        self.assertIn('[REDACTED]',text)

    def test_offline_builder_avoids_network_process_and_db_import(self):
        import builtins
        original=builtins.__import__
        def guarded(name,*args,**kwargs):
            if name.startswith(('db.','api.analysis_report','scripts.run_day2','scripts.run_day3','scripts.run_day4')):
                raise AssertionError('Forbidden execution path: '+name)
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=guarded),patch.object(socket,'socket',side_effect=AssertionError),patch.object(subprocess,'run',side_effect=AssertionError):
            result=generate_final_report(ROOT,self.output/'offline-run')
        self.assertEqual(result['summary']['record_count'],25)

    def test_old_db_pdf_renderer_remains_compatible(self):
        path=self.output/'legacy.pdf'
        render_report_pdf({'assets':[],'summary':{},'scans':[]},path)
        self.assertIn('Report Metadata',pdf_text(path))

    def test_pdf_failure_does_not_publish_staged_json(self):
        directory=self.output/'failed-run'
        with patch('api.report_pdf.render_day5_report_pdf',side_effect=RuntimeError('test failure')):
            with self.assertRaises(RuntimeError):
                generate_final_report(ROOT,directory)
        self.assertFalse((directory/FILES['report']).exists())
        self.assertFalse((directory/FILES['manifest']).exists())


class FinalReportBoundaryTests(unittest.TestCase):
    def test_missing_inputs_generate_explicit_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            result=generate_final_report(root)
            snapshot=json.loads(Path(result['paths']['report']).read_text(encoding='utf-8'))
            self.assertEqual(result['completion_status'],'PARTIAL')
            self.assertEqual(snapshot['summary']['record_count'],0)
            self.assertTrue(all(s['import_status']=='ERROR' for s in snapshot['inputs']))
            self.assertEqual(snapshot['comparison']['invalid_relation_count'],1)

    def test_output_must_stay_in_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            with self.assertRaisesRegex(FinalReportError,'output_outside_reports'):
                generate_final_report(root,root/'evidence')

    def test_invalid_json_is_partial_and_never_echoes_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            (root/'logs').mkdir()
            (root/'logs/day2-before.json').write_text('{"api_secret":"FAKE_SENTINEL",',encoding='utf-8')
            result=generate_final_report(root)
            self.assertEqual(result['completion_status'],'PARTIAL')
            self.assertNotIn('FAKE_SENTINEL',Path(result['paths']['report']).read_text(encoding='utf-8'))

    def test_content_hash_excludes_itself_only(self):
        data={'generated_at':'a','content_sha256':'one'}
        first=content_sha256(data)
        data['content_sha256']='two'
        self.assertEqual(first,content_sha256(data))
        data['generated_at']='b'
        self.assertNotEqual(first,content_sha256(data))

    def test_scrub_nested_credentials_without_destroying_guidance(self):
        data=scrub({'api_secret':'FAKE_SECRET','x':{'Authorization':'Bearer FAKE_TOKEN'},
                    'guidance':'Disable empty SSH passwords.'})
        self.assertNotIn('FAKE_SECRET',json.dumps(data))
        self.assertNotIn('FAKE_TOKEN',json.dumps(data))
        self.assertEqual(data['guidance'],'Disable empty SSH passwords.')

    def test_cli_success_and_partial_exit_codes(self):
        for status,code in (('COMPLETE_WITH_LIMITATIONS',0),('PARTIAL',2)):
            with patch('scripts.run_integrated_report.generate_final_report',return_value={'completion_status':status}),redirect_stdout(StringIO()):
                self.assertEqual(main([]),code)

    def test_cli_error_does_not_echo_credentials(self):
        buffer=StringIO()
        with patch('scripts.run_integrated_report.generate_final_report',side_effect=ValueError('API_SECRET=FAKE_LEAK')),redirect_stderr(buffer):
            self.assertEqual(main([]),1)
        self.assertNotIn('FAKE_LEAK',buffer.getvalue())

    def test_cli_unknown_arguments_never_echo_secret_values(self):
        buffer=StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(main(['--api-secret','FAKE_ARG_LEAK']),1)
        self.assertNotIn('FAKE_ARG_LEAK',buffer.getvalue())


if __name__=='__main__':
    unittest.main()
