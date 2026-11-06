"""Always-on synthetic PDF integration tests, independent of ignored local evidence."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader

from config_audit.final_report import canonical, content_sha256
from scripts.generate_day5_sample import ASSETS, ROOT, build_sample, generate_sample


class PublicSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.result = generate_sample(cls.directory/'one')
        cls.snapshot = json.loads((cls.directory/'one/sample-integrated-report.json').read_text(encoding='utf-8'))
        cls.reader = PdfReader(cls.directory/'one/sample-integrated-report.pdf')
        cls.text = '\n'.join(page.extract_text() or '' for page in cls.reader.pages)

    def test_actual_status_is_never_illustrative_pass(self):
        for row in self.snapshot['details']:
            for channel in ('automatic','manual'):
                if row[channel]:
                    self.assertEqual(row[channel]['status'],'NOT_TESTED')
        self.assertIn('PASS',{r['illustrative_status'] for r in self.snapshot['details']})
        self.assertIn('FAIL',{r['illustrative_status'] for r in self.snapshot['details']})

    def test_no_fake_integrity_or_local_evidence(self):
        index=self.snapshot['diagnostics']['evidence_index']
        self.assertEqual(index['counts']['VERIFIED'],0)
        self.assertEqual(index['unique_local_files'],0)
        for entry in index['entries']:
            self.assertIsNone(entry['actual_sha256'])
            self.assertIsNone(entry['expected_sha256'])
            self.assertIsNone(entry['exists'])
            self.assertIsNone(entry['local_path'])
            self.assertIsNone(entry['verified_at'])

    def test_all_pdf_pages_label_sample_and_korean_extracts(self):
        self.assertEqual(len(self.reader.pages),self.result['pages'])
        self.assertGreater(len(self.reader.pages),6)
        for page in self.reader.pages:
            self.assertIn('SAMPLE',page.extract_text())
        self.assertIn('합성 데이터',self.text)
        self.assertIn('실제 점검 결과 아님',self.text)
        self.assertIn('세부 진단 결과',self.text)
        self.assertNotIn('\ufffd',self.text)

    def test_pdf_metadata_hidden_objects_and_paths_are_public_safe(self):
        data=self.text+json.dumps(dict(self.reader.metadata),ensure_ascii=False)+json.dumps(self.snapshot,ensure_ascii=False)
        for forbidden in ('10.77.','C:\\Projects','[REDACTED]','fw04-active-rules','fw06-restore-ping'):
            self.assertNotIn(forbidden,data)
        self.assertIsNone(re.search(r'(?<![A-Za-z0-9_])[A-Za-z]:[\\/]|/home/|/Users/',data),
                          'Unexpected personal/platform absolute path in public sample')
        self.assertIn('SAMPLE',self.reader.metadata.title)
        self.assertEqual(self.reader.metadata.author,'Synthetic Sample Generator')
        self.assertFalse(self.reader.attachments)
        self.assertNotIn('/OpenAction',self.reader.trailer['/Root'])
        self.assertNotIn('/AA',self.reader.trailer['/Root'])

    def test_addresses_only_from_documentation_networks(self):
        networks=[ipaddress.ip_network(c) for c in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')]
        for address in ASSETS.values():
            self.assertTrue(any(ipaddress.ip_address(address) in network for network in networks))
        for address in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',json.dumps(self.snapshot)):
            self.assertTrue(any(ipaddress.ip_address(address) in network for network in networks))

    def test_reproducible_without_real_inputs_or_network(self):
        with patch.object(Path,'read_bytes',side_effect=AssertionError('No real inputs')):
            self.assertEqual(canonical(build_sample()),canonical(self.snapshot))
        generate_sample(self.directory/'two')
        for filename in ('sample-integrated-report.json','sample-integrated-report.pdf'):
            self.assertEqual((self.directory/'one'/filename).read_bytes(),(self.directory/'two'/filename).read_bytes())
        self.assertEqual(content_sha256(self.snapshot),self.snapshot['content_sha256'])

    def test_committed_json_is_reproducible_across_platforms(self):
        committed=json.loads((ROOT/'examples/day5-demo/sample-integrated-report.json').read_text(encoding='utf-8'))
        self.assertEqual(committed,self.snapshot)

    def test_cannot_overwrite_real_report_or_evidence(self):
        for path in (ROOT/'reports/day5',ROOT/'evidence/day4'):
            with self.assertRaisesRegex(ValueError,'sample_output_cannot_overwrite_real_artifacts'):
                generate_sample(path)

    def test_real_local_reports_unchanged(self):
        paths=[ROOT/'reports/day5'/name for name in ('day5-integrated-report.json','day5-integrated-report.pdf','day5-manifest.json')]
        hashes={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
        generate_sample(self.directory/'preservation')
        self.assertEqual(hashes,{p:hashlib.sha256(p.read_bytes()).hexdigest() for p in hashes})


if __name__=='__main__':
    unittest.main()
