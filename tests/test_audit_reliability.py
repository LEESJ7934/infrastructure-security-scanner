"""Offline regression cases; none of these are actual infrastructure evidence."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json
import tempfile
import unittest
from config_audit.collectors.web_was import nginx_values, ROOT
from config_audit.engine import evaluate
from config_audit.models import AuditAsset,AuditRule,Observation
from config_audit.kisa_2026 import condition
from config_audit.kisa_ciip_review import review_windows
from config_audit.supplemental import assess
from scripts.run_supplemental_audit import main


class LockoutConsistencyTests(unittest.TestCase):
    def test_both_entrypoints_agree_for_boundary_missing_and_disabled(self):
        base=dict(lockout_threshold=5,lockout_duration=60,reset_minutes=60)
        cases=[base,dict(base,lockout_threshold=0),dict(base,lockout_threshold=True),dict(base,lockout_threshold=-1),
               dict(base,lockout_threshold=6),dict(base,lockout_duration=0),dict(base,lockout_duration=59),
               dict(base,reset_minutes=59),{k:v for k,v in base.items() if k!='lockout_threshold'}]
        for values in cases:
            report={'mode':'LAB','results':[dict(check_id='WIN-LAB-004',status='NEEDS_REVIEW',after_values=values)]}
            for row in review_windows(report):
                with self.subTest(values=values,check=row['kisa_id']):
                    expected={'PASS':True,'FAIL':False}.get(row['kisa_recommendation_result'])
                    self.assertIs(condition(row['kisa_id'],values),expected)
        self.assertIs(condition('W-08',dict(base,lockout_threshold=0)),False)
        self.assertIsNone(condition('W-08',dict(base,lockout_duration=0)))


class EffectiveNginxTests(unittest.TestCase):
    def test_equivalent_general_config_inheritance_and_include(self):
        raw='http { server_tokens off; autoindex off; access_log /var/log/nginx/access.log; include /etc/nginx/site.conf; }'
        site='server { listen 8088; server_name audit.local; location /files/ { alias /other/files/; } location /private/ { deny all; } }'
        self.assertTrue(all(v is True for v in nginx_values(raw,includes={'/etc/nginx/site.conf':site}).values()))
    def test_location_override_prevents_false_pass(self):
        raw=(ROOT/'lab/web-was-lab/after/nginx.conf').read_text().replace('autoindex off','autoindex on')
        self.assertFalse(nginx_values(raw)['autoindex_disabled'])
        raw=(ROOT/'lab/web-was-lab/after/nginx.conf').read_text().replace('alias /srv/files/;', 'alias /srv/files/; server_tokens on; access_log off;')
        result=nginx_values(raw)
        self.assertFalse(result['tokens_hidden']);self.assertFalse(result['access_logging'])
    def test_unresolved_cycle_regex_dynamic_and_unknown_are_review(self):
        raw=(ROOT/'lab/web-was-lab/after/nginx.conf').read_text()
        variants=[raw+' include /missing.conf;',raw.replace('location /files/','location ~ /files/'),
                  raw.replace('autoindex off','autoindex $policy'),raw.replace('server_tokens off;','server_tokens off; unknown yes;')]
        for text in variants:
            with self.subTest(text=text):self.assertTrue(all(v is None for v in nginx_values(text).values()))
        cycle=nginx_values('include a;',includes={'a':'include b;','b':'include a;'})
        self.assertTrue(all(v is None for v in cycle.values()))
    def test_every_server_and_literal_context_is_considered(self):
        raw='http { server_tokens off; autoindex off; access_log /tmp/access; server { location /private/ { return 404; } } server { server_tokens on; location /private/ { return 404; } } }'
        self.assertFalse(nginx_values(raw)['tokens_hidden'])
    def test_missing_explicit_setting_not_defaulted(self):
        result=nginx_values('http { server { location /files/ { autoindex off; } location /private/ { return 404; } } }')
        self.assertTrue(result['autoindex_disabled']);self.assertIsNone(result['tokens_hidden']);self.assertIsNone(result['access_logging'])


class ProvenanceEngineTests(unittest.TestCase):
    def test_nginx_return_200_cannot_be_overridden_by_deny_all(self):
        raw='http { server_tokens off; autoindex off; access_log /tmp/access; server { location /private/ { return 200; deny all; } } }'
        self.assertFalse(nginx_values(raw)['private_blocked'])

    def status(self,observation):
        return evaluate(AuditAsset('a','linux','24.04'),AuditRule('internal','1','true','review',condition=lambda v:v),observation,
                        execution_id='test',checked_at=datetime.now(timezone.utc))
    def test_partial_positive_no_pass_but_observed_failure_retained(self):
        self.assertEqual(self.status(Observation(True,collection_complete=False)).status.value,'NEEDS_REVIEW')
        self.assertEqual(self.status(Observation(False,collection_complete=False)).status.value,'FAIL')
    def test_missing_unsupported_exception_error_and_good(self):
        cases=[(Observation(), 'NOT_TESTED'),(Observation(True,supported=False),'NEEDS_REVIEW'),
            (Observation(True,review_reason='policy_exception_unreviewed'),'NEEDS_REVIEW'),
            (Observation(True,collection_error=True),'ERROR'),(Observation(True,collection_complete=True,supported=True),'PASS')]
        for obs,wanted in cases:self.assertEqual(self.status(obs).status.value,wanted)
    def test_original_time_separate_private_and_legacy_shape(self):
        old=datetime(2026,1,1,tzinfo=timezone.utc)
        result=self.status(Observation(True,collected_at=old,source_kind='SAVED_LAB',collection_scope='single_root_context'))
        safe=result.to_safe_dict();self.assertEqual(safe['collected_at'],old.isoformat())
        self.assertNotEqual(safe['checked_at'],safe['collected_at']);self.assertEqual(safe['evidence_visibility'],'PRIVATE')
        self.assertNotIn('collected_at',self.status(Observation(True)).to_safe_dict())
    def test_naive_time_and_bad_flags_rejected(self):
        with self.assertRaises(ValueError):Observation(True,collected_at=datetime(2026,1,1))
        with self.assertRaises(ValueError):Observation(True,collection_complete='yes')


class SupplementalTests(unittest.TestCase):
    def document(self,check,value):
        return dict(schema_version=1,origin='SYNTHETIC',items=[dict(check_id=check,asset_id='synthetic-asset',
            product_version='review-fixture',collection_status='COLLECTED',value=value,
            collected_at='2026-01-01T00:00:00+00:00',evidence_reference='sample://fixture',scope='explicit-test-scope',complete=True,supported=True)])
    def status(self,doc):return assess(doc)['results'][0]['status']
    def test_account_privilege_inventory_good_bad_and_partial(self):
        doc=self.document('LINUX-ACCOUNT-UID0',dict(accounts=[dict(name='root',uid=0),dict(name='app',uid=1000)],designated_root='root'))
        self.assertEqual(self.status(doc),'PASS');doc['items'][0]['complete']=False
        self.assertEqual(self.status(doc),'NEEDS_REVIEW');doc['items'][0]['value']['accounts'].append(dict(name='other',uid=0))
        self.assertEqual(self.status(doc),'FAIL')
        self.assertNotIn('other',json.dumps(assess(doc)))
    def test_effective_ssh_missing_context_and_duplicate_output(self):
        value=dict(expected_contexts=['root-loopback','root-admin'],effective_outputs={'root-loopback':'permitrootlogin no\n','root-admin':'permitrootlogin no\n'})
        doc=self.document('LINUX-SSH-ROOT-CONTEXTS',value);self.assertEqual(self.status(doc),'PASS')
        del value['effective_outputs']['root-admin'];self.assertEqual(self.status(doc),'NEEDS_REVIEW')
        value['effective_outputs']['root-loopback']='permitrootlogin yes\n';self.assertEqual(self.status(doc),'FAIL')
        value['effective_outputs']['root-loopback']='permitrootlogin no\npermitrootlogin yes\n';self.assertEqual(self.status(doc),'NEEDS_REVIEW')
    def test_actual_tls_not_inferred_from_socket_or_cipher_alone(self):
        value=dict(transport='TCP',ssl_cipher='TLS_AES_256_GCM_SHA384',ssl_version='TLSv1.3',peer_identity_verified=True)
        doc=self.document('MYSQL-TLS-SESSION',value);self.assertEqual(self.status(doc),'PASS')
        value['peer_identity_verified']=None;self.assertEqual(self.status(doc),'NEEDS_REVIEW')
        value['ssl_cipher']='';self.assertEqual(self.status(doc),'FAIL')
        value['transport']='SOCKET';self.assertEqual(self.status(doc),'NEEDS_REVIEW')
    def test_log_marker_currentness_and_metadata_required(self):
        value=dict(probe_id='synthetic-run',observed_probe_id='synthetic-run',probe_at='2026-01-01T00:00:00Z',received_at='2026-01-01T00:00:01Z',destination='syslog-test',destination_matches=True)
        doc=self.document('LINUX-LOG-DELIVERY',value);self.assertEqual(self.status(doc),'PASS')
        value['observed_probe_id']='earlier-run';self.assertEqual(self.status(doc),'FAIL')
        doc['items'][0].pop('collected_at');self.assertEqual(self.status(doc),'NEEDS_REVIEW')
    def test_all_core_statuses_and_no_unverified_origin_promotion(self):
        doc=self.document('MYSQL-TLS-SESSION',dict(transport='TCP',ssl_cipher='x',ssl_version='TLSv1.3',peer_identity_verified=True))
        for change,wanted in [({'collection_status':'NOT_TESTED'},'NOT_TESTED'),({'collection_status':'ERROR'},'ERROR'),({'supported':False},'NEEDS_REVIEW'),({'review_reason':'organizational_exception_pending'},'NEEDS_REVIEW')]:
            other=deepcopy(doc);other['items'][0].update(change);self.assertEqual(self.status(other),wanted)
        doc['origin']='VERIFIED_LAB'
        with self.assertRaises(ValueError):assess(doc)
    def test_cli_exclusive_output_and_rejects_extra_secrets(self):
        doc=self.document('MYSQL-TLS-SESSION',dict(transport='TCP',ssl_cipher='x',ssl_version='TLSv1.3',peer_identity_verified=True))
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'input.json';output=Path(temp)/'output.json';source.write_text(json.dumps(doc))
            self.assertEqual(main(['--input',str(source),'--output',str(output)]),0)
            first=output.read_bytes();self.assertEqual(main(['--input',str(source),'--output',str(output)]),1);self.assertEqual(output.read_bytes(),first)
        doc['items'][0]['value']['password']='must-not-export'
        with self.assertRaises(ValueError):assess(doc)


if __name__=='__main__':unittest.main()
