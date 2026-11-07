"""Synthetic/read-only mocks only. No Docker, DB, SSH or host-policy changes."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from config_audit.collectors import linux_mysql_lab as lm
from config_audit.linux_mysql_report import common_snapshot, write_pdf
from scripts.run_linux_mysql_audit import main

ROOT = Path(__file__).resolve().parents[1]


class LinuxMySQLLabTests(unittest.TestCase):
    def setUp(self):
        self.before = lm.synthetic_bundle('before')
        self.after = lm.synthetic_bundle('after')

    def row(self, bundle, check):
        return next(r for r in lm.audit(bundle, synthetic=bundle['origin'] == 'synthetic')['results'] if r['check_id'] == check)

    def test_default_no_network_and_not_tested(self):
        with patch('scripts.run_linux_mysql_audit.collect_docker', side_effect=AssertionError()), redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        self.assertEqual(lm.audit()['summary'], {'NOT_TESTED': 10})

    def test_before_all_fail_synthetic_label(self):
        report = lm.audit(self.before, synthetic=True)
        self.assertEqual(report['summary'], {'FAIL': 10})
        self.assertEqual(report['origin'], 'synthetic')

    def test_after_all_pass_synthetic_label(self):
        self.assertEqual(lm.audit(self.after, synthetic=True)['summary'], {'PASS': 10})

    def test_common_engine_used_ten_times(self):
        with patch.object(lm, 'evaluate', wraps=lm.evaluate) as evaluate:
            lm.audit(self.after, synthetic=True)
        self.assertEqual(evaluate.call_count, 10)

    def test_existing_parsers_reused(self):
        with patch.object(lm, 'parse_ssh_settings', wraps=lm.parse_ssh_settings) as ssh, patch.object(lm, 'parse_mysql_settings', wraps=lm.parse_mysql_settings) as sql:
            lm.synthetic_bundle('after')
        self.assertTrue(ssh.called and sql.called)

    def test_synthetic_cannot_be_claimed_actual(self):
        with self.assertRaises(lm.LabInputError): lm.audit(self.after)

    def test_root_login_prohibit_password_not_no(self):
        self.after['nodes']['linux']['checks']['LINUX-LAB-001']['value'] = 'prohibit-password'
        self.assertEqual(self.row(self.after, 'LINUX-LAB-001')['status'], 'FAIL')

    def test_unrecognized_ssh_needs_review(self):
        self.after['nodes']['linux']['checks']['LINUX-LAB-001']['value'] = 'unrecognized'
        self.assertEqual(self.row(self.after, 'LINUX-LAB-001')['status'], 'NEEDS_REVIEW')

    def test_missing_setting_is_not_tested(self):
        del self.after['nodes']['linux']['checks']['LINUX-LAB-002']
        self.assertEqual(self.row(self.after, 'LINUX-LAB-002')['status'], 'NOT_TESTED')

    def test_file_modes_and_owner_fail(self):
        for field, value in [('mode', 0o666), ('uid', 1000), ('symlink', True), ('regular', False), ('group_approved', False)]:
            b = deepcopy(self.after); b['nodes']['linux']['checks']['LINUX-LAB-003']['value'][0][field] = value
            self.assertEqual(self.row(b, 'LINUX-LAB-003')['status'], 'FAIL')

    def test_missing_file_collection_error(self):
        self.after['nodes']['linux']['checks']['LINUX-LAB-003'] = lm.section(error=True)
        self.assertEqual(self.row(self.after, 'LINUX-LAB-003')['status'], 'ERROR')

    def test_demo_listener_present_fails(self):
        self.after['nodes']['linux']['checks']['LINUX-LAB-004']['value'] = True
        self.assertEqual(self.row(self.after, 'LINUX-LAB-004')['status'], 'FAIL')

    def test_logging_daemon_and_route_and_startup_required(self):
        for key in ('daemon_running', 'auth_route_enabled', 'startup_config_matches'):
            b = deepcopy(self.after); b['nodes']['linux']['checks']['LINUX-LAB-005']['value'][key] = False
            self.assertEqual(self.row(b, 'LINUX-LAB-005')['status'], 'FAIL')

    def test_anonymous_and_remote_root_count(self):
        for check in ('MYSQL-LAB-001', 'MYSQL-LAB-002'):
            b = deepcopy(self.after); b['nodes']['mysql']['checks'][check]['value'] = 1
            self.assertEqual(self.row(b, check)['status'], 'FAIL')

    def test_roles_mandatory_roles_and_unknown_grants_prevent_pass(self):
        for key, value in [('roles_assigned', 1), ('mandatory_roles', True), ('direct_grants', ['UNRECOGNIZED'])]:
            b = deepcopy(self.after); b['nodes']['mysql']['checks']['MYSQL-LAB-005']['value'][key] = value
            self.assertEqual(self.row(b, 'MYSQL-LAB-005')['status'], 'NEEDS_REVIEW')

    def test_proxy_broad_grants_and_missing_account_fail(self):
        for key, value in [('proxy_grants', 1), ('account_count', 0), ('direct_grants', ['EXCESSIVE'])]:
            b = deepcopy(self.after); b['nodes']['mysql']['checks']['MYSQL-LAB-005']['value'][key] = value
            self.assertEqual(self.row(b, 'MYSQL-LAB-005')['status'], 'FAIL')

    def test_select_database_scope_excessive(self):
        self.assertEqual(lm.grants_summary('GRANT SELECT ON `lab_data`.* TO `lab_app`@`localhost`'), ['EXCESSIVE'])

    def test_grant_option_excessive(self):
        self.assertEqual(lm.grants_summary('GRANT SELECT ON `lab_data`.`items` TO `lab_app`@`localhost` WITH GRANT OPTION'), ['EXCESSIVE'])

    def test_grant_raw_secret_not_retained(self):
        self.assertNotIn('SECRET_CANARY', json.dumps(lm.grants_summary('SECRET_CANARY')))

    def test_mysql_auth_failure_not_pass(self):
        node = lm.normalize_mysql()
        self.after['nodes']['mysql'] = node
        self.assertTrue(all(r['status'] == 'ERROR' for r in lm.audit(self.after, synthetic=True)['results'][5:]))

    def test_mysql_partial_query_failure_separated(self):
        node = lm.normalize_mysql('8.4.13\t0\t1\t1\t0', None, None)
        self.after['nodes']['mysql'] = node
        statuses = [r['status'] for r in lm.audit(self.after, synthetic=True)['results'][5:]]
        self.assertEqual(statuses, ['ERROR','ERROR','PASS','PASS','ERROR'])

    def test_mysql_malformed_settings(self):
        node = lm.normalize_mysql('broken')
        self.assertEqual(node['checks']['MYSQL-LAB-003']['state'], 'ERROR')

    def test_invalid_account_counts(self):
        for raw in ('1\t2', '-1\t0\t1\t0\t0\t0', '0\t0\t1\t0\t0\t2'):
            with self.assertRaises(lm.LabInputError): lm.normalize_mysql(accounts=raw)

    def test_unsupported_version_not_tested(self):
        self.after['nodes']['mysql']['version'] = '8.0.44'
        self.assertEqual(self.row(self.after, 'MYSQL-LAB-004')['status'], 'NOT_TESTED')

    def test_unknown_secret_fields_rejected(self):
        for where in ('bundle', 'node', 'section'):
            b = deepcopy(self.after)
            target = b if where == 'bundle' else b['nodes']['mysql'] if where == 'node' else b['nodes']['mysql']['checks']['MYSQL-LAB-004']
            target['password'] = 'SECRET_CANARY'
            with self.assertRaises(lm.LabInputError): lm.validate(b)

    def test_error_code_cannot_smuggle_secret(self):
        self.after['nodes']['mysql']['checks']['MYSQL-LAB-004']['error_code'] = 'SECRET_CANARY'
        with self.assertRaises(lm.LabInputError): lm.validate(self.after)

    def test_json_invalid_missing_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'input.json'
            with self.assertRaises(lm.LabInputError): lm.load(p)
            for raw in ('{', '{"x":1,"x":2}'):
                p.write_text(raw)
                with self.assertRaises(lm.LabInputError): lm.load(p)

    def test_report_input_original_bytes_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'before.json'; p.write_text(json.dumps(lm.audit(self.before, synthetic=True)))
            raw = p.read_bytes(); bundle, hashed = lm.load(p)
            self.assertEqual(raw, p.read_bytes()); self.assertEqual(hashed, lm.digest(raw)); self.assertEqual(bundle, self.before)

    def compare(self, before=None, after=None):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'before.json'; p.write_text(json.dumps(before or self.before))
            return lm.compare(lm.audit(after or self.after, synthetic=True), p)

    def test_ten_synthetic_transitions_not_real_remediation(self):
        r = self.compare()['comparison']
        self.assertEqual(r['summary'], {'IMPROVED_OBSERVED': 10})
        self.assertFalse(any(v['remediation_complete_in_LAB'] for v in r['results']))

    def test_reverse_time_and_version_change_incomparable(self):
        b = deepcopy(self.after); b['collected_at'] = self.before['collected_at']
        self.assertEqual(self.compare(after=b)['comparison']['summary'], {'INCOMPARABLE': 10})
        b = deepcopy(self.after); b['nodes']['linux']['components']['rsyslog'] = '9.0'
        self.assertEqual(self.compare(after=b)['comparison']['summary'], {'INCOMPARABLE': 10})

    def test_error_to_pass_not_improved(self):
        self.before['nodes']['linux']['checks']['LINUX-LAB-001'] = lm.section(error=True)
        self.assertEqual(self.compare()['comparison']['results'][0]['comparison_result'], 'UNVERIFIABLE')

    def test_rule_version_mismatch_rejected(self):
        self.before['rule_version'] = 'unknown'
        with self.assertRaises(lm.LabInputError): self.compare()

    def test_timestamp_timezone_required(self):
        self.after['collected_at'] = '2026-01-01T00:01:00'
        with self.assertRaises(lm.LabInputError): lm.validate(self.after)

    def test_common_report_channels_and_collection_time(self):
        report = lm.audit(self.after, synthetic=True); s = common_snapshot(report, 'after')
        self.assertEqual(len(s['results']), 10)
        self.assertIsNone(s['results'][0]['manual'])
        self.assertEqual(s['results'][0]['automatic']['collected_at'], self.after['collected_at'])
        self.assertNotEqual(report['generated_at'], self.after['collected_at'])

    def test_no_output_overwrite_or_collection_on_bad_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'keep.json'; p.write_text('PRESERVE')
            with patch('scripts.run_linux_mysql_audit.collect_docker', side_effect=AssertionError()), redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--execute','--output',str(p)]),2)
            self.assertEqual(p.read_text(),'PRESERVE')

    def test_process_error_no_secret(self):
        with patch.object(lm.subprocess,'run',side_effect=OSError('SECRET_CANARY')):
            with self.assertRaisesRegex(lm.LabInputError,'docker_query_failed'): lm.run(['docker','context','show'])
        output=io.StringIO()
        with patch('scripts.run_linux_mysql_audit.collect_docker', side_effect=OSError('SECRET_CANARY')), redirect_stdout(output):
            self.assertEqual(main(['--execute']),2)
        self.assertNotIn('SECRET_CANARY',output.getvalue())

    def test_remote_context_and_endpoint_rejected(self):
        with patch.object(lm,'run',return_value='production'):
            with self.assertRaises(lm.LabInputError): lm.docker_scope()
        with patch.object(lm,'run',side_effect=['default',json.dumps([{'Endpoints':{'docker':{'Host':'tcp://remote:2375'}}}])]):
            with self.assertRaisesRegex(lm.LabInputError,'remote_docker_rejected'): lm.docker_scope()

    def scope_responses(self, project=lm.PROJECT):
        nodes=[]
        for service in lm.VERSIONS:
            nodes.append({'Id':('a' if service == 'linux' else 'b') * 64,'Image':'sha256:'+'c'*64,'State':{'Running':True},'Config':{
                'Image':project+'-linux:after' if service=='linux' else project+'-mysql:local',
                'Labels':{'com.docker.compose.project':project,'com.docker.compose.service':service},
                'Entrypoint':['python3','/opt/lab/start-linux.py'] if service=='linux' else ['bash','/opt/lab/start-mysql.sh']},
                'HostConfig':{'Privileged':False,'NetworkMode':project+'_isolated','PidMode':'','IpcMode':'private','PortBindings':{}},'Mounts':[],'NetworkSettings':{'Networks':{project+'_isolated':{}}}})
        network={'Internal':True,'Driver':'bridge','Labels':{'com.docker.compose.project':project},'Containers':{'a'*64:{},'b'*64:{}}}
        return ['default',json.dumps([{'Endpoints':{'docker':{'Host':'unix:///var/run/docker.sock'}}}]),'linux',json.dumps([nodes[0]]),json.dumps([nodes[1]]),json.dumps([network])]

    def test_scoped_local_project_accepted(self):
        with patch.object(lm,'run',side_effect=self.scope_responses()): self.assertEqual(set(lm.docker_scope()[1]),set(lm.VERSIONS))

    def test_foreign_project_host_mount_ports_capabilities_rejected(self):
        for field in ('foreign','mount','port','privileged','capability'):
            replies=self.scope_responses();obj=json.loads(replies[3])[0]
            if field=='foreign':obj['Config']['Labels']['com.docker.compose.project']='other'
            if field=='mount':obj['Mounts']=[{'Type':'bind','Destination':'/host'}]
            if field=='port':obj['HostConfig']['PortBindings']={'22/tcp':[{'HostPort':'22'}]}
            if field=='privileged':obj['HostConfig']['Privileged']=True
            if field=='capability':obj['HostConfig']['CapAdd']=['SYS_ADMIN']
            replies[3]=json.dumps([obj])
            with patch.object(lm,'run',side_effect=replies),self.assertRaises(lm.LabInputError):lm.docker_scope()

    def test_compose_isolation_ephemeral_secrets_and_no_host_ports(self):
        compose=json.loads((ROOT/'lab/phase2-linux-mysql/compose.json').read_text())
        self.assertTrue(compose['networks']['isolated']['internal'])
        for s in compose['services'].values():
            self.assertNotIn('ports',s);self.assertNotIn('volumes',s);self.assertNotIn('privileged',s)
            self.assertNotIn('SYS_ADMIN',s['cap_add'])
        wrapper=(ROOT/'lab/phase2-linux-mysql/start-mysql.sh').read_text()
        self.assertIn('openssl rand -hex 32',wrapper)
        self.assertNotIn('MYSQL_RANDOM_ROOT_PASSWORD=',wrapper)
        for p in (ROOT/'lab/phase2-linux-mysql').glob('*.sh'):self.assertNotIn(b'\r',p.read_bytes())

    def test_readonly_queries_no_authentication_hashes_or_mutations(self):
        for q in (lm.SQL_SETTINGS,lm.SQL_ACCOUNTS,lm.SQL_GRANTS):
            self.assertTrue(q.startswith(('SELECT','SHOW')))
            self.assertNotIn('authentication_string',q);self.assertNotIn('IDENTIFIED',q)

    def simulated_collection(self, sql_failure=None, linux_bad=False):
        raw={'version':'24.04','components':{'openssh-server':'9.6p1','rsyslog':'8.2312'},
            'ssh':'permitrootlogin no\npasswordauthentication no','ssh_error':False,
            'files':self.after['nodes']['linux']['checks']['LINUX-LAB-003']['value'],'files_error':False,
            'demo_listener':False,'logging':self.after['nodes']['linux']['checks']['LINUX-LAB-005']['value'],'logging_error':False}
        if linux_bad:raw['password']='SECRET_CANARY'
        nodes={p:{'Id':ch*64,'Image':'sha256:'+'a'*64,'State':{'StartedAt':'2020-01-01T00:00:00Z'}} for p,ch in [('linux','b'),('mysql','c')]}
        outputs=[json.dumps(raw),'8.4.13\t0\t1\t1\t0','0\t0\t1\t0\t0\t0','GRANT USAGE ON *.* TO `lab_app`@`localhost`\nGRANT SELECT ON `lab_data`.`items` TO `lab_app`@`localhost`']
        if sql_failure is not None:outputs[sql_failure+1]=lm.LabInputError('docker_query_failed')
        with patch.object(lm,'docker_scope',return_value=(['docker'],nodes)),patch.object(lm,'run',side_effect=outputs) as commands:
            bundle=lm.collect_docker()
        self.assertTrue(all(c.args[0][1]=='exec' for c in commands.call_args_list))
        return bundle

    def test_simulated_container_collection_all_checks(self):
        bundle=self.simulated_collection()
        self.assertEqual(bundle['origin'],'local_container_readonly')
        self.assertEqual(lm.audit(bundle)['summary'],{'PASS':10})

    def test_mysql_permissions_failure_keeps_linux_results(self):
        result=lm.audit(self.simulated_collection(sql_failure=1))
        self.assertEqual(result['summary'],{'PASS':7,'ERROR':3})

    def test_grants_query_failure_not_minimum_privilege_pass(self):
        result=lm.audit(self.simulated_collection(sql_failure=2))
        self.assertEqual(result['results'][-1]['status'],'ERROR')

    def test_untrusted_linux_extra_fields_not_exported(self):
        report=lm.audit(self.simulated_collection(linux_bad=True))
        self.assertEqual(report['summary'],{'ERROR':5,'PASS':5})
        self.assertNotIn('SECRET_CANARY',json.dumps(report))

    def test_duplicate_effective_ssh_setting_errors(self):
        raw={'version':'24.04','components':{},'ssh':'permitrootlogin no\npermitrootlogin yes','ssh_error':False,'files':None,'files_error':False,'demo_listener':None,'logging':None,'logging_error':False}
        node=lm.normalize_linux(raw)
        self.assertEqual(node['checks']['LINUX-LAB-001']['state'],'ERROR')
        self.assertIsNone(node['checks']['LINUX-LAB-001']['value'])

    def test_pdf_synthetic_label_and_checks(self):
        from pypdf import PdfReader
        output=io.BytesIO();write_pdf(lm.audit(self.after,synthetic=True),output)
        text='\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(output.getvalue())).pages)
        self.assertIn('합성 테스트',text)
        for check in lm.CHECKS:self.assertIn(check,text)

    def test_each_safety_rejection_has_precise_code(self):
        cases=[('state','Running',False,'linux_container_not_running'),
            ('host','Privileged',True,'linux_privileged_or_unknown'),
            ('host','NetworkMode','host','linux_network_mode_rejected'),
            ('host','PidMode','host','linux_pid_namespace_rejected'),
            ('host','IpcMode','host','linux_ipc_namespace_rejected'),
            ('host','PortBindings',{'22/tcp':[{'HostPort':'22'}]},'linux_published_ports_rejected')]
        for where,key,value,code in cases:
            replies=self.scope_responses();obj=json.loads(replies[3])[0]
            obj['State' if where=='state' else 'HostConfig'][key]=value;replies[3]=json.dumps([obj])
            with self.subTest(code=code),patch.object(lm,'run',side_effect=replies),self.assertRaisesRegex(lm.LabInputError,code):lm.docker_scope()

    def test_missing_safety_field_is_not_assumed_safe(self):
        replies=self.scope_responses();obj=json.loads(replies[3])[0];del obj['HostConfig']['Privileged'];replies[3]=json.dumps([obj])
        with patch.object(lm,'run',side_effect=replies),self.assertRaisesRegex(lm.LabInputError,'privileged_or_unknown'):lm.docker_scope()

    def test_foreign_image_name_and_invalid_image_id_rejected(self):
        for key,value in [('Image','not-an-image-id'),('Config.Image','other-project:latest')]:
            replies=self.scope_responses();obj=json.loads(replies[3])[0]
            if key=='Image':obj['Image']=value
            else:obj['Config']['Image']=value
            replies[3]=json.dumps([obj])
            with patch.object(lm,'run',side_effect=replies),self.assertRaises(lm.LabInputError):lm.docker_scope()

    def test_mysql_canonical_tmpfs_mount_allowed(self):
        replies=self.scope_responses();obj=json.loads(replies[4])[0];obj['Mounts']=[{'Type':'tmpfs','Destination':'/run/mysqld'}];replies[4]=json.dumps([obj])
        with patch.object(lm,'run',side_effect=replies):self.assertEqual(set(lm.docker_scope()[1]),set(lm.VERSIONS))

    def test_bind_mount_at_canonical_tmpfs_path_rejected(self):
        replies=self.scope_responses();obj=json.loads(replies[4])[0];obj['Mounts']=[{'Type':'bind','Destination':'/run/mysqld'}];replies[4]=json.dumps([obj])
        with patch.object(lm,'run',side_effect=replies),self.assertRaisesRegex(lm.LabInputError,'unexpected_mount'):lm.docker_scope()

    def test_replay_scope_is_allowlisted_separately(self):
        with patch.object(lm,'run',side_effect=self.scope_responses(lm.REPLAY_PROJECT)):
            self.assertEqual(set(lm.docker_scope(lm.REPLAY_PROJECT)[1]),set(lm.VERSIONS))
        with patch.object(lm,'run',side_effect=AssertionError()),self.assertRaisesRegex(lm.LabInputError,'project_not_allowed'):lm.docker_scope('unrelated')

    def test_replay_asset_identity_and_provenance(self):
        self.after['project']=lm.REPLAY_PROJECT;self.after['capture_context']='new_reproduction_not_historical_baseline'
        report=lm.audit(self.after,synthetic=True)
        self.assertTrue(all(r['asset_id'].startswith(lm.REPLAY_PROJECT+'/') for r in report['results']))
        result=self.compare(after=self.after)
        self.assertEqual(result['comparison']['summary'],{'INCOMPARABLE':10})
        self.assertIn('logical_project_asset_mismatch',result['comparison']['issues'])

    def test_replay_compose_does_not_reuse_current_names_or_images(self):
        compose=json.loads((ROOT/'lab/phase2-linux-mysql/compose.replay.json').read_text())
        self.assertEqual(compose['name'],lm.REPLAY_PROJECT)
        for service in compose['services'].values():
            self.assertTrue(service['image'].startswith(lm.REPLAY_PROJECT+'-'))
            self.assertNotIn('container_name',service);self.assertNotIn('volumes',service);self.assertNotIn('ports',service)

    def test_initial_rsyslog_keeps_nonsecurity_action_without_auth_route(self):
        raw=(ROOT/'lab/phase2-linux-mysql/before/rsyslog.conf').read_text()
        self.assertIn('auth,authpriv.* stop',raw)
        self.assertIn('user.* action(type="omfile" file="/var/log/lab-user.log")',raw)
        self.assertNotIn('/var/log/lab-auth.log',raw)
        self.assertEqual(lm.audit(self.before,synthetic=True)['summary'],{'FAIL':10})

    def test_both_compose_profiles_wait_for_linux_health(self):
        for name in ('compose.json','compose.replay.json'):
            d=json.loads((ROOT/'lab/phase2-linux-mysql'/name).read_text())
            self.assertEqual(d['services']['linux']['healthcheck']['test'],['CMD','python3','/opt/lab/collect-linux.py','--health'])

    def test_missing_baseline_keeps_current_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'current.json'
            with redirect_stdout(io.StringIO()):
                code=main(['--demo','after','--baseline-json',str(Path(tmp)/'missing.json'),'--output',str(output)])
            saved=json.loads(output.read_text())
            self.assertEqual(code,0);self.assertEqual(saved['summary'],{'PASS':10})
            self.assertEqual(saved['comparison']['status'],'UNAVAILABLE');self.assertEqual(saved['comparison']['results'],[])

    def test_invalid_baseline_keeps_current_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline=Path(tmp)/'bad.json';baseline.write_text('{broken');output=Path(tmp)/'current.json'
            with redirect_stdout(io.StringIO()):code=main(['--demo','after','--baseline-json',str(baseline),'--output',str(output)])
            self.assertEqual(code,0);self.assertEqual(baseline.read_text(),'{broken')
            self.assertEqual(json.loads(output.read_text())['comparison']['status'],'UNAVAILABLE')

    def test_pdf_failure_does_not_discard_saved_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'current.json';pdf=Path(tmp)/'report.pdf';stdout=io.StringIO()
            with patch('config_audit.linux_mysql_report.write_pdf',side_effect=OSError('SECRET_CANARY')),redirect_stdout(stdout):
                code=main(['--demo','after','--output',str(output),'--pdf',str(pdf)])
            self.assertEqual(code,2);self.assertEqual(json.loads(output.read_text())['summary'],{'PASS':10})
            self.assertTrue(json.loads(stdout.getvalue())['json_saved']);self.assertNotIn('SECRET_CANARY',stdout.getvalue())


if __name__=='__main__':unittest.main()
