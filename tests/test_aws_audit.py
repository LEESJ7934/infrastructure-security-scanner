"""AWS offline-only fixtures; no credentials, SDK clients or AWS operations."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cloud_security.aws_scope import AwsOfflineError, AwsScope, read_json
from config_audit.collectors import aws_security as aws
from config_audit.aws_report import common_snapshot, write_pdf
from scripts.run_aws_audit import main

FIXTURES = Path(__file__).parent / 'fixtures/aws_audit'


def fixture(name): return json.loads((FIXTURES / (name + '.json')).read_text(encoding='utf-8'))


class AwsAuditTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture('pass')
        self.scope = AwsScope.from_dict(fixture('scope'))

    def report(self, data=None):
        return aws.build_report(data or self.data,self.scope,source_reference='synthetic.json',source_sha256='a'*64,scope_sha256='b'*64)

    def row(self, check, data=None): return next(r for r in self.report(data)['results'] if r['check_id']==check)

    def test_common_engine_evaluates_exactly_eight_checks(self):
        with patch.object(aws,'evaluate',wraps=aws.evaluate) as engine: self.report()
        self.assertEqual(engine.call_count,8)

    def test_next_token_present_blocks_all_eight_passes(self):
        for section in self.data['sections'].values():section['pagination']['next_token_present']=True
        self.assertEqual(self.report()['summary'],{'NEEDS_REVIEW':8})

    def test_empty_cloudtrail_selectors_not_assumed_default_pass(self):
        self.data['sections']['CT-01']['data']['EventSelectors']=[]
        self.assertEqual(self.row('CT-01')['status'],'NEEDS_REVIEW')

    def test_malformed_route_cidr_is_error(self):
        self.data['sections']['VPC-01']['data']['RouteTable']['Routes'][0]['DestinationCidrBlock']='not-a-network'
        self.assertEqual(self.row('VPC-01')['status'],'ERROR')

    def test_no_boto3_client_creation_even_when_module_is_available(self):
        from types import SimpleNamespace
        def forbidden(*args,**kwargs):raise AssertionError('SDK client construction forbidden')
        fake=SimpleNamespace(client=forbidden,Session=forbidden,session=SimpleNamespace(Session=forbidden))
        with patch.dict('sys.modules',{'boto3':fake}),redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--input-json',str(FIXTURES/'pass.json'),'--scope-json',str(FIXTURES/'scope.json')]),0)

    def test_scope_account_partition_region_service_and_resource_blocked(self):
        mutations=[('account',None),('partition',None),('region',None),('service',None),('resource',None)]
        for key,_ in mutations:
            data=deepcopy(self.data)
            if key=='account':data['account_id']='999999999999'
            if key=='partition':data['partition']='aws-cn'
            if key=='region':data['sections']['SG-01']['region']='us-east-1'
            if key=='service':data['sections']['SG-01']['service']='iam'
            if key=='resource':data['sections']['SG-01']['resource_id']='sg-fff'
            with self.subTest(key=key),self.assertRaises(AwsOfflineError):self.report(data)

    def test_nested_resource_scope_blocked(self):
        self.data['sections']['SG-01']['data']['VpcId']='vpc-fff'
        with self.assertRaisesRegex(AwsOfflineError,'resource_scope_mismatch'):self.report()

    def test_cross_account_arn_blocked(self):
        scope=fixture('scope');scope['resources']['iam'][1]=scope['resources']['iam'][1].replace('123456789012','999999999999')
        with self.assertRaisesRegex(AwsOfflineError,'arn_scope_mismatch'):AwsScope.from_dict(scope)

    def test_scope_wildcard_target_rejected(self):
        scope=fixture('scope');scope['resources']['ec2']=['*']
        with self.assertRaises(AwsOfflineError):AwsScope.from_dict(scope)

    def test_root_centralized_removed_is_not_applicable(self):
        self.data['sections']['IAM-02']['data']={'SummaryMap':{'AccountMFAEnabled':0,'AccountPasswordPresent':0,'AccountAccessKeysPresent':0,'AccountSigningCertificatesPresent':0},'CentralizedRootManagement':{'Verified':True,'CredentialsRemoved':True}}
        row=self.row('IAM-02');self.assertEqual(row['status'],'NOT_APPLICABLE')
        self.assertIn('input_declaration',row['observed_value']['facts']['context_basis'])

    def test_root_mfa_zero_without_management_context_review(self):
        self.data['sections']['IAM-02']['data']={'SummaryMap':{'AccountMFAEnabled':0,'AccountPasswordPresent':0,'AccountAccessKeysPresent':0,'AccountSigningCertificatesPresent':0}}
        self.assertEqual(self.row('IAM-02')['status'],'NEEDS_REVIEW')

    def test_root_context_does_not_hide_existing_credentials_without_mfa(self):
        data=self.data['sections']['IAM-02']['data'];data['SummaryMap']['AccountMFAEnabled']=0
        data['CentralizedRootManagement']={'Verified':True,'CredentialsRemoved':True}
        self.assertEqual(self.row('IAM-02')['status'],'FAIL')

    def test_resource_star_justified_describe_is_pass(self):
        row=self.row('IAM-03');self.assertEqual(row['status'],'PASS')
        self.assertEqual(row['observed_value']['facts']['justified_resource_star_count'],1)

    def test_s3_resource_star_is_fail(self):
        self.data['sections']['IAM-03']['data']['PolicyDocuments'][0]['Statement'][1]['Resource']='*'
        self.assertEqual(self.row('IAM-03')['status'],'FAIL')

    def test_complex_iam_condition_notaction_and_partial_policy_review(self):
        for extra in ({'Condition':{'StringEquals':{'aws:RequestedRegion':'ap-northeast-2'}}},{'NotAction':'iam:*'}):
            data=deepcopy(self.data);data['sections']['IAM-03']['data']['PolicyDocuments'][0]['Statement'][0].update(extra)
            self.assertEqual(self.row('IAM-03',data)['status'],'NEEDS_REVIEW')
        self.data['sections']['IAM-03']['data']['PolicySetComplete']=False
        self.assertEqual(self.row('IAM-03')['status'],'NEEDS_REVIEW')

    def test_all_port_sg_rule_not_misread_as_missing_specific_findings(self):
        self.data['sections']['SG-01']['data']['IpPermissions']=[{'IpProtocol':'-1','IpRanges':[{'CidrIp':'0.0.0.0/0'}],'Ipv6Ranges':[],'UserIdGroupPairs':[]}]
        row=self.row('SG-01');self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['observed_value']['facts']['legacy_rule_ids'],['AWS-SG-006'])

    def test_sg_existing_inventory_and_analyzer_reused(self):
        from cloud_security import aws_observations as normalizer
        with patch.object(normalizer,'_normalize_sg',wraps=normalizer._normalize_sg) as inventory,patch.object(normalizer,'analyze_resource',wraps=normalizer.analyze_resource) as analyze:
            self.report()
        inventory.assert_called_once();analyze.assert_called_once()

    def test_ipv6_worldwide_sg_is_fail(self):
        self.data['sections']['SG-01']['data']['IpPermissions']=[{'IpProtocol':'6','FromPort':3306,'ToPort':3306,'IpRanges':[],'Ipv6Ranges':[{'CidrIpv6':'::/0'}],'UserIdGroupPairs':[]}]
        self.assertEqual(self.row('SG-01')['status'],'FAIL')

    def test_sg_prefix_list_not_expanded_prevents_pass(self):
        self.data['sections']['SG-01']['data']['IpPermissions']=[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[],'Ipv6Ranges':[],'UserIdGroupPairs':[],'PrefixListIds':[{'PrefixListId':'pl-example'}]}]
        self.assertEqual(self.row('SG-01')['status'],'NEEDS_REVIEW')

    def test_subnet_direct_igw_and_ipv6_public_address_fail(self):
        data=deepcopy(self.data);data['sections']['VPC-01']['data']['RouteTable']['Routes'].append({'DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-001','State':'active'})
        self.assertEqual(self.row('VPC-01',data)['status'],'FAIL')
        self.data['sections']['VPC-01']['data']['NetworkInterfaces'][0]['Ipv6Addresses']=[{'Ipv6Address':'2600:1f00::10'}]
        self.assertEqual(self.row('VPC-01')['status'],'FAIL')

    def test_subnet_unresolved_and_empty_route_table_review(self):
        data=deepcopy(self.data);data['sections']['VPC-01']['data']['RouteTableAssociationResolved']=False
        self.assertEqual(self.row('VPC-01',data)['status'],'NEEDS_REVIEW')
        self.data['sections']['VPC-01']['data']['RouteTable']['Routes']=[]
        self.assertEqual(self.row('VPC-01')['status'],'NEEDS_REVIEW')

    def test_nacl_earlier_allow_overrides_later_deny(self):
        entries=self.data['sections']['NACL-01']['data']['Entries']
        entries.extend([{'RuleNumber':10,'Egress':False,'Protocol':'-1','RuleAction':'allow','CidrBlock':'0.0.0.0/0'},
            {'RuleNumber':20,'Egress':False,'Protocol':'6','RuleAction':'deny','CidrBlock':'198.51.100.0/24','PortRange':{'From':22,'To':22}}])
        row=self.row('NACL-01');self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['observed_value']['facts']['matrix_results'][0]['ingress_rule_number'],10)

    def test_nacl_return_traffic_required_for_allow_case(self):
        entries=self.data['sections']['NACL-01']['data']['Entries']
        self.data['sections']['NACL-01']['data']['Entries']=[e for e in entries if not(e['Egress'] and e['RuleNumber']==100)]
        row=self.row('NACL-01');self.assertEqual(row['status'],'FAIL')
        self.assertFalse(row['observed_value']['facts']['actual_reachability_verified'])

    def test_nacl_missing_direction_and_duplicate_rule(self):
        data=deepcopy(self.data);data['sections']['NACL-01']['data']['Entries']=[e for e in data['sections']['NACL-01']['data']['Entries'] if not e['Egress']]
        self.assertEqual(self.row('NACL-01',data)['status'],'NEEDS_REVIEW')
        self.data['sections']['NACL-01']['data']['Entries'].append(deepcopy(self.data['sections']['NACL-01']['data']['Entries'][0]))
        self.assertEqual(self.row('NACL-01')['status'],'ERROR')

    def test_cloudtrail_management_write_only_and_advanced_selectors(self):
        data=deepcopy(self.data);data['sections']['CT-01']['data']['EventSelectors'][0]['ReadWriteType']='WriteOnly'
        self.assertEqual(self.row('CT-01',data)['status'],'FAIL')
        self.data['sections']['CT-01']['data']['AdvancedEventSelectors']=[{'Name':'unsupported-selector'}]
        self.assertEqual(self.row('CT-01')['status'],'NEEDS_REVIEW')

    def test_cloudtrail_and_flow_config_pass_never_claim_records_verified(self):
        for check in ('CT-01','FL-01'):
            row=self.row(check);self.assertEqual(row['status'],'PASS')
            self.assertEqual(row['observed_value']['facts']['delivery_verification'],'NOT_TESTED')
            self.assertEqual(row['analyses']['log_delivery_records'],'NOT_TESTED')

    def test_flow_pending_failure_accept_only_and_uncovered_target(self):
        for field,value,expected in [('FlowLogStatus','PENDING','NEEDS_REVIEW'),('DeliverLogsStatus','FAILED','FAIL'),('TrafficType','ACCEPT','FAIL'),('ResourceId','subnet-001','FAIL')]:
            data=deepcopy(self.data);data['sections']['FL-01']['data']['FlowLogs'][0][field]=value
            self.assertEqual(self.row('FL-01',data)['status'],expected)

    def test_malformed_response_is_error(self):
        self.data['sections']['IAM-01']['data']['SummaryMap']['AccountAccessKeysPresent']='0'
        self.assertEqual(self.row('IAM-01')['status'],'ERROR')

    def test_unknown_checks_and_p2_not_implicitly_enabled(self):
        self.data['sections']['SG-02']=deepcopy(self.data['sections']['SG-01'])
        with self.assertRaises(AwsOfflineError):self.report()

    def test_invalid_json_duplicate_keys_missing_file_and_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input.json'
            with self.assertRaises(AwsOfflineError):read_json(p)
            for text in ('{broken','{"x":1,"x":2}','{"x":NaN}'):
                p.write_text(text)
                with self.assertRaises(AwsOfflineError):read_json(p)

    def test_sensitive_input_not_echoed(self):
        self.data['sections']['IAM-01']['data']['password']='SECRET_CANARY'
        with self.assertRaisesRegex(AwsOfflineError,'sensitive_input_rejected'):self.report()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input.json';p.write_text(json.dumps(self.data));stdout=io.StringIO()
            with redirect_stdout(stdout):self.assertEqual(main(['--input-json',str(p),'--scope-json',str(FIXTURES/'scope.json')]),2)
            self.assertNotIn('SECRET_CANARY',stdout.getvalue())

    def test_timestamps_preserve_offset_and_collection_vs_analysis(self):
        self.data['collected_at']='2026-01-01T09:01:00+09:00'
        for s in self.data['sections'].values():s['collected_at']=self.data['collected_at']
        report=self.report();self.assertEqual(report['results'][0]['collected_at'],self.data['collected_at'])
        self.assertNotEqual(report['generated_at'],self.data['collected_at'])
        self.data['collected_at']='2026-01-01T09:01:00'
        with self.assertRaises(AwsOfflineError):self.report()

    def test_hash_without_independent_expectation_not_verified(self):
        report=aws.load_report(FIXTURES/'pass.json',FIXTURES/'scope.json')
        self.assertEqual(report['evidence']['hash_comparison'],'NOT_VERIFIED')
        self.assertFalse(report['evidence']['independently_verified'])
        self.assertEqual(report['evidence']['file_sha256'],hashlib.sha256((FIXTURES/'pass.json').read_bytes()).hexdigest())

    def test_declared_hash_match_not_source_authentication_and_tamper_blocked(self):
        hashed=hashlib.sha256((FIXTURES/'pass.json').read_bytes()).hexdigest()
        report=aws.load_report(FIXTURES/'pass.json',FIXTURES/'scope.json',expected_sha256=hashed)
        self.assertEqual(report['evidence']['hash_comparison'],'MATCH_DECLARED_HASH')
        self.assertFalse(report['evidence']['independently_verified'])
        with self.assertRaisesRegex(AwsOfflineError,'input_hash_mismatch'):aws.load_report(FIXTURES/'fail.json',FIXTURES/'scope.json',expected_sha256=hashed)

    def test_declared_aws_snapshot_origin_not_attestation(self):
        self.data['origin']='aws_collected_snapshot';report=self.report()
        self.assertEqual(report['origin'],'aws_collected_snapshot')
        self.assertEqual(report['origin_basis'],'input_declaration_not_remote_attestation')

    def test_common_report_model_keeps_automatic_channel(self):
        s=common_snapshot(self.report(),'synthetic-pass')
        self.assertEqual(len(s['results']),8)
        self.assertTrue(all(r['manual'] is None for r in s['results']))

    def test_comparison_records_transitions_without_claiming_remediation(self):
        before=self.report(fixture('fail'));after=self.report()
        result=aws.compare_reports(before,after)
        self.assertEqual(result['summary'],{'IMPROVED_OBSERVED':8})
        self.assertTrue(all(not r['actual_remediation_proven'] for r in result['results']))
        before['results'][0]['status']='ERROR'
        self.assertEqual(aws.compare_reports(before,after)['results'][0]['comparison_result'],'UNVERIFIABLE')

    def test_comparison_duplicates_invalid_status_scope_and_time(self):
        before=self.report(fixture('fail'));after=self.report()
        before['results'].append(deepcopy(before['results'][0]))
        self.assertEqual(aws.compare_reports(before,after)['results'][0]['comparison_result'],'UNVERIFIABLE')
        before=self.report(fixture('fail'));before['results'][0]['status']='NOT_A_STATUS'
        with self.assertRaises(AwsOfflineError):aws.compare_reports(before,after)
        before=self.report(fixture('fail'));before['scope_sha256']='c'*64
        self.assertEqual(aws.compare_reports(before,after)['summary'],{'INCOMPARABLE':8})
        before=self.report(fixture('fail'));before['snapshot_collected_at']=after['snapshot_collected_at']
        self.assertEqual(aws.compare_reports(before,after)['summary'],{'INCOMPARABLE':8})

    def test_cli_offline_sdk_socket_and_subprocess_guards(self):
        import subprocess
        with patch('cloud_security.aws_inventory.create_live_clients',side_effect=AssertionError('NO_SDK')),patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_PROCESSES')),redirect_stdout(io.StringIO()):
            self.assertEqual(main([]),0)
            self.assertEqual(main(['--dry-run']),0)
            self.assertEqual(main(['--input-json',str(FIXTURES/'pass.json'),'--scope-json',str(FIXTURES/'scope.json'),'--dry-run']),0)

    def test_cli_rejects_live_execute_option(self):
        with redirect_stdout(io.StringIO()),patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit):main(['--execute'])

    def test_no_overwrite_and_dry_run_no_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'keep.json';p.write_text('PRESERVE')
            args=['--input-json',str(FIXTURES/'pass.json'),'--scope-json',str(FIXTURES/'scope.json'),'--output',str(p)]
            with redirect_stdout(io.StringIO()):self.assertEqual(main(args),2)
            self.assertEqual(p.read_text(),'PRESERVE')
            new=Path(tmp)/'dry.json'
            with redirect_stdout(io.StringIO()):self.assertEqual(main(args[:-1]+[str(new),'--dry-run']),2)
            self.assertFalse(new.exists())

    def test_cli_json_pdf_same_statuses_and_synthetic_label(self):
        from pypdf import PdfReader
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'report.json';pdf=Path(tmp)/'report.pdf'
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--input-json',str(FIXTURES/'pass.json'),'--scope-json',str(FIXTURES/'scope.json'),'--output',str(output),'--pdf',str(pdf)]),0)
            saved=json.loads(output.read_text(encoding='utf-8'));text='\n'.join(p.extract_text() for p in PdfReader(pdf).pages)
            self.assertIn('합성 테스트',text)
            for row in saved['results']:self.assertIn(row['check_id']+' | '+row['status'],text)


def control_case(check, case):
    def test(self):
        data=fixture('fail' if case=='fail' else 'pass');section=data['sections'][check]
        expected={'pass':'PASS','fail':'FAIL','missing':'NEEDS_REVIEW','error':'ERROR','partial':'NEEDS_REVIEW','not_tested':'NOT_TESTED'}[case]
        if case=='missing':section['data']={}
        elif case=='error':section.update(state='ERROR',data=None,error_code='AccessDenied')
        elif case=='partial':section['pagination']['complete']=False
        elif case=='not_tested':section.update(state='NOT_TESTED',data=None)
        self.assertEqual(self.row(check,data)['status'],expected)
    return test


for _check in aws.CHECKS:
    for _case in ('pass','fail','missing','error','partial','not_tested'):
        setattr(AwsAuditTests,'test_'+_check.lower().replace('-','_')+'_'+_case,control_case(_check,_case))


if __name__=='__main__':unittest.main()
