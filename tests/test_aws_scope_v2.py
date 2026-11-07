"""v2 synthetic collection tests; no AWS credentials or network permitted."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cloud_security.aws_scope import AwsScope, AwsOfflineError
from cloud_security import aws_live as live
from config_audit.collectors.aws_security import build_report
from scripts.run_aws_audit import main

FIX=Path(__file__).parent/'fixtures/aws_live'
def read(name): return json.loads((FIX/name).read_text(encoding='utf-8'))

def inputs():
    scope=read('scope.json');scope['schema_version']=2
    scope['resources']['cloudtrail']=[];scope['resources']['logs']=[]
    scope['role_allowed_actions']=[];scope['role_allowed_resources']=[]
    scope['policy']={'criteria_version':'SYNTHETIC-LAB-0.2','iam_role_criteria_confirmed':False,
        'internal_subnet_ids':[],'nacl_criteria_confirmed':True,'trail_required':True,'flow_required':True,'flow_scope':'vpc'}
    plan=read('targets.json');plan['schema_version']=2
    plan['targets']['VPC-01']['resource_id']=plan['vpcs']['ap-northeast-2']
    plan['targets']['CT-01']['resource_id']=scope['account_id']
    script=read('mock_responses.json')
    script['requests']=[r for r in script['requests'] if r['operation'] not in ('describe_internet_gateways','get_trail_status','get_event_selectors')]
    for r in script['requests']:
        if r['operation']=='describe_trails':r['params']={'includeShadowTrails':True};r['response']={'trailList':[]}
        if r['operation']=='describe_flow_logs':
            r['params']['Filters'][0]['Values']=['vpc-001','subnet-001','eni-001'];r['response']={'FlowLogs':[]}
    return scope,plan,script

class AwsScopeV2Tests(unittest.TestCase):
    def setUp(self):
        self.raw,self.plan,self.script=inputs();self.scope=AwsScope.from_dict(self.raw)
        self.guard=patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK'));self.guard.start();self.addCleanup(self.guard.stop)
    def item(self,op):return next(r for r in self.script['requests'] if r['operation']==op)
    def collect(self):return live.collect(self.scope,self.plan,expected_account=self.scope.account_id,allowed_regions=list(self.scope.regions),factory=live.mock_factory(self.script),limits=live.Limits(retries=0))
    def report(self,doc=None):return build_report(doc or self.collect()[0],self.scope,source_reference='synthetic',source_sha256='a'*64)
    def row(self,check,doc=None):return next(r for r in self.report(doc)['results'] if r['check_id']==check)
    def change_scope(self):self.scope=AwsScope.from_dict(self.raw)
    def test_v2_scope_and_plan_accept_missing_criteria_and_no_trail_ids(self):
        live.validate_targets(self.scope,self.plan,self.scope.account_id,list(self.scope.regions))
    def test_empty_trail_is_fail(self):self.assertEqual(self.row('CT-01')['status'],'FAIL')
    def test_empty_flow_is_fail(self):self.assertEqual(self.row('FL-01')['status'],'FAIL')
    def test_missing_iam_criteria_is_review_not_fail_for_star(self):
        row=self.row('IAM-03');self.assertEqual(row['status'],'NEEDS_REVIEW');self.assertIn('policy_statements',row['observed_value']['facts'])
    def test_internal_subnet_unconfirmed_is_review(self):
        row=self.row('VPC-01');self.assertEqual(row['status'],'NEEDS_REVIEW');self.assertTrue(row['observed_value']['facts']['topology'])
    def test_public_default_subnet_not_automatically_private_failure(self):
        self.item('describe_subnets')['response']['Subnets'][0]['MapPublicIpOnLaunch']=True
        self.assertEqual(self.row('VPC-01')['status'],'NEEDS_REVIEW')
    def test_explicit_internal_subnet_public_ip_is_fail(self):
        self.raw['policy']['internal_subnet_ids']=['subnet-001'];self.change_scope()
        self.item('describe_subnets')['response']['Subnets'][0]['MapPublicIpOnLaunch']=True
        self.assertEqual(self.row('VPC-01')['status'],'FAIL')
    def test_confirmed_internal_subnet_clean_is_pass(self):
        self.raw['policy']['internal_subnet_ids']=['subnet-001'];self.change_scope()
        self.assertEqual(self.row('VPC-01')['status'],'PASS')
    def test_trail_denied_is_error(self):
        r=self.item('describe_trails');r.pop('response');r['error_code']='AccessDenied'
        self.assertEqual(self.row('CT-01')['status'],'ERROR')
    def test_trail_missing_field_is_error(self):
        self.item('describe_trails')['response']={};self.assertEqual(self.row('CT-01')['status'],'ERROR')
    def test_trail_unexpected_token_is_incomplete_not_absent_fail(self):
        self.item('describe_trails')['response']['NextToken']='remaining';self.assertEqual(self.row('CT-01')['status'],'NEEDS_REVIEW')
    def test_foreign_trail_is_filtered_no_foreign_id_export(self):
        self.item('describe_trails')['response']['trailList']=[{'TrailARN':'arn:aws:cloudtrail:ap-northeast-2:999999999999:trail/foreign','HomeRegion':'ap-northeast-2'}]
        doc,_=self.collect();self.assertNotIn('999999999999',json.dumps(doc));self.assertEqual(self.row('CT-01',doc)['status'],'NEEDS_REVIEW')
    def test_existing_trail_status_and_selectors_pass(self):
        original=read('mock_responses.json')['requests'];pos=self.script['requests'].index(self.item('describe_trails'))
        self.item('describe_trails')['response']=deepcopy(next(r['response'] for r in original if r['operation']=='describe_trails'))
        follow=[deepcopy(r) for r in original if r['operation'] in ('describe_trails','get_trail_status','get_event_selectors')]
        self.script['requests'][pos+1:pos+1]=follow
        self.assertEqual(self.row('CT-01')['status'],'PASS')
    def test_trail_detail_incomplete_no_false_pass(self):
        original=read('mock_responses.json')['requests'];pos=self.script['requests'].index(self.item('describe_trails'))
        self.item('describe_trails')['response']=deepcopy(next(r['response'] for r in original if r['operation']=='describe_trails'))
        follow=[deepcopy(r) for r in original if r['operation'] in ('describe_trails','get_trail_status','get_event_selectors')]
        follow[0]['response']['NextToken']='unexpected-more'
        self.script['requests'][pos+1:pos+1]=follow
        self.assertEqual(self.row('CT-01')['status'],'NEEDS_REVIEW')
    def test_flow_denied_is_error(self):
        r=self.item('describe_flow_logs');r.pop('response');r['error_code']='UnauthorizedOperation';self.assertEqual(self.row('FL-01')['status'],'ERROR')
    def test_flow_page_limit_is_review(self):
        self.item('describe_flow_logs')['response']['NextToken']='more'
        self.script['requests'].append(deepcopy(self.item('describe_flow_logs')))
        self.script['requests'][-1]['params']['NextToken']='more'
        self.assertEqual(self.row('FL-01')['status'],'NEEDS_REVIEW')
    def flow(self,resource='vpc-001'):
        value=deepcopy(next(r['response']['FlowLogs'][0] for r in read('mock_responses.json')['requests'] if r['operation']=='describe_flow_logs'))
        value['ResourceId']=resource;value['FlowLogId']='fl-abc';self.item('describe_flow_logs')['response']['FlowLogs']=[value];return value
    def test_discovered_flow_without_known_id_or_log_group_can_pass(self):
        self.flow();doc,_=self.collect();self.assertEqual(self.row('FL-01',doc)['status'],'PASS');self.assertNotIn('LogDestination"',json.dumps(doc))
    def test_subnet_flow_does_not_substitute_for_required_vpc_flow(self):
        self.flow('subnet-001');self.assertEqual(self.row('FL-01')['status'],'FAIL')
    def test_eni_flow_does_not_substitute_for_required_vpc_flow(self):
        self.flow('eni-001');self.assertEqual(self.row('FL-01')['status'],'FAIL')
    def test_unscoped_flow_resource_is_error(self):
        self.flow('vpc-fff');self.assertEqual(self.row('FL-01')['status'],'ERROR')
    def test_flow_actual_delivery_still_not_tested(self):
        self.flow();row=self.row('FL-01');self.assertEqual(row['observed_value']['facts']['delivery_verification'],'NOT_TESTED')
    def test_missing_flow_destination_is_error(self):
        value=self.flow();value.pop('LogDestination');self.assertEqual(self.row('FL-01')['status'],'ERROR')
    def test_flow_s3_destination_configuration_supported(self):
        value=self.flow();value['LogDestinationType']='s3';value['LogDestination']='arn:aws:s3:::synthetic-destination'
        self.assertEqual(self.row('FL-01')['status'],'PASS')
    def test_empty_nacl_criteria_not_vacuous_pass(self):
        self.raw['nacl_matrix']=[];self.raw['policy']['nacl_criteria_confirmed']=False;self.change_scope()
        self.assertEqual(self.row('NACL-01')['status'],'NEEDS_REVIEW')
    def test_earlier_nacl_allow_defeats_deny(self):
        acl=self.item('describe_network_acls')['response']['NetworkAcls'][0]
        entry=deepcopy(next(e for e in acl['Entries'] if not e['Egress'] and e['RuleAction']=='deny'))
        entry['RuleNumber']=1;entry['RuleAction']='allow';acl['Entries'].append(entry)
        self.assertEqual(self.row('NACL-01')['status'],'FAIL')
    def test_return_direction_missing_is_review(self):
        acl=self.item('describe_network_acls')['response']['NetworkAcls'][0];acl['Entries']=[e for e in acl['Entries'] if not e['Egress']]
        self.assertEqual(self.row('NACL-01')['status'],'NEEDS_REVIEW')
    def test_account_mismatch_stops(self):
        self.item('get_caller_identity')['response']['Account']='999999999999'
        with self.assertRaises(AwsOfflineError):self.collect()
    def test_wrong_expected_account_rejected_before_factory(self):
        with self.assertRaises(AwsOfflineError):live.validate_targets(self.scope,self.plan,'999999999999',['ap-northeast-2'])
    def test_wrong_region_rejected(self):
        with self.assertRaises(AwsOfflineError):live.validate_targets(self.scope,self.plan,self.scope.account_id,['us-east-1'])
    def test_confirmed_role_without_criteria_rejected(self):
        self.raw['policy']['iam_role_criteria_confirmed']=True
        with self.assertRaises(AwsOfflineError):self.change_scope()
    def test_confirmed_nacl_without_matrix_rejected(self):
        self.raw['nacl_matrix']=[]
        with self.assertRaises(AwsOfflineError):self.change_scope()
    def test_v1_empty_criteria_still_rejected(self):
        self.raw.pop('policy');self.raw['schema_version']=1
        with self.assertRaises(AwsOfflineError):self.change_scope()
    def test_validation_cli_no_factory_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scope.json').write_text(json.dumps(self.raw));(root/'targets.json').write_text(json.dumps(self.plan))
            with patch.object(live,'live_factory',side_effect=AssertionError('FORBIDDEN')),redirect_stdout(io.StringIO()) as out:
                result=main(['--validate-inputs','--scope-json',str(root/'scope.json'),'--targets-json',str(root/'targets.json'),'--expected-account-id',self.scope.account_id,'--allowed-region','ap-northeast-2'])
            self.assertEqual(result,0);self.assertFalse(json.loads(out.getvalue())['network_access'])
    def test_v2_rule_version_distinct(self):self.assertEqual(self.report()['rule_version'],'AWS-LAB-COLLECTION-0.2')
    def test_ct_requirement_unconfirmed_is_review(self):
        self.raw['policy']['trail_required']=False;self.change_scope();self.assertEqual(self.row('CT-01')['status'],'NEEDS_REVIEW')
    def test_flow_requirement_unconfirmed_is_review(self):
        self.raw['policy']['flow_required']=False;self.change_scope();self.assertEqual(self.row('FL-01')['status'],'NEEDS_REVIEW')

    def test_bad_route_cidr_no_pass(self):
        self.raw['policy']['internal_subnet_ids']=['subnet-001'];self.change_scope()
        self.item('describe_route_tables')['response']['RouteTables'][0]['Routes'][0]['DestinationCidrBlock']='invalid'
        self.assertEqual(self.row('VPC-01')['status'],'ERROR')
    def test_unknown_route_target_no_pass(self):
        self.raw['policy']['internal_subnet_ids']=['subnet-001'];self.change_scope()
        route=self.item('describe_route_tables')['response']['RouteTables'][0]['Routes'][0]
        route.pop('GatewayId',None);route['TransitGatewayId']='tgw-not-projected'
        self.assertEqual(self.row('VPC-01')['status'],'NEEDS_REVIEW')
    def test_legacy_subnet_shape_v2_needs_purpose(self):
        doc,_=self.collect();old=json.loads((Path(__file__).parent/'fixtures/aws_audit/pass.json').read_text())
        doc['sections']['VPC-01']={**old['sections']['VPC-01'],'collected_at':doc['sections']['VPC-01']['collected_at']}
        self.assertEqual(self.row('VPC-01',doc)['status'],'NEEDS_REVIEW')
    def test_arbitrary_flow_id_not_general_query_authority(self):
        with self.assertRaises(AwsOfflineError):self.scope.check_resource('ec2','fl-abc')
    def test_foreign_trail_authority_denied(self):
        with self.assertRaises(AwsOfflineError):self.scope.check_resource('cloudtrail','arn:aws:cloudtrail:ap-northeast-2:999999999999:trail/x')
    def test_other_region_trail_authority_denied(self):
        with self.assertRaises(AwsOfflineError):self.scope.check_resource('cloudtrail','arn:aws:cloudtrail:us-east-1:123456789012:trail/x')
    def test_invalid_policy_scope_type_rejected(self):
        self.raw['policy']['internal_subnet_ids']=[{}]
        with self.assertRaises(AwsOfflineError):self.change_scope()
    def test_repeated_unknown_eni_no_false_pass(self):
        self.raw['resources']['ec2'].remove('eni-001');self.change_scope()
        self.assertEqual(self.row('VPC-01')['status'],'NEEDS_REVIEW')
        self.assertNotIn('eni-001',json.dumps(self.collect()[0]))
    def test_full_mock_cli_json_pdf_no_live_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,value in [('scope',self.raw),('targets',self.plan),('mock',self.script)]:
                (root/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
            with patch.object(live,'live_factory',side_effect=AssertionError('FORBIDDEN')),redirect_stdout(io.StringIO()) as out:
                result=main(['--mock-collect','--scope-json',str(root/'scope.json'),'--targets-json',str(root/'targets.json'),
                    '--mock-json',str(root/'mock.json'),'--expected-account-id',self.scope.account_id,'--allowed-region','ap-northeast-2','--output-root',str(root/'runs')])
            self.assertEqual(result,0)
            run=Path(json.loads(out.getvalue())['run_directory']);report=json.loads((run/'report.json').read_text())
            self.assertEqual(len(report['results']),8);self.assertTrue((run/'report.pdf').read_bytes().startswith(b'%PDF'))
            self.assertFalse(report['collection']['network_access_enabled'])

if __name__=='__main__':unittest.main()
