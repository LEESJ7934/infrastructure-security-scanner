"""Injected/scripted AWS clients only. Never uses credentials or live_factory."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cloud_security.aws_scope import AwsScope, AwsOfflineError
from cloud_security import aws_live as live
from config_audit.collectors.aws_security import build_report, load_report
from scripts.run_aws_audit import main

FIX=Path(__file__).parent/'fixtures/aws_live'


def read(name):return json.loads((FIX/name).read_text(encoding='utf-8'))


class AwsLiveTests(unittest.TestCase):
    def setUp(self):
        self.scope=AwsScope.from_dict(read('scope.json'));self.plan=read('targets.json');self.script=read('mock_responses.json')

    def run_collection(self,script=None,scope=None,plan=None,limits=None,**kwargs):
        scope=scope or self.scope
        return live.collect(scope,plan or self.plan,expected_account=scope.account_id,allowed_regions=list(scope.regions),
            factory=live.mock_factory(script or self.script),limits=limits or live.Limits(retries=0),sleep=lambda _:None,**kwargs)

    def report(self,document):return build_report(document,self.scope,source_reference='synthetic-mock.json',source_sha256='a'*64)

    def entry(self,operation,script=None):return next(r for r in (script or self.script)['requests'] if r['operation']==operation)

    def replace_response(self,operation,error):
        item=self.entry(operation);item.pop('response',None);item['error_code']=error

    def test_sts_matching_and_eight_checks_use_common_schema(self):
        document,audit=self.run_collection()
        self.assertTrue(audit['account_match']);self.assertEqual(audit['actual_account_id'],self.scope.account_id)
        self.assertEqual(audit['call_count'],19);self.assertEqual(len(audit['checks']),8)
        self.assertEqual(document['origin'],'synthetic');self.assertEqual(self.report(document)['summary'],{'PASS':8})

    def test_shared_account_summary_keeps_original_request_and_time(self):
        document,audit=self.run_collection()
        self.assertEqual(audit['checks']['IAM-01']['api_request_indexes'],audit['checks']['IAM-02']['api_request_indexes'])
        self.assertTrue(audit['checks']['IAM-02']['api_request_indexes'])
        self.assertEqual(document['sections']['IAM-01']['collected_at'],document['sections']['IAM-02']['collected_at'])

    def test_sts_mismatch_stops_before_any_other_client(self):
        calls=[]
        def factory(service,region):
            calls.append(service)
            return SimpleNamespace(get_caller_identity=lambda:{'Account':'999999999999','Arn':'arn:aws:iam::999999999999:root'})
        with self.assertRaisesRegex(AwsOfflineError,'STS_account_mismatch') as caught:
            live.collect(self.scope,self.plan,expected_account=self.scope.account_id,allowed_regions=list(self.scope.regions),factory=factory)
        self.assertEqual(calls,['sts']);audit=caught.exception.collection_audit
        self.assertFalse(audit['account_match']);self.assertIsNone(audit['actual_account_id'])
        self.assertNotIn('999999999999',json.dumps(audit))

    def test_sts_partition_mismatch_stops(self):
        item=self.entry('get_caller_identity');item['response']['Arn']='arn:aws-cn:iam::123456789012:root'
        with self.assertRaisesRegex(AwsOfflineError,'STS_identity_malformed'):self.run_collection()

    def test_missing_credentials_safe_and_no_service_client(self):
        NoCredentialsError=type('NoCredentialsError',(Exception,),{})
        created=[]
        def factory(service,region):created.append(service);raise NoCredentialsError('SECRET_CANARY')
        with self.assertRaisesRegex(AwsOfflineError,'NoCredentials') as caught:
            live.collect(self.scope,self.plan,expected_account=self.scope.account_id,allowed_regions=list(self.scope.regions),factory=factory)
        self.assertEqual(created,['sts']);self.assertNotIn('SECRET_CANARY',json.dumps(caught.exception.collection_audit))

    def test_expected_account_and_region_required_before_factory(self):
        factory=lambda *_:self.fail('must not create any client')
        for account,regions in [('999999999999',list(self.scope.regions)),(self.scope.account_id,['us-east-1'])]:
            with self.assertRaises(AwsOfflineError):live.collect(self.scope,self.plan,expected_account=account,allowed_regions=regions,factory=factory)

    def test_target_resource_region_and_vpc_mismatch_blocked(self):
        for mode in ('resource','region','vpc'):
            plan=deepcopy(self.plan)
            if mode=='resource':plan['targets']['SG-01']['resource_id']='sg-fff'
            elif mode=='region':plan['targets']['SG-01']['region']='us-east-1'
            else:plan['targets']['FL-01']['resource_id']='vpc-fff'
            with self.assertRaises(AwsOfflineError):live.validate_targets(self.scope,plan,self.scope.account_id,list(self.scope.regions))

    def test_reader_blocks_changes_and_unscoped_list_before_call(self):
        reader=live.Reader(self.scope,lambda *_:self.fail('no client'),live.Limits());reader.identified=True
        for operation,params in [('create_security_group',{}),('describe_security_groups',{}),('describe_security_groups',{'GroupIds':['sg-fff']}),('describe_route_tables',{'Filters':[{'Name':'association.main','Values':['true']}]})]:
            with self.assertRaises(AwsOfflineError):reader.call('ec2',self.scope.regions[0],operation,params)
        self.assertEqual(reader.calls,0)

    def test_non_sts_reads_blocked_before_identity(self):
        reader=live.Reader(self.scope,lambda *_:self.fail('no client'),live.Limits())
        with self.assertRaisesRegex(AwsOfflineError,'STS_identity_required'):reader.call('iam','global','get_account_summary')

    def test_access_denied_single_api_does_not_erase_other_results(self):
        self.replace_response('describe_security_groups','AccessDenied')
        document,audit=self.run_collection();r=self.report(document)
        self.assertEqual(r['summary'],{'PASS':7,'ERROR':1});self.assertEqual(document['sections']['SG-01']['error_code'],'AccessDenied')
        self.assertTrue(any(not x['success'] and x['api']=='ec2:DescribeSecurityGroups' for x in audit['requests']))

    def test_account_summary_denial_affects_both_root_checks_only(self):
        self.replace_response('get_account_summary','AccessDenied')
        document,audit=self.run_collection();self.assertEqual(self.report(document)['summary'],{'ERROR':2,'PASS':6})
        self.assertEqual(sum(x['api']=='iam:GetAccountSummary' for x in audit['requests']),1)

    def test_pagination_completion_is_recorded_per_api(self):
        self.entry('describe_flow_logs')['response']['NextToken']='not-read'
        _,audit=self.run_collection(limits=live.Limits(max_pages=1,retries=0))
        flow=next(p for p in audit['pagination'] if p['api']=='ec2:DescribeFlowLogs')
        self.assertFalse(flow['complete']);self.assertEqual(flow['reason'],'page_limit_reached')

    def test_sdk_rejects_non_aws_or_non_https_endpoint_before_request(self):
        import sys
        class Session:
            def __init__(self,**_):self._session=SimpleNamespace(set_config_variable=lambda *a:None)
            def client(self,*args,**kwargs):return SimpleNamespace(meta=SimpleNamespace(endpoint_url='http://untrusted.invalid'))
        fake=SimpleNamespace(session=SimpleNamespace(Session=Session))
        with patch.dict(sys.modules,{'boto3':fake,'botocore.config':SimpleNamespace(Config=lambda **_:None)}):
            factory=live.live_factory(self.scope,live.Limits())
            with self.assertRaisesRegex(AwsOfflineError,'EndpointRejected'):factory('sts','ap-northeast-2')

    def test_iam_pages_are_merged(self):
        i=next(i for i,x in enumerate(self.script['requests']) if x['operation']=='list_attached_role_policies')
        first=self.script['requests'][i];full=deepcopy(first)
        first['response']={'AttachedPolicies':[],'IsTruncated':True,'Marker':'page-2'}
        full['params']['Marker']='page-2';self.script['requests'].insert(i+1,full)
        document,audit=self.run_collection();self.assertEqual(self.report(document)['summary'],{'PASS':8})
        self.assertEqual(document['sections']['IAM-03']['pagination']['pages'],2);self.assertEqual(audit['call_count'],20)

    def test_iam_truncated_without_marker_never_passes(self):
        self.entry('list_attached_role_policies')['response']['IsTruncated']=True
        document,_=self.run_collection();self.assertEqual(self.report(document)['results'][2]['status'],'NEEDS_REVIEW')

    def test_iam_missing_truncation_metadata_never_passes(self):
        self.entry('list_role_policies')['response'].pop('IsTruncated')
        document,_=self.run_collection();self.assertFalse(document['sections']['IAM-03']['pagination']['complete'])
        self.assertEqual(self.report(document)['results'][2]['status'],'NEEDS_REVIEW')

    def test_ec2_pagination(self):
        i=next(i for i,x in enumerate(self.script['requests']) if x['operation']=='describe_network_interfaces')
        first=self.script['requests'][i];next_page=deepcopy(first)
        first['response']={'NetworkInterfaces':[],'NextToken':'eni-2'};next_page['params']['NextToken']='eni-2';self.script['requests'].insert(i+1,next_page)
        document,_=self.run_collection();self.assertEqual(self.report(document)['summary'],{'PASS':8})

    def test_page_limit_blocks_partial_pass(self):
        self.entry('describe_flow_logs')['response']['NextToken']='unread-page'
        document,_=self.run_collection(limits=live.Limits(max_pages=1,retries=0))
        self.assertEqual(self.report(document)['results'][-1]['status'],'NEEDS_REVIEW')

    def test_repeated_token_never_passes(self):
        client=SimpleNamespace(describe_flow_logs=lambda **_:{'FlowLogs':[],'NextToken':'repeat'})
        reader=live.Reader(self.scope,lambda *_:client,live.Limits(retries=0));reader.identified=True
        rows,pages,complete=reader.pages('ec2',self.scope.regions[0],'describe_flow_logs','FlowLogs',{'Filters':[{'Name':'resource-id','Values':['vpc-001']}]})
        self.assertEqual(pages,2);self.assertFalse(complete)

    def test_second_page_access_denied_is_error_not_empty_success(self):
        i=next(i for i,x in enumerate(self.script['requests']) if x['operation']=='describe_flow_logs')
        first=self.script['requests'][i];second=deepcopy(first);first['response']['NextToken']='last-page'
        second.pop('response');second.update(error_code='AccessDenied');second['params']['NextToken']='last-page';self.script['requests'].insert(i+1,second)
        document,_=self.run_collection();self.assertEqual(document['sections']['FL-01']['state'],'ERROR')
        self.assertEqual(self.report(document)['results'][-1]['status'],'ERROR')

    def test_call_limit_no_more_real_attempts(self):
        document,audit=self.run_collection(limits=live.Limits(max_calls=1,retries=0))
        self.assertEqual(audit['call_count'],1);self.assertEqual(self.report(document)['summary'],{'ERROR':8})
        self.assertTrue(all(s['error_code']=='CallLimitExceeded' for s in document['sections'].values()))
        self.assertTrue(all(s['pagination']['pages']==0 for s in document['sections'].values()))

    def test_timeout_is_recorded_without_raw_error(self):
        reader=live.Reader(self.scope,lambda *_:SimpleNamespace(get_caller_identity=lambda:(_ for _ in ()).throw(TimeoutError('SECRET_CANARY'))),live.Limits(retries=0))
        with self.assertRaisesRegex(AwsOfflineError,'Timeout'):reader.identity()
        self.assertNotIn('SECRET_CANARY',json.dumps(reader.audit))

    def test_retry_count_consumes_budget_and_is_bounded(self):
        first=deepcopy(self.script['requests'][0]);first.pop('response');first['error_code']='Throttling'
        self.script['requests'].insert(0,first)
        document,audit=self.run_collection(limits=live.Limits(retries=1))
        self.assertEqual(audit['call_count'],20);self.assertEqual(self.report(document)['summary'],{'PASS':8})
        self.assertEqual(audit['requests'][1]['attempt'],2)

    def test_overall_deadline_before_and_after_call(self):
        times=iter([0,10]);reader=live.Reader(self.scope,lambda *_:self.fail('no request after deadline'),live.Limits(max_seconds=5),clock=lambda:next(times))
        with self.assertRaisesRegex(AwsOfflineError,'DeadlineExceeded'):reader.identity()
        times=iter([0,0,10]);reader=live.Reader(self.scope,lambda *_:SimpleNamespace(get_caller_identity=lambda:{'Account':self.scope.account_id,'Arn':'arn:aws:iam::123456789012:root'}),live.Limits(max_seconds=5),clock=lambda:next(times))
        with self.assertRaisesRegex(AwsOfflineError,'DeadlineExceeded'):reader.identity()

    def test_missing_response_result_is_parse_error(self):
        self.entry('describe_security_groups')['response']={}
        document,_=self.run_collection();self.assertEqual(document['sections']['SG-01']['error_code'],'ParseError')

    def test_wrong_owner_vpc_and_identity_are_scope_errors(self):
        for key,value in [('OwnerId','999999999999'),('VpcId','vpc-fff'),('GroupId','sg-fff')]:
            script=deepcopy(self.script);self.entry('describe_security_groups',script)['response']['SecurityGroups'][0][key]=value
            document,_=self.run_collection(script=script);self.assertEqual(document['sections']['SG-01']['state'],'ERROR')
            self.assertNotIn('999999999999',json.dumps(document));self.assertNotIn('sg-fff',json.dumps(document))

    def test_unlisted_eni_and_flow_id_mark_partial_without_leaking(self):
        self.entry('describe_network_interfaces')['response']['NetworkInterfaces'][0]['NetworkInterfaceId']='eni-fff'
        self.entry('describe_flow_logs')['response']['FlowLogs'][0]['FlowLogId']='fl-fff'
        document,_=self.run_collection();statuses={r['check_id']:r['status'] for r in self.report(document)['results']}
        self.assertEqual(statuses['VPC-01'],'NEEDS_REVIEW');self.assertEqual(statuses['FL-01'],'NEEDS_REVIEW')
        self.assertNotIn('eni-fff',json.dumps(document));self.assertNotIn('fl-fff',json.dumps(document))

    def test_main_route_table_fallback(self):
        i=next(i for i,x in enumerate(self.script['requests']) if x['operation']=='describe_route_tables')
        first=self.script['requests'][i];main=deepcopy(first);first['response']={'RouteTables':[]}
        main['params']={'Filters':[{'Name':'vpc-id','Values':['vpc-001']},{'Name':'association.main','Values':['true']}]}
        main['response']['RouteTables'][0]['Associations']=[{'Main':True}];self.script['requests'].insert(i+1,main)
        document,_=self.run_collection();self.assertEqual(self.report(document)['summary'],{'PASS':8})

    def test_url_encoded_policy_document(self):
        from urllib.parse import quote
        policy=self.entry('get_role_policy')['response'];policy['PolicyDocument']=quote(json.dumps(policy['PolicyDocument']))
        document,_=self.run_collection();self.assertEqual(self.report(document)['results'][2]['status'],'PASS')

    def test_missing_policy_default_version_does_not_pass(self):
        self.entry('get_policy_version')['response']['PolicyVersion'].pop('IsDefaultVersion')
        document,_=self.run_collection();self.assertEqual(self.report(document)['results'][2]['status'],'ERROR')

    def test_unlisted_policy_not_fetched_and_marked_incomplete(self):
        scope_data=read('scope.json');scope_data['resources']['iam']=scope_data['resources']['iam'][:-1];scope=AwsScope.from_dict(scope_data)
        self.script['requests']=[r for r in self.script['requests'] if r['operation'] not in ('get_policy','get_policy_version')]
        document,audit=self.run_collection(scope=scope);self.assertEqual(document['sections']['IAM-03']['pagination']['complete'],False)
        self.assertFalse(any(r['api']=='iam:GetPolicy' for r in audit['requests']))

    def test_aws_managed_policy_must_be_explicitly_scoped(self):
        data=read('scope.json');arn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore';data['resources']['iam'].append(arn)
        scope=AwsScope.from_dict(data);scope.check_resource('iam',arn)
        with self.assertRaises(AwsOfflineError):self.scope.check_resource('iam',arn)

    def test_cloudtrail_regional_statuses_and_org_limit(self):
        data=read('scope.json');data['regions'].append('us-east-1');scope=AwsScope.from_dict(data)
        i=next(i for i,x in enumerate(self.script['requests']) if x['operation']=='get_trail_status');other=deepcopy(self.script['requests'][i]);other['region']='us-east-1';other['response']['IsLogging']=False
        self.script['requests'].insert(i+1,other);self.entry('describe_trails')['response']['trailList'][0]['IsOrganizationTrail']=True
        document,audit=self.run_collection(scope=scope)
        report=build_report(document,scope,source_reference='mock',source_sha256='a'*64)
        self.assertEqual(next(r for r in report['results'] if r['check_id']=='CT-01')['status'],'FAIL')
        self.assertEqual(set(document['sections']['CT-01']['data']['RegionalStatuses']),set(scope.regions))
        self.assertIn('organization_trail_visibility_limited_to_authorized_account_regions',audit['warnings'])

    def test_cloudtrail_regional_access_denied_not_trail_absence(self):
        self.replace_response('get_trail_status','AccessDenied')
        self.script['requests']=[r for r in self.script['requests'] if r['operation']!='get_event_selectors']
        document,_=self.run_collection();self.assertEqual(document['sections']['CT-01']['state'],'ERROR')
        self.assertEqual(document['sections']['CT-01']['error_code'],'AccessDenied')

    def test_cloudtrail_missing_both_selector_fields_is_error(self):
        response=self.entry('get_event_selectors')['response'];response.pop('EventSelectors')
        document,_=self.run_collection();self.assertEqual(document['sections']['CT-01']['error_code'],'ParseError')

    def test_cloudwatch_arn_suffix_is_canonicalized_not_wildcard_authorized(self):
        flow=self.entry('describe_flow_logs')['response']['FlowLogs'][0];flow['LogDestination']+=':*'
        document,_=self.run_collection();self.assertEqual(self.report(document)['summary'],{'PASS':8})
        self.assertFalse(document['sections']['FL-01']['data']['FlowLogs'][0]['LogDestination'].endswith(':*'))

    def test_raw_headers_tags_userid_and_error_message_not_persisted(self):
        self.entry('get_account_summary')['response']['ResponseMetadata']={'HTTPHeaders':{'Authorization':'SECRET_CANARY'}}
        self.entry('describe_security_groups')['response']['SecurityGroups'][0]['Tags']=[{'Key':'password','Value':'SECRET_CANARY'}]
        document,audit=self.run_collection();self.assertNotIn('SECRET_CANARY',json.dumps([document,audit,self.report(document)]))
        self.assertNotIn('synthetic-not-exported',json.dumps(audit))

    def test_client_error_message_never_echoed(self):
        error=RuntimeError('SECRET_CANARY');error.response={'Error':{'Code':'AccessDenied','Message':'SECRET_CANARY'}}
        self.assertEqual(live.error_code(error),'AccessDenied')

    def test_unknown_error_code_cannot_leak_secret(self):
        self.assertEqual(live.error_code(live.AcquisitionError('SECRET_CANARY')),'QueryFailed')
        self.replace_response('describe_security_groups','SECRET_CANARY')
        document,audit=self.run_collection();self.assertNotIn('SECRET_CANARY',json.dumps([document,audit]))

    def test_permission_example_contains_only_implemented_read_operations(self):
        policy=json.loads((FIX.parents[2]/'config/aws-audit-readonly-policy.example.json').read_text())
        actions=[]
        for statement in policy['Statement']:actions.extend(statement['Action'] if isinstance(statement['Action'],list) else [statement['Action']])
        allowed={service+':'+api for service,ops in live.OPERATIONS.items() for api in ops.values()}
        self.assertEqual(set(actions),allowed)

    def test_limits_reject_unbounded_values(self):
        for limits in [live.Limits(max_calls=0),live.Limits(retries=3),live.Limits(read_timeout=100),live.Limits(max_pages=99)]:
            with self.assertRaises(AwsOfflineError):limits.validate()

    def args(self,tmp,live_mode=False):
        args=['--live-collect' if live_mode else '--mock-collect','--scope-json',str(FIX/'scope.json'),'--targets-json',str(FIX/'targets.json'),
              '--expected-account-id','123456789012','--allowed-region','ap-northeast-2','--output-root',str(tmp)]
        if not live_mode:args+=['--mock-json',str(FIX/'mock_responses.json')]
        return args

    def test_mock_cli_no_network_sdk_and_unique_directories(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK')),patch.object(live,'live_factory',side_effect=AssertionError('NO_LIVE_FACTORY')):
            for _ in range(2):
                with redirect_stdout(io.StringIO()):self.assertEqual(main(self.args(tmp)),0)
            directories=list(Path(tmp).iterdir());self.assertEqual(len(directories),2)
            for directory in directories:
                self.assertTrue(all((directory/name).is_file() for name in ('snapshot.json','collection.json','report.json','report.pdf','manifest.json')))
                report=json.loads((directory/'report.json').read_text(encoding='utf-8'));self.assertEqual(report['summary'],{'PASS':8})
                self.assertEqual(report['collection']['mode'],'MOCK_COLLECTION');self.assertFalse(report['collection']['network_access_enabled'])

    def test_live_cli_requires_explicit_flags_and_dryrun_blocks_factory(self):
        with patch.object(live,'live_factory',side_effect=AssertionError('MUST_NOT_RUN')),redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--live-collect']),2)
            with tempfile.TemporaryDirectory() as tmp:self.assertEqual(main(self.args(tmp,True)+['--dry-run']),2)

    def test_live_dispatch_with_injected_mock_factory_not_real_sdk(self):
        from pypdf import PdfReader
        with tempfile.TemporaryDirectory() as tmp,patch.object(live,'live_factory',return_value=live.mock_factory(self.script)),patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK')),redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args(tmp,True)),0)
            d=next(Path(tmp).iterdir());report=json.loads((d/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['collection']['mode'],'LIVE_READ_ONLY')
            self.assertNotIn('no_AWS_API_or_SDK_client_created',report['limitations'])
            text='\n'.join(p.extract_text() for p in PdfReader(d/'report.pdf').pages)
            self.assertIn('Explicit read-only AWS acquisition',text)
            self.assertNotIn('No AWS API, STS or SDK client was used',text)

    def test_fatal_sts_preserves_only_failure_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            script=deepcopy(self.script);script['requests'][0]['response']['Account']='999999999999';script['requests'][0]['response']['Arn']='arn:aws:iam::999999999999:root'
            with patch.object(live,'live_factory',return_value=live.mock_factory(script)),redirect_stdout(io.StringIO()):self.assertEqual(main(self.args(tmp,True)),2)
            d=next(Path(tmp).iterdir());self.assertTrue((d/'collection.json').is_file());self.assertTrue((d/'failure.json').is_file())
            self.assertFalse((d/'snapshot.json').exists());self.assertNotIn('999999999999',(d/'collection.json').read_text())

    def test_saved_mock_snapshot_works_with_original_offline_loader(self):
        with tempfile.TemporaryDirectory() as tmp,redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args(tmp)),0);d=next(Path(tmp).iterdir())
            report=load_report(d/'snapshot.json',FIX/'scope.json');self.assertEqual(report['summary'],{'PASS':8})

    def test_sdk_config_factory_uses_standard_chain_tls_and_no_hidden_retries(self):
        import sys
        calls=[];configs=[]
        class Config:
            def __init__(self,**kwargs):configs.append(kwargs)
        class Session:
            def __init__(self,**kwargs):calls.append(('session',kwargs));self._session=SimpleNamespace(set_config_variable=lambda *a:None)
            def client(self,service,**kwargs):calls.append((service,kwargs));return SimpleNamespace(meta=SimpleNamespace(endpoint_url='https://sts.ap-northeast-2.amazonaws.com'))
        fake=SimpleNamespace(session=SimpleNamespace(Session=Session))
        with patch.dict(sys.modules,{'boto3':fake,'botocore.config':SimpleNamespace(Config=Config)}):
            factory=live.live_factory(self.scope,live.Limits());self.assertEqual(len(calls),1);factory('sts','ap-northeast-2')
        self.assertEqual(configs[0]['retries'],{'total_max_attempts':1});self.assertTrue(configs[0]['ignore_configured_endpoint_urls'])
        self.assertTrue(calls[-1][1]['verify']);self.assertNotIn('aws_access_key_id',calls[0][1])


if __name__=='__main__':unittest.main()
