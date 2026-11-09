"""Synthetic Terraform JSON + mocked AWS. No Terraform plan or AWS calls."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cloud_security import aws_lab as lab
from cloud_security.aws_scope import AwsScope,AwsOfflineError
from cloud_security import aws_live as live
from config_audit.collectors.aws_security import build_report,compare_reports
from scripts.prepare_aws_audit_lab import main
from scripts.run_aws_audit import main as audit_main
from tests.test_aws_scope_v2 import inputs,read

ACCOUNT='123456789012';NAME='scanner-p2audit-abc123';OWNER='tester'

def values(phase):
    tags=lab.identity(ACCOUNT,NAME,OWNER)
    addresses=lab.STABLE | (lab.BEFORE_ONLY if phase=='before' else lab.AFTER_ONLY)
    result={}
    ids={'aws_vpc.lab':'vpc-a01','aws_subnet.internal':'subnet-a01','aws_security_group.lab':'sg-a01',
         'aws_network_acl.lab':'acl-a01','aws_route_table.lab':'rtb-a01','aws_internet_gateway.lab':'igw-a01'}
    for i,address in enumerate(sorted(addresses)):
        kind=lab.base_address(address).split('.')[0]
        v={'id':ids.get(address,'synthetic-'+hashlib.sha256(address.encode()).hexdigest()[:12]),'tags_all':{**tags,'Name':NAME+'-'+kind}}
        if kind in ('aws_security_group','aws_iam_role'):v['name']=NAME+'-resource'
        if kind=='aws_cloudwatch_log_group':v.update(name='/'+NAME+'/vpc-flow',retention_in_days=1,arn=f'arn:aws:logs:ap-northeast-2:{ACCOUNT}:log-group:/{NAME}/vpc-flow')
        if kind=='aws_iam_role':v['arn']=f'arn:aws:iam::{ACCOUNT}:role/{NAME}-resource'
        if kind=='aws_iam_role':
            v['assume_role_policy']=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'vpc-flow-logs.amazonaws.com'},'Action':'sts:AssumeRole','Condition':{'StringEquals':{'aws:SourceAccount':ACCOUNT},'ArnLike':{'aws:SourceArn':f'arn:aws:ec2:ap-northeast-2:{ACCOUNT}:vpc-flow-log/*'}}}]})
        if kind=='aws_iam_role_policy':
            v['policy']=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents','logs:DescribeLogStreams'],'Resource':f'arn:aws:logs:ap-northeast-2:{ACCOUNT}:log-group:/{NAME}/vpc-flow:*'},{'Effect':'Allow','Action':['logs:DescribeLogGroups'],'Resource':'*'}]})
        if kind=='aws_subnet':v['map_public_ip_on_launch']=phase=='before'
        if kind=='aws_route':v['destination_cidr_block']='0.0.0.0/0'
        if kind=='aws_flow_log':v.update(traffic_type='ALL',log_destination_type='cloud-watch-logs')
        if kind=='aws_vpc_security_group_ingress_rule':
            port=int(address.split('"')[1]);v.update(ip_protocol='tcp',cidr_ipv4='0.0.0.0/0',from_port=port,to_port=port)
        if kind=='aws_network_acl_rule':
            if '.deny[' in address:
                port=int(address.split('"')[1]);v.update(rule_number={22:50,23:51,3389:52}[port],egress=False,protocol='6',rule_action='deny',cidr_block='198.51.100.10/32',from_port=port,to_port=port)
            else:v.update(rule_number=100,egress=address.endswith('allow_out'),protocol='-1',rule_action='allow',cidr_block='0.0.0.0/0')
        result[address]={'address':address,'mode':'managed','type':kind,'provider_name':lab.PROVIDER,'values':v}
    for row in result.values():
        for field,parent in lab.PARENTS.get(row['type'],{}).items():
            key='arn' if field in ('iam_role_arn','log_destination') else 'name' if row['type']=='aws_iam_role_policy' else 'id'
            row['values'][field]=result[parent]['values'][key]
    return result

def state(phase):return {'format_version':'1.0','values':{'root_module':{'resources':list(values(phase).values())}}}

def plan(phase='before',initial=True):
    prior={} if initial else values('before' if phase=='after' else 'after' if phase=='before' else 'after')
    planned={} if phase=='destroy' else values(phase)
    changes=[]
    for address in sorted(set(prior)|set(planned)):
        before=prior.get(address,{}).get('values');after=planned.get(address,{}).get('values')
        actions=['create'] if before is None else ['delete'] if after is None else ['no-op'] if before==after else ['update']
        row=planned.get(address,prior.get(address));changes.append({k:row[k] for k in ('address','mode','type','provider_name')})
        changes[-1]['change']={'actions':actions,'before':before,'after':after,'after_unknown':{}}
    config=[]
    for address in sorted({lab.base_address(a) for a in lab.ADDRESSES}):
        kind=address.split('.')[0];expressions={}
        for field,parent in lab.PARENTS.get(kind,{}).items():expressions[field]={'references':[parent+'.id',parent]}
        config.append({'address':address,'mode':'managed','expressions':expressions})
    variables={'expected_account_id':ACCOUNT,'region':'ap-northeast-2','lab_name':NAME,'owner':OWNER,'phase':'after' if phase=='destroy' else phase,'vpc_cidr':'10.206.0.0/16'}
    return {'format_version':'1.2','variables':{k:{'value':v} for k,v in variables.items()},
        'configuration':{'provider_config':{'aws':{'full_name':lab.PROVIDER,'expressions':{'region':{'references':['var.region']},'allowed_account_ids':{'references':['var.expected_account_id']}}}},'root_module':{'resources':config}},
        'prior_state':{'values':{'root_module':{'resources':list(prior.values())}}},
        'planned_values':{'root_module':{'resources':list(planned.values())}},'resource_changes':changes}

def outputs(phase):
    rows=values(phase);v={'schema_version':1,'account_id':ACCOUNT,'region':'ap-northeast-2','lab_name':NAME,'owner':OWNER,'phase':phase,'tags':lab.identity(ACCOUNT,NAME,OWNER)}
    for key,address,field in [('vpc_id','aws_vpc.lab','id'),('subnet_id','aws_subnet.internal','id'),('sg_id','aws_security_group.lab','id'),('nacl_id','aws_network_acl.lab','id'),('route_table_id','aws_route_table.lab','id'),('igw_id','aws_internet_gateway.lab','id'),('log_group_arn','aws_cloudwatch_log_group.flow','arn'),('flow_role_arn','aws_iam_role.flow','arn')]:v[key]=rows[address]['values'][field]
    return {'audit_lab':{'sensitive':False,'value':v}}

class AwsAuditLabTests(unittest.TestCase):
    def setUp(self):
        self.base,_,_=inputs();self.scope=AwsScope.from_dict(self.base)
        self.guard=patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK'));self.guard.start();self.addCleanup(self.guard.stop)
    def check(self,p=None,phase='before',initial=True):return lab.check_plan(p or plan(phase,initial),account=ACCOUNT,name=NAME,owner=OWNER,phase=phase,protected_scope=self.scope,initial=initial)
    def deny(self,p,**kw):
        with self.assertRaises(AwsOfflineError):self.check(p,**kw)
    def test_initial_creates_only_lab(self):self.assertEqual(self.check()['resource_count'],17)
    def test_after_keeps_base_ids(self):self.assertEqual(self.check(phase='after',initial=False)['status'],'VALID')
    def test_owned_reverse_phase_for_explicit_lab_replay(self):self.assertEqual(self.check(phase='before',initial=False)['status'],'VALID')
    def test_destroy_only_owned(self):self.assertEqual(self.check(phase='destroy',initial=False)['resource_count'],0)
    def test_initial_existing_state_rejected(self):self.deny(plan('after',False),phase='after')
    def test_foreign_resource_address_rejected(self):
        p=plan();p['resource_changes'][0]['address']='aws_instance.production';self.deny(p)
    def test_import_rejected(self):
        p=plan();p['resource_changes'][0]['change']['importing']={'id':'vpc-001'};self.deny(p)
    def test_move_rejected(self):
        p=plan();p['resource_changes'][0]['previous_address']='aws_default_vpc.existing';self.deny(p)
    def test_replacement_rejected(self):
        p=plan();p['resource_changes'][0]['change']['actions']=['delete','create'];self.deny(p)
    def test_initial_update_rejected(self):
        p=plan();p['resource_changes'][0]['change']['actions']=['update'];self.deny(p)
    def test_wrong_account_rejected(self):
        p=plan();p['variables']['expected_account_id']['value']='999999999999';self.deny(p)
    def test_wrong_region_rejected(self):
        p=plan();p['variables']['region']['value']='us-east-1';self.deny(p)
    def test_wrong_owner_tags_rejected(self):
        p=plan();next(x for x in p['resource_changes'] if x['type']=='aws_vpc')['change']['after']['tags_all']['Owner']='other';self.deny(p)
    def test_protected_existing_vpc_rejected(self):
        p=plan();next(x for x in p['resource_changes'] if x['type']=='aws_subnet')['change']['after']['vpc_id']='vpc-001';self.deny(p)
    def test_other_parent_even_not_protected_rejected(self):
        p=plan();next(x for x in p['resource_changes'] if x['type']=='aws_subnet')['change']['after']['vpc_id']='vpc-bad';self.deny(p)
    def test_default_vpc_configuration_rejected(self):
        p=plan();p['configuration']['root_module']['resources'].append({'address':'aws_default_vpc.existing','mode':'managed'});self.deny(p)
    def test_data_source_forbidden(self):
        p=plan();p['configuration']['root_module']['resources'].append({'address':'data.aws_vpc.default','mode':'data'});self.deny(p)
    def test_modules_forbidden(self):
        p=plan();p['configuration']['root_module']['module_calls']={'other':{}};self.deny(p)
    def test_endpoint_override_forbidden(self):
        p=plan();p['configuration']['provider_config']['aws']['expressions']['endpoints']={'constant_value':[]};self.deny(p)
    def test_provider_account_guard_required(self):
        p=plan();p['configuration']['provider_config']['aws']['expressions'].pop('allowed_account_ids');self.deny(p)
    def test_stable_role_update_rejected(self):
        p=plan('after',False);x=next(x for x in p['resource_changes'] if x['type']=='aws_iam_role');x['change']['actions']=['update'];self.deny(p,phase='after',initial=False)
    def test_drift_rejected(self):
        p=plan();p['resource_drift']=[{}];self.deny(p)
    def test_missing_change_rejected(self):
        p=plan();p['resource_changes'].pop();self.deny(p)
    def test_retention_change_rejected(self):
        p=plan();next(x for x in p['resource_changes'] if x['type']=='aws_cloudwatch_log_group')['change']['after']['retention_in_days']=0;self.deny(p)
    def test_unknown_parent_requires_exact_reference(self):
        p=plan();x=next(x for x in p['resource_changes'] if x['type']=='aws_subnet');x['change']['after']['vpc_id']=None;x['change']['after_unknown']['vpc_id']=True
        next(r for r in p['planned_values']['root_module']['resources'] if r['type']=='aws_subnet')['values']['vpc_id']=None
        self.assertEqual(self.check(p)['status'],'VALID')
        c=next(c for c in p['configuration']['root_module']['resources'] if c['address']=='aws_subnet.internal');c['expressions']['vpc_id']['references']=['var.existing_vpc_id'];self.deny(p)
    def test_changed_prior_identity_rejected(self):
        p=plan('after',False);p['resource_changes'][0]['change']['before']['id']='foreign-id';self.deny(p,phase='after',initial=False)
    def test_changed_existing_after_id_rejected(self):
        p=plan('after',False);x=next(x for x in p['resource_changes'] if x['address']=='aws_subnet.internal');x['change']['after']['id']='subnet-fff';self.deny(p,phase='after',initial=False)
    def test_wide_iam_policy_rejected(self):
        p=plan();x=next(x for x in p['resource_changes'] if x['type']=='aws_iam_role_policy')
        x['change']['after']['policy']=json.dumps({'Statement':[{'Effect':'Allow','Action':['*'],'Resource':'*'}]});self.deny(p)
    def test_foreign_flow_trust_rejected(self):
        p=plan();x=next(x for x in p['resource_changes'] if x['type']=='aws_iam_role')
        trust=json.loads(x['change']['after']['assume_role_policy']);trust['Statement'][0]['Condition']['StringEquals']['aws:SourceAccount']='999999999999'
        x['change']['after']['assume_role_policy']=json.dumps(trust);self.deny(p)
    def test_unresolved_policy_requires_owned_log_reference(self):
        p=plan();x=next(x for x in p['resource_changes'] if x['type']=='aws_iam_role_policy');x['change']['after']['policy']=None;x['change']['after_unknown']['policy']=True
        next(r for r in p['planned_values']['root_module']['resources'] if r['type']=='aws_iam_role_policy')['values']['policy']=None
        c=next(x for x in p['configuration']['root_module']['resources'] if x['address']=='aws_iam_role_policy.flow')
        c['expressions']['policy']={'references':['aws_cloudwatch_log_group.flow.arn']};self.assertEqual(self.check(p)['status'],'VALID')
        c['expressions']['policy']['references']=['data.aws_iam_policy_document.admin.json'];self.deny(p)
    def test_subnet_phase_wrong_rejected(self):
        p=plan();next(x for x in p['resource_changes'] if x['type']=='aws_subnet')['change']['after']['map_public_ip_on_launch']=False;self.deny(p)
    def test_after_nacl_wrong_priority_rejected(self):
        p=plan('after',False);next(x for x in p['resource_changes'] if '.deny[' in x['address'])['change']['after']['rule_number']=150;self.deny(p,phase='after',initial=False)
    def test_cidr_outside_private_lab_rejected(self):
        p=plan();p['variables']['vpc_cidr']['value']='172.31.0.0/16';self.deny(p)
    def test_before_after_export_scope_identical(self):
        a,_=lab.export_scope(outputs('before'),state('before'),self.base,account=ACCOUNT,name=NAME,owner=OWNER)
        b,_=lab.export_scope(outputs('after'),state('after'),self.base,account=ACCOUNT,name=NAME,owner=OWNER)
        self.assertEqual(a,b);self.assertEqual(a['policy']['internal_subnet_ids'],['subnet-a01'])
    def test_export_forged_id_rejected(self):
        o=outputs('before');o['audit_lab']['value']['vpc_id']='vpc-bad'
        with self.assertRaises(AwsOfflineError):lab.export_scope(o,state('before'),self.base,account=ACCOUNT,name=NAME,owner=OWNER)
    def test_export_foreign_state_rejected(self):
        st=state('before');st['values']['root_module']['resources'][0]['values']['tags_all']['Project']='other'
        with self.assertRaises(AwsOfflineError):lab.export_scope(outputs('before'),st,self.base,account=ACCOUNT,name=NAME,owner=OWNER)
    def test_no_overwrite_export_and_hash_links(self):
        a,b=lab.export_scope(outputs('before'),state('before'),self.base,account=ACCOUNT,name=NAME,owner=OWNER)
        with tempfile.TemporaryDirectory() as tmp:
            x=Path(lab.save_export(tmp,a,b,{}));y=Path(lab.save_export(tmp,a,b,{}));self.assertNotEqual(x,y)
            receipt=json.loads((x/'receipt.json').read_text())
            for e in receipt['artifacts']:self.assertEqual(hashlib.sha256((x/e['file']).read_bytes()).hexdigest(),e['sha256'])
    def test_cli_no_network_no_tf_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for key,value in [('scope',self.base),('plan',plan())]:(root/(key+'.json')).write_text(json.dumps(value))
            with patch('subprocess.run',side_effect=AssertionError('NO_SUBPROCESS')),redirect_stdout(io.StringIO()) as out:
                rc=main(['check-plan','--plan-json',str(root/'plan.json'),'--phase','before','--initial','--expected-account-id',ACCOUNT,'--lab-name',NAME,'--owner',OWNER,'--protected-scope-json',str(root/'scope.json')])
            self.assertEqual(rc,0);self.assertFalse(json.loads(out.getvalue())['network_access'])

    def test_cli_export_cannot_write_private_scope_to_public_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scope.json').write_text(json.dumps(self.base))
            with redirect_stdout(io.StringIO()) as out:
                rc=main(['export-scope','--expected-account-id',ACCOUNT,'--lab-name',NAME,'--owner',OWNER,
                    '--protected-scope-json',str(root/'scope.json'),'--outputs-json',str(root/'missing.outputs.json'),
                    '--state-json',str(root/'missing.state.json'),'--output-root',str(root)])
            self.assertEqual(rc,2);self.assertEqual(json.loads(out.getvalue())['error_code'],'lab_export_reports_directory_required')
    def collect_lab(self,phase):
        raw,targets,script=inputs();raw['policy']['internal_subnet_ids']=['subnet-001']
        raw['nacl_matrix']=[{'source_ip':'198.51.100.10','destination_port':p,'return_port':55000,'expected':'BLOCK'} for p in (22,23,3389)]
        for entry in script['requests']:
            op=entry['operation'];response=entry['response']
            if op=='describe_network_interfaces':response['NetworkInterfaces']=[]
            if op=='describe_subnets':response['Subnets'][0]['MapPublicIpOnLaunch']=phase=='before'
            if op=='describe_route_tables' and phase=='before':response['RouteTables'][0]['Routes'].append({'State':'active','DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-001'})
            if op=='describe_security_groups':
                response['SecurityGroups'][0]['IpPermissions']=[] if phase=='after' else [{'IpProtocol':'tcp','FromPort':p,'ToPort':p,'IpRanges':[{'CidrIp':'0.0.0.0/0'}],'Ipv6Ranges':[],'UserIdGroupPairs':[],'PrefixListIds':[]} for p in (21,23,3389)]
            if op=='describe_network_acls':
                acl=response['NetworkAcls'][0];acl['Entries']=[{'RuleNumber':n,'Egress':direction,'Protocol':'-1','RuleAction':action,'CidrBlock':'0.0.0.0/0'} for direction in (False,True) for n,action in [(100,'allow'),(32767,'deny')]]
                if phase=='after':acl['Entries'] += [{'RuleNumber':50+i,'Egress':False,'Protocol':'6','RuleAction':'deny','CidrBlock':'198.51.100.10/32','PortRange':{'From':p,'To':p}} for i,p in enumerate((22,23,3389))]
            if op=='describe_flow_logs' and phase=='after':response['FlowLogs']=deepcopy(next(e['response']['FlowLogs'] for e in read('mock_responses.json')['requests'] if e['operation']==op))
        scope=AwsScope.from_dict(raw)
        doc,audit=live.collect(scope,targets,expected_account=ACCOUNT,allowed_regions=['ap-northeast-2'],factory=live.mock_factory(script))
        report=build_report(doc,scope,source_reference='synthetic-'+phase+'.json',source_sha256=('a' if phase=='before' else 'b')*64,scope_sha256='c'*64)
        return doc,audit,report
    def test_four_actual_setting_shapes_before_fail(self):
        _,_,report=self.collect_lab('before');rows={r['check_id']:r for r in report['results']}
        for check in ['SG-01','NACL-01','VPC-01','FL-01']:self.assertEqual(rows[check]['status'],'FAIL')
    def test_four_setting_shapes_after_pass(self):
        _,_,report=self.collect_lab('after');rows={r['check_id']:r for r in report['results']}
        for check in ['SG-01','NACL-01','VPC-01','FL-01']:self.assertEqual(rows[check]['status'],'PASS')
    def test_empty_eni_is_complete(self):
        doc,audit,_=self.collect_lab('after');self.assertTrue(doc['sections']['VPC-01']['pagination']['complete']);self.assertTrue(audit['checks']['VPC-01']['complete'])
    def test_comparison_four_observed_and_evidence_preserved(self):
        before=self.collect_lab('before')[2];after=self.collect_lab('after')[2]
        result=compare_reports(before,after)
        self.assertEqual(result['summary'].get('IMPROVED_OBSERVED'),4)
        self.assertTrue(all(r['evidence_reference'].startswith('sha256:') for r in after['results']))
    def test_saved_comparison_json_pdf_and_real_local_hashes(self):
        raw,_,_=inputs();raw['policy']['internal_subnet_ids']=['subnet-001']
        raw['nacl_matrix']=[{'source_ip':'198.51.100.10','destination_port':p,'return_port':55000,'expected':'BLOCK'} for p in (22,23,3389)]
        scope=AwsScope.from_dict(raw)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scope_raw=json.dumps(raw).encode();(root/'scope.json').write_bytes(scope_raw)
            before=self.collect_lab('before')[0];after=self.collect_lab('after')[0]
            before_raw=json.dumps(before).encode();after_raw=json.dumps(after).encode()
            (root/'before.snapshot.json').write_bytes(before_raw);(root/'after.snapshot.json').write_bytes(after_raw)
            baseline=build_report(before,scope,source_reference=str(root/'before.snapshot.json'),source_sha256=hashlib.sha256(before_raw).hexdigest(),scope_sha256=hashlib.sha256(scope_raw).hexdigest())
            (root/'before.report.json').write_text(json.dumps(baseline))
            with patch.object(live,'live_factory',side_effect=AssertionError('NO_LIVE')),redirect_stdout(io.StringIO()):
                rc=audit_main(['--input-json',str(root/'after.snapshot.json'),'--scope-json',str(root/'scope.json'),
                    '--baseline-json',str(root/'before.report.json'),'--output',str(root/'comparison.json'),'--pdf',str(root/'comparison.pdf')])
            self.assertEqual(rc,0);result=json.loads((root/'comparison.json').read_text())
            self.assertEqual(result['comparison']['summary'].get('IMPROVED_OBSERVED'),4)
            self.assertEqual(result['evidence']['file_sha256'],hashlib.sha256(after_raw).hexdigest())
            self.assertFalse(result['evidence']['independently_verified']);self.assertEqual(result['evidence']['hash_comparison'],'NOT_VERIFIED')
            from pypdf import PdfReader
            text=' '.join(p.extract_text() for p in PdfReader(root/'comparison.pdf').pages)
            for check in ('SG-01','NACL-01','VPC-01','FL-01'):self.assertIn(check,text)
    def test_export_unc_rejected(self):
        with self.assertRaises(AwsOfflineError):lab.save_export(r'\\server\share',{}, {}, {})
    def test_context_channels_not_forced_to_pass(self):
        _,_,report=self.collect_lab('after');rows={r['check_id']:r for r in report['results']}
        self.assertEqual(rows['IAM-03']['status'],'NEEDS_REVIEW');self.assertEqual(rows['CT-01']['status'],'FAIL')
    def test_partial_cause_records_safe_warning(self):
        raw,targets,script=inputs();raw['resources']['ec2'].remove('eni-001');scope=AwsScope.from_dict(raw)
        doc,audit=live.collect(scope,targets,expected_account=ACCOUNT,allowed_regions=['ap-northeast-2'],factory=live.mock_factory(script))
        self.assertIn('ENI_filtered_outside_explicit_resource_scope',audit['warnings']);self.assertFalse(doc['sections']['VPC-01']['pagination']['complete'])
    def test_terraform_source_has_no_data_modules_or_compute(self):
        root=Path(__file__).parents[1]/'infra/aws/security-audit-lab';text='\n'.join(p.read_text() for p in root.glob('*.tf'))
        for forbidden in ['resource "aws_instance"','resource "aws_nat_gateway"','resource "aws_eip"','resource "aws_default_','data "','module "','import {','local-exec','remote-exec']:
            self.assertNotIn(forbidden,text)
        self.assertIn('phase2-audit-lab.tfstate',text);self.assertIn('allowed_account_ids',text)

if __name__=='__main__':unittest.main()
