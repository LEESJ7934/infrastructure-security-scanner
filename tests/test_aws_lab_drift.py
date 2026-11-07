"""Strict parent/child drift tests, synthetic IDs only; never calls AWS."""
from copy import deepcopy
import json
import socket
import unittest
from unittest.mock import patch
from cloud_security.aws_scope import AwsOfflineError,AwsScope
from cloud_security.aws_lab import check_plan
from tests.test_aws_audit_lab import plan,ACCOUNT,NAME,OWNER
from tests.test_aws_scope_v2 import inputs

PARENTS=['aws_iam_role.flow','aws_network_acl.lab','aws_route_table.lab','aws_security_group.lab']

def synced():
    p=plan('after',False);baseline=deepcopy(p['prior_state'])
    old={r['address']:r for r in baseline['values']['root_module']['resources']}
    old['aws_iam_role_policy.flow']['values']['name']=NAME+'-flow-write'
    defaults={'aws_iam_role.flow':{'inline_policy':[]},'aws_network_acl.lab':{'ingress':[],'egress':[],'subnet_ids':[]},'aws_route_table.lab':{'route':[]},'aws_security_group.lab':{'ingress':[]}}
    for address,fields in defaults.items():old[address]['values'].update(fields)
    current=deepcopy(old)
    current['aws_iam_role.flow']['values']['inline_policy']=[{'name':NAME+'-flow-write','policy':old['aws_iam_role_policy.flow']['values']['policy']}]
    current['aws_network_acl.lab']['values'].update(ingress=[{'action':'allow','cidr_block':'0.0.0.0/0','ipv6_cidr_block':'','from_port':0,'to_port':0,'icmp_code':0,'icmp_type':0,'protocol':'-1','rule_no':100}],egress=[{'action':'allow','cidr_block':'0.0.0.0/0','ipv6_cidr_block':'','from_port':0,'to_port':0,'icmp_code':0,'icmp_type':0,'protocol':'-1','rule_no':100}],subnet_ids=['subnet-a01'])
    route={'carrier_gateway_id':'','cidr_block':'0.0.0.0/0','core_network_arn':'','destination_prefix_list_id':'','egress_only_gateway_id':'','gateway_id':'igw-a01','ipv6_cidr_block':'','local_gateway_id':'','nat_gateway_id':'','network_interface_id':'','odb_network_arn':'','transit_gateway_id':'','vpc_endpoint_id':'','vpc_peering_connection_id':''}
    current['aws_route_table.lab']['values']['route']=[route]
    current['aws_security_group.lab']['values']['ingress']=[{'cidr_blocks':['0.0.0.0/0'],'description':'','from_port':port,'to_port':port,'protocol':'tcp','ipv6_cidr_blocks':[],'prefix_list_ids':[],'security_groups':[],'self':False} for port in (21,23,3389)]
    p['prior_state']=deepcopy(baseline);p['prior_state']['values']['root_module']['resources']=list(deepcopy(current).values())
    planned={r['address']:r for r in p['planned_values']['root_module']['resources']}
    for address in PARENTS+['aws_iam_role_policy.flow']:
        planned[address]['values']=deepcopy(current[address]['values'])
        change=next(r for r in p['resource_changes'] if r['address']==address)
        change['change'].update(before=deepcopy(current[address]['values']),after=deepcopy(current[address]['values']))
    p['resource_drift']=[]
    for address in PARENTS:
        r=current[address];p['resource_drift'].append({'address':address,'type':r['type'],'mode':'managed','provider_name':r['provider_name'],
            'change':{'actions':['update'],'before':deepcopy(old[address]['values']),'after':deepcopy(r['values']),'after_unknown':{}}})
    return p,baseline

def observed(p,address,field,value):
    for row in p['prior_state']['values']['root_module']['resources']:
        if row['address']==address:row['values'][field]=deepcopy(value)
    for row in p['planned_values']['root_module']['resources']:
        if row['address']==address:row['values'][field]=deepcopy(value)
    for row in p['resource_changes']:
        if row['address']==address:
            row['change']['before'][field]=deepcopy(value);row['change']['after'][field]=deepcopy(value)
    next(r for r in p['resource_drift'] if r['address']==address)['change']['after'][field]=deepcopy(value)

def collection(p,address,field):return deepcopy(next(r for r in p['resource_drift'] if r['address']==address)['change']['after'][field])

class ParentDriftTests(unittest.TestCase):
    def setUp(self):
        self.p,self.b=synced();self.scope=AwsScope.from_dict(inputs()[0])
        guard=patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK'));guard.start();self.addCleanup(guard.stop)
    def check(self):return check_plan(self.p,account=ACCOUNT,name=NAME,owner=OWNER,phase='after',protected_scope=self.scope,baseline_state=self.b)
    def deny(self):
        with self.assertRaises(AwsOfflineError):self.check()
    def test_exact_complete_child_sync_accepted(self):self.assertEqual(len(self.check()['approved_parent_readback_sync']),4)
    def test_list_order_not_security_difference(self):
        observed(self.p,'aws_security_group.lab','ingress',list(reversed(collection(self.p,'aws_security_group.lab','ingress'))));self.assertEqual(self.check()['status'],'VALID')
    def test_policy_json_format_not_security_difference(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');rows[0]['policy']=json.dumps(json.loads(rows[0]['policy']),indent=2,sort_keys=True)
        observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.assertEqual(self.check()['status'],'VALID')
    def test_extra_public_sg_port_rejected(self):
        rows=collection(self.p,'aws_security_group.lab','ingress');extra=deepcopy(rows[0]);extra.update(from_port=22,to_port=22);rows.append(extra);observed(self.p,'aws_security_group.lab','ingress',rows);self.deny()
    def test_duplicate_sg_entry_rejected(self):
        rows=collection(self.p,'aws_security_group.lab','ingress');rows.append(deepcopy(rows[0]));observed(self.p,'aws_security_group.lab','ingress',rows);self.deny()
    def test_sg_cidr_changed_rejected(self):
        rows=collection(self.p,'aws_security_group.lab','ingress');rows[0]['cidr_blocks']=['10.0.0.0/8'];observed(self.p,'aws_security_group.lab','ingress',rows);self.deny()
    def test_sg_protocol_changed_rejected(self):
        rows=collection(self.p,'aws_security_group.lab','ingress');rows[0]['protocol']='udp';observed(self.p,'aws_security_group.lab','ingress',rows);self.deny()
    def test_nacl_rule_number_changed_rejected(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['rule_no']=99;observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_nacl_direction_changed_rejected(self):
        rows=collection(self.p,'aws_network_acl.lab','egress');observed(self.p,'aws_network_acl.lab','ingress',[]);observed(self.p,'aws_network_acl.lab','egress',rows+rows);self.deny()
    def test_nacl_cidr_changed_rejected(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['cidr_block']='198.51.100.10/32';observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_nacl_protocol_changed_rejected(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['protocol']='6';observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_nacl_action_changed_rejected(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['action']='deny';observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_boolean_not_equivalent_to_zero_port(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['from_port']=False;observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_duplicate_policy_json_key_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');rows[0]['policy']='{"Statement":[],"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.deny()
    def test_nacl_ports_not_ignored(self):
        rows=collection(self.p,'aws_network_acl.lab','ingress');rows[0]['from_port']=22;observed(self.p,'aws_network_acl.lab','ingress',rows);self.deny()
    def test_extra_subnet_rejected(self):observed(self.p,'aws_network_acl.lab','subnet_ids',['subnet-a01','subnet-fff']);self.deny()
    def test_extra_route_rejected(self):
        rows=collection(self.p,'aws_route_table.lab','route');extra=deepcopy(rows[0]);extra['cidr_block']='10.10.0.0/16';rows.append(extra);observed(self.p,'aws_route_table.lab','route',rows);self.deny()
    def test_wrong_gateway_rejected(self):
        rows=collection(self.p,'aws_route_table.lab','route');rows[0]['gateway_id']='igw-fff';observed(self.p,'aws_route_table.lab','route',rows);self.deny()
    def test_wrong_route_destination_rejected(self):
        rows=collection(self.p,'aws_route_table.lab','route');rows[0]['cidr_block']='1.0.0.0/8';observed(self.p,'aws_route_table.lab','route',rows);self.deny()
    def test_policy_privilege_expansion_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');v=json.loads(rows[0]['policy']);v['Statement'][0]['Action'].append('iam:*');rows[0]['policy']=json.dumps(v);observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.deny()
    def test_policy_condition_difference_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');v=json.loads(rows[0]['policy']);v['Statement'][0]['Condition']={'StringEquals':{'aws:RequestedRegion':'ap-northeast-2'}};rows[0]['policy']=json.dumps(v);observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.deny()
    def test_policy_effect_difference_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');v=json.loads(rows[0]['policy']);v['Statement'][0]['Effect']='Deny';rows[0]['policy']=json.dumps(v);observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.deny()
    def test_policy_resource_difference_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');v=json.loads(rows[0]['policy']);v['Statement'][0]['Resource']='*';rows[0]['policy']=json.dumps(v);observed(self.p,'aws_iam_role.flow','inline_policy',rows);self.deny()
    def test_duplicate_policy_rejected(self):
        rows=collection(self.p,'aws_iam_role.flow','inline_policy');observed(self.p,'aws_iam_role.flow','inline_policy',rows+rows);self.deny()
    def test_external_drift_resource_rejected(self):self.p['resource_drift'][0]['address']='aws_iam_role.production';self.deny()
    def test_parent_id_changed_rejected(self):self.p['resource_drift'][0]['change']['before']['id']='other-id';self.deny()
    def test_missing_child_rejected(self):
        self.p['prior_state']['values']['root_module']['resources']=[r for r in self.p['prior_state']['values']['root_module']['resources'] if r['address']!='aws_network_acl_rule.allow_out'];self.deny()
    def test_duplicate_child_rejected(self):
        rows=self.p['prior_state']['values']['root_module']['resources'];rows.append(deepcopy(rows[0]));self.deny()
    def test_missing_baseline_child_rejected(self):
        self.b['values']['root_module']['resources']=[r for r in self.b['values']['root_module']['resources'] if r['address']!='aws_vpc_security_group_ingress_rule.open["21"]'];self.deny()
    def test_child_changed_since_baseline_rejected(self):
        row=next(r for r in self.p['prior_state']['values']['root_module']['resources'] if r['address']=='aws_vpc_security_group_ingress_rule.open["21"]');row['values']['from_port']=22;self.deny()
    def test_unapproved_parent_field_rejected(self):observed(self.p,'aws_security_group.lab','description','unexpected');self.deny()
    def test_parent_planned_update_rejected(self):
        next(r for r in self.p['resource_changes'] if r['address']=='aws_security_group.lab')['change']['actions']=['update'];self.deny()
    def test_parent_replacement_rejected(self):
        next(r for r in self.p['resource_changes'] if r['address']=='aws_security_group.lab')['change']['actions']=['delete','create'];self.deny()
    def test_missing_baseline_is_rejected(self):
        with self.assertRaises(AwsOfflineError):check_plan(self.p,account=ACCOUNT,name=NAME,owner=OWNER,phase='after',protected_scope=self.scope)
    def test_duplicate_drift_parent_rejected(self):self.p['resource_drift'].append(deepcopy(self.p['resource_drift'][0]));self.deny()
    def test_unknown_readback_rejected(self):self.p['resource_drift'][0]['change']['after_unknown']={'inline_policy':True};self.deny()
    def test_state_and_before_inputs_not_mutated(self):
        before=json.dumps([self.p,self.b],sort_keys=True);self.check();self.assertEqual(before,json.dumps([self.p,self.b],sort_keys=True))
    def test_unknown_parent_entry_field_rejected(self):
        rows=collection(self.p,'aws_security_group.lab','ingress');rows[0]['unexpected']='value';observed(self.p,'aws_security_group.lab','ingress',rows);self.deny()
    def test_unchanged_collection_also_checked(self):
        rows=collection(self.p,'aws_network_acl.lab','egress');extra=deepcopy(rows[0]);extra['rule_no']=101;rows.append(extra)
        baseline=next(r for r in self.b['values']['root_module']['resources'] if r['address']=='aws_network_acl.lab');baseline['values']['egress']=deepcopy(rows)
        drift=next(r for r in self.p['resource_drift'] if r['address']=='aws_network_acl.lab');drift['change']['before']['egress']=deepcopy(rows)
        observed(self.p,'aws_network_acl.lab','egress',rows);self.deny()

if __name__=='__main__':unittest.main()
