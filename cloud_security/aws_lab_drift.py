"""Narrow Terraform parent readback synchronization checks; no AWS/TF execution.

No security-bearing fields are discarded. Only JSON key order, list order and
provider-defined absent zero/default fields in the *expected* child projection
are normalized. Unknown fields and duplicate entries are rejected.
"""
import json
from .aws_scope import require, unique

FIELDS={
 'aws_iam_role.flow':{'inline_policy'},
 'aws_network_acl.lab':{'ingress','egress','subnet_ids'},
 'aws_route_table.lab':{'route'},
 'aws_security_group.lab':{'ingress'},
}

def canonical(value):
    if isinstance(value,dict):return {k:canonical(value[k]) for k in sorted(value)}
    if isinstance(value,list):return sorted((canonical(v) for v in value),key=lambda v:json.dumps(v,sort_keys=True))
    return value

def equal(a,b):return json.dumps(canonical(a),sort_keys=True,separators=(',',':'))==json.dumps(canonical(b),sort_keys=True,separators=(',',':'))

def policy(value):
    require(isinstance(value,str),'lab_sync_policy_invalid')
    try:return json.loads(value,object_pairs_hook=unique,parse_constant=lambda _:require(False,'lab_sync_policy_invalid'))
    except (ValueError,TypeError):require(False,'lab_sync_policy_invalid')

def distinct(rows):
    require(isinstance(rows,list),'lab_sync_collection_required')
    keys=[json.dumps(canonical(row),sort_keys=True) for row in rows]
    require(len(keys)==len(set(keys)),'lab_sync_duplicate_entry')
    return rows

def expected_collections(address,resources):
    parent=resources[address]['values'];pid=parent['id']
    if address=='aws_iam_role.flow':
        rows=[]
        for row in resources.values():
            if row['type']=='aws_iam_role_policy':
                v=row['values'];require(v['role']==parent['name'],'lab_sync_child_parent_mismatch')
                rows.append({'name':v['name'],'policy':policy(v['policy'])})
        return {'inline_policy':distinct(rows)}
    if address=='aws_security_group.lab':
        rows=[]
        for row in resources.values():
            if row['type']=='aws_vpc_security_group_ingress_rule':
                v=row['values'];require(v['security_group_id']==pid,'lab_sync_child_parent_mismatch')
                require(all(v.get(k) in (None,'') for k in ('cidr_ipv6','prefix_list_id','referenced_security_group_id')),'lab_sync_unsupported_sg_source')
                rows.append({'cidr_blocks':[v['cidr_ipv4']],'description':v.get('description') or '',
                    'from_port':v['from_port'],'to_port':v['to_port'],'protocol':v['ip_protocol'],
                    'ipv6_cidr_blocks':[],'prefix_list_ids':[],'security_groups':[],'self':False})
        return {'ingress':distinct(rows)}
    if address=='aws_network_acl.lab':
        result={'ingress':[],'egress':[],'subnet_ids':[]}
        for row in resources.values():
            v=row['values']
            if row['type']=='aws_network_acl_rule':
                require(v['network_acl_id']==pid and type(v['egress']) is bool,'lab_sync_child_parent_mismatch')
                result['egress' if v['egress'] else 'ingress'].append({'action':v['rule_action'],'cidr_block':v.get('cidr_block') or '',
                    'ipv6_cidr_block':v.get('ipv6_cidr_block') or '', 'from_port':v.get('from_port') if v.get('from_port') is not None else 0,
                    'to_port':v.get('to_port') if v.get('to_port') is not None else 0,'icmp_code':v.get('icmp_code') if v.get('icmp_code') is not None else 0,
                    'icmp_type':v.get('icmp_type') if v.get('icmp_type') is not None else 0,'protocol':v['protocol'],'rule_no':v['rule_number']})
            if row['type']=='aws_network_acl_association':
                require(v['network_acl_id']==pid,'lab_sync_child_parent_mismatch');result['subnet_ids'].append(v['subnet_id'])
        for rows in result.values():distinct(rows)
        return result
    if address=='aws_route_table.lab':
        fields={'carrier_gateway_id':'carrier_gateway_id','cidr_block':'destination_cidr_block','core_network_arn':'core_network_arn',
            'destination_prefix_list_id':'destination_prefix_list_id','egress_only_gateway_id':'egress_only_gateway_id','gateway_id':'gateway_id',
            'ipv6_cidr_block':'destination_ipv6_cidr_block','local_gateway_id':'local_gateway_id','nat_gateway_id':'nat_gateway_id',
            'network_interface_id':'network_interface_id','odb_network_arn':'odb_network_arn','transit_gateway_id':'transit_gateway_id',
            'vpc_endpoint_id':'vpc_endpoint_id','vpc_peering_connection_id':'vpc_peering_connection_id'}
        rows=[]
        for row in resources.values():
            if row['type']=='aws_route':
                v=row['values'];require(v['route_table_id']==pid,'lab_sync_child_parent_mismatch')
                rows.append({key:v.get(field) or '' for key,field in fields.items()})
        return {'route':distinct(rows)}
    require(False,'lab_sync_parent_not_allowed')

def observed(value,field):
    rows=distinct(value)
    if field=='inline_policy':
        parsed=[];names=set()
        for row in rows:
            require(isinstance(row,dict) and set(row)=={'name','policy'} and row['name'] not in names,'lab_sync_policy_entry_invalid')
            names.add(row['name']);parsed.append({'name':row['name'],'policy':policy(row['policy'])})
        return parsed
    return rows

def verify(plan, baseline, state, planned, changes):
    """Requires complete checked state maps and an explicit immutable baseline."""
    drifts=plan.get('resource_drift',[])
    if not drifts:return []
    require(baseline is not None,'lab_drift_baseline_required')
    # Imported lazily: aws_lab calls this only after its module is initialized.
    from .aws_lab import STABLE,BEFORE_ONLY,AFTER_ONLY
    flag=baseline.get('aws_subnet.internal',{}).get('values',{}).get('map_public_ip_on_launch')
    require(type(flag) is bool,'lab_sync_baseline_phase_invalid')
    phase='before' if flag else 'after'
    inventory=STABLE | (BEFORE_ONLY if phase=='before' else AFTER_ONLY)
    require(set(baseline)==set(state)==inventory,'lab_sync_child_inventory_incomplete')
    require(isinstance(drifts,list) and len(drifts)<=len(FIELDS),'lab_sync_drift_inventory_invalid')
    by_address={}
    for drift in drifts:
        require(isinstance(drift,dict),'lab_sync_drift_invalid')
        address=drift.get('address')
        require(address in FIELDS and address not in by_address,'lab_sync_parent_not_allowed')
        require(drift.get('mode')=='managed' and drift.get('provider_name')==state[address]['provider_name']
            and drift.get('type')==state[address]['type'] and not drift.get('previous_address') and not drift.get('deposed'),'lab_sync_drift_identity_invalid')
        change=drift.get('change',{});before=change.get('before');after=change.get('after')
        require(change.get('actions')==['update'] and not change.get('importing')
            and isinstance(before,dict) and isinstance(after,dict) and not change.get('after_unknown'),'lab_sync_drift_action_invalid')
        require(before.get('id')==after.get('id')==baseline[address]['values'].get('id')==state[address]['values'].get('id'),'lab_sync_parent_id_mismatch')
        require(equal(before,baseline[address]['values']) and equal(after,state[address]['values']),'lab_sync_reference_state_mismatch')
        changed={key for key in set(before)|set(after) if not equal(before.get(key),after.get(key))}
        require(changed and changed<=FIELDS[address],'lab_sync_unapproved_parent_field')
        target=changes.get(address,{})
        require(target.get('change',{}).get('actions')==['no-op'] and address in planned
            and equal(target['change'].get('before'),after) and equal(target['change'].get('after'),after)
            and equal(planned[address]['values'],after),'lab_sync_parent_not_noop')
        by_address[address]=changed
    # Every child must still equal the baseline. Parent diffs need a matching
    # drift entry; unknown or hidden child changes cannot be smuggled through.
    for address,row in baseline.items():
        before=row['values'];after=state[address]['values']
        if address in by_address:
            fields=by_address[address]
            require(equal({k:v for k,v in before.items() if k not in fields},{k:v for k,v in after.items() if k not in fields}),'lab_sync_unapproved_parent_field')
        else:require(equal(before,after),'lab_sync_child_or_hidden_change')
    results=[]
    for address,changed in by_address.items():
        expected=expected_collections(address,state)
        # Check ALL approved readback collections, including unchanged ones:
        # otherwise an extra unchanged rule could escape the complete inventory.
        actual=state[address]['values']
        for field,want in expected.items():
            require(field in actual and equal(observed(actual[field],field),want),'lab_sync_child_collection_mismatch')
        results.append({'address':address,'fields':sorted(changed),'basis':'exact_complete_standalone_child_readback','parent_planned_action':'no-op'})
    return sorted(results,key=lambda x:x['address'])
