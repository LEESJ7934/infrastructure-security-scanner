"""Offline-only guard/export for the dedicated Terraform LAB. Never runs Terraform/AWS."""
from copy import deepcopy
import hashlib
import json
import ntpath
import ipaddress
from pathlib import Path
import re
from uuid import uuid4

from .aws_scope import AwsOfflineError, AwsScope, read_json, require
from .aws_live import validate_targets

PROVIDER = 'registry.terraform.io/hashicorp/aws'
STABLE = {'aws_vpc.lab','aws_subnet.internal','aws_internet_gateway.lab','aws_route_table.lab',
 'aws_route_table_association.internal','aws_security_group.lab','aws_network_acl.lab',
 'aws_network_acl_association.internal','aws_network_acl_rule.allow_in','aws_network_acl_rule.allow_out',
 'aws_cloudwatch_log_group.flow','aws_iam_role.flow','aws_iam_role_policy.flow'}
BEFORE_ONLY = {'aws_route.public[0]'} | {f'aws_vpc_security_group_ingress_rule.open["{p}"]' for p in (21,23,3389)}
AFTER_ONLY = {'aws_flow_log.lab[0]'} | {f'aws_network_acl_rule.deny["{p}"]' for p in (22,23,3389)}
ADDRESSES = STABLE | BEFORE_ONLY | AFTER_ONLY
UNTAGGED = {'aws_route_table_association','aws_network_acl_association','aws_network_acl_rule','aws_route','aws_iam_role_policy'}
PARENTS = {
 'aws_subnet':{'vpc_id':'aws_vpc.lab'},'aws_internet_gateway':{'vpc_id':'aws_vpc.lab'},
 'aws_route_table':{'vpc_id':'aws_vpc.lab'},'aws_security_group':{'vpc_id':'aws_vpc.lab'},
 'aws_network_acl':{'vpc_id':'aws_vpc.lab'},
 'aws_route_table_association':{'subnet_id':'aws_subnet.internal','route_table_id':'aws_route_table.lab'},
 'aws_network_acl_association':{'subnet_id':'aws_subnet.internal','network_acl_id':'aws_network_acl.lab'},
 'aws_network_acl_rule':{'network_acl_id':'aws_network_acl.lab'},
 'aws_vpc_security_group_ingress_rule':{'security_group_id':'aws_security_group.lab'},
 'aws_route':{'route_table_id':'aws_route_table.lab','gateway_id':'aws_internet_gateway.lab'},
 'aws_flow_log':{'vpc_id':'aws_vpc.lab','iam_role_arn':'aws_iam_role.flow','log_destination':'aws_cloudwatch_log_group.flow'},
 'aws_iam_role_policy':{'role':'aws_iam_role.flow'}}

def identity(account, name, owner):
    require(isinstance(account,str) and re.fullmatch(r'\d{12}',account),'lab_account_invalid')
    require(isinstance(name,str) and re.fullmatch(r'scanner-p2audit-[a-z0-9]{6,12}',name),'lab_name_invalid')
    require(isinstance(owner,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,32}',owner),'lab_owner_invalid')
    return {'Project':name,'Environment':'isolated-lab','Owner':owner,'Purpose':'phase2-security-audit','ManagedBy':'terraform-phase2-audit-lab'}

def base_address(address):return address.split('[',1)[0]

def resource_map(module):
    require(isinstance(module,dict) and not module.get('child_modules'),'lab_modules_forbidden')
    rows=module.get('resources',[]);require(isinstance(rows,list),'lab_resources_invalid')
    result={}
    for row in rows:
        require(isinstance(row,dict) and row.get('mode')=='managed' and row.get('address') in ADDRESSES,'outside_lab_resource')
        require(row.get('provider_name')==PROVIDER,'lab_provider_invalid')
        require(row['address'] not in result,'lab_duplicate_resource')
        require(row.get('type')==base_address(row['address']).split('.')[0],'lab_type_mismatch')
        result[row['address']]=row
    return result

def strings(value):
    if isinstance(value,str):yield value
    elif isinstance(value,dict):
        for item in value.values():yield from strings(item)
    elif isinstance(value,list):
        for item in value:yield from strings(item)

def protected_ids(scope):
    return {v for group in scope.resources.values() for v in group if v!=scope.account_id}

def reject_protected(value, protected):
    for value in strings(value):
        require(not any(p in value for p in protected),'protected_existing_resource_referenced')

def ownership(row,tags,name):
    values=row.get('values');require(isinstance(values,dict),'lab_values_missing')
    if row['type'] not in UNTAGGED:
        actual=values.get('tags_all',values.get('tags',{}))
        require(isinstance(actual,dict) and all(actual.get(k)==v for k,v in tags.items()),'lab_ownership_tags_mismatch')
        require(not actual.get('Name') or actual['Name'].startswith(name+'-'),'lab_resource_name_mismatch')
    if row['type'] in ('aws_security_group','aws_iam_role'):
        require(isinstance(values.get('name'),str) and values['name'].startswith(name+'-'),'lab_resource_name_mismatch')
    if row['type']=='aws_cloudwatch_log_group':require(values.get('name')=='/'+name+'/vpc-flow','lab_log_name_mismatch')

def parent_links(row, resources, config=None, unknown=None):
    values=row.get('values',{})
    for field,parent in PARENTS.get(row['type'],{}).items():
        expected=resources.get(parent,{}).get('values',{})
        key='arn' if field in ('iam_role_arn','log_destination') else 'name' if row['type']=='aws_iam_role_policy' else 'id'
        actual=values.get(field)
        if actual is not None:
            require(expected.get(key) is not None and actual==expected[key],'lab_parent_mismatch')
        else:
            require(config is not None and isinstance(unknown,dict) and unknown.get(field) is True,'lab_parent_unresolved')
            refs=config.get('expressions',{}).get(field,{}).get('references',[])
            require(refs and all(r==parent or r.startswith(parent+'.') for r in refs),'lab_parent_reference_invalid')


def settings(row, phase, account, name, unknown_policy=False):
    v=row['values'];kind=row['type'];address=row['address']
    if kind=='aws_subnet':require(v.get('map_public_ip_on_launch') == (phase=='before'), 'lab_subnet_phase_invalid')
    if kind=='aws_cloudwatch_log_group':require(v.get('retention_in_days')==1,'lab_log_retention_invalid')
    if kind=='aws_route':require(v.get('destination_cidr_block')=='0.0.0.0/0','lab_route_destination_invalid')
    if kind=='aws_flow_log':
        require(v.get('traffic_type')=='ALL' and v.get('log_destination_type')=='cloud-watch-logs','lab_flow_settings_invalid')
    if kind=='aws_vpc_security_group_ingress_rule':
        port=int(address.split('"')[1]);require(v.get('ip_protocol')=='tcp' and v.get('cidr_ipv4')=='0.0.0.0/0'
            and v.get('from_port')==v.get('to_port')==port,'lab_sg_settings_invalid')
    if kind=='aws_network_acl_rule':
        if '.deny[' in address:
            port=int(address.split('"')[1]);number={22:50,23:51,3389:52}[port]
            require(v.get('rule_number')==number and v.get('egress') is False and v.get('rule_action')=='deny'
                and str(v.get('protocol')) in ('tcp','6') and v.get('cidr_block')=='198.51.100.10/32'
                and v.get('from_port')==v.get('to_port')==port,'lab_nacl_settings_invalid')
        else:
            require(v.get('rule_number')==100 and v.get('rule_action')=='allow' and str(v.get('protocol'))=='-1'
                and v.get('cidr_block')=='0.0.0.0/0' and v.get('egress')==address.endswith('allow_out'),'lab_nacl_settings_invalid')
    if kind=='aws_iam_role':
        require(isinstance(v.get('assume_role_policy'),str),'lab_flow_trust_invalid')
        trust=json.loads(v['assume_role_policy']);rows=trust.get('Statement')
        require(isinstance(rows,list) and len(rows)==1,'lab_flow_trust_invalid')
        statement=rows[0]
        require(statement.get('Effect')=='Allow' and statement.get('Principal')=={'Service':'vpc-flow-logs.amazonaws.com'}
            and statement.get('Action')=='sts:AssumeRole','lab_flow_trust_invalid')
        require(statement.get('Condition')=={'StringEquals':{'aws:SourceAccount':account},
            'ArnLike':{'aws:SourceArn':f'arn:aws:ec2:ap-northeast-2:{account}:vpc-flow-log/*'}},'lab_flow_trust_invalid')
    if kind=='aws_iam_role_policy' and not unknown_policy:
        require(isinstance(v.get('policy'),str),'lab_flow_policy_invalid')
        document=json.loads(v['policy']);statements=document.get('Statement');require(isinstance(statements,list) and len(statements)==2,'lab_flow_policy_invalid')
        allowed={'logs:CreateLogStream','logs:PutLogEvents','logs:DescribeLogStreams','logs:DescribeLogGroups'};observed=set()
        for statement in statements:
            actions=statement.get('Action');actions=[actions] if isinstance(actions,str) else actions
            require(isinstance(actions,list) and actions and set(actions)<=allowed and statement.get('Effect')=='Allow','lab_flow_policy_invalid')
            observed.update(actions);resource=statement.get('Resource')
            if actions==['logs:DescribeLogGroups']:require(resource=='*','lab_flow_policy_invalid')
            else:require(resource==f'arn:aws:logs:ap-northeast-2:{account}:log-group:/{name}/vpc-flow:*','lab_flow_policy_invalid')
        require(observed==allowed,'lab_flow_policy_invalid')

def check_state(document, account, name, owner, protected):
    tags=identity(account,name,owner)
    require(isinstance(document,dict) and isinstance(document.get('values'),dict),'lab_state_invalid')
    resources=resource_map(document['values'].get('root_module',{}))
    for row in resources.values():
        ownership(row,tags,name);reject_protected(row['values'],protected);parent_links(row,resources)
    require(not resources or STABLE <= set(resources),'lab_state_incomplete')
    return resources

def check_plan(plan, *, account, name, owner, phase, protected_scope, initial=False, baseline_state=None):
    """Reject foreign IDs/tags, data/modules/imports/moves/replacements and unexpected actions."""
    tags=identity(account,name,owner)
    require(phase in ('before','after','destroy'),'lab_phase_invalid')
    require(protected_scope.account_id==account and protected_scope.regions==('ap-northeast-2',),'lab_protected_scope_mismatch')
    require(isinstance(plan,dict) and plan.get('format_version','').startswith('1.'),'lab_plan_format_invalid')
    variables=plan.get('variables',{})
    require(set(variables)=={'expected_account_id','region','lab_name','owner','phase','vpc_cidr'},'lab_variables_invalid')
    expected={'expected_account_id':account,'region':'ap-northeast-2','lab_name':name,'owner':owner}
    for k,v in expected.items():require(variables[k].get('value')==v,'lab_plan_identity_mismatch')
    require(variables['phase'].get('value')==('before' if initial else phase if phase!='destroy' else variables['phase'].get('value')),'lab_plan_phase_mismatch')
    network=ipaddress.ip_network(variables['vpc_cidr'].get('value'),strict=True)
    require(network.version==4 and network.prefixlen==16 and network.subnet_of(ipaddress.ip_network('10.0.0.0/8')), 'lab_cidr_invalid')
    require(not plan.get('errored') and not plan.get('deferred_changes'),'lab_plan_incomplete_or_drift')
    conf=plan.get('configuration',{});module=conf.get('root_module',{})
    require(not module.get('module_calls'),'lab_modules_forbidden')
    config={}
    for row in module.get('resources',[]):
        require(row.get('mode')=='managed' and row.get('address') in {base_address(a) for a in ADDRESSES},'outside_lab_configuration')
        require(row['address'] not in config,'lab_duplicate_resource');config[row['address']]=row
    require(set(config)=={base_address(a) for a in ADDRESSES},'lab_configuration_incomplete')
    providers=conf.get('provider_config',{});require(set(providers)=={'aws'},'lab_provider_invalid')
    require(providers['aws'].get('full_name')==PROVIDER,'lab_provider_invalid')
    expressions=providers['aws'].get('expressions',{})
    require(set(expressions)<= {'region','allowed_account_ids','default_tags'},'lab_provider_override_forbidden')
    for field,var in [('region','region'),('allowed_account_ids','expected_account_id')]:
        require(expressions.get(field,{}).get('references')==['var.'+var],'lab_provider_scope_required')
    protected=protected_ids(protected_scope)
    reject_protected(conf, protected)
    prior=plan.get('prior_state',{'values':{'root_module':{}}})
    state=check_state(prior,account,name,owner,protected)
    if initial:require(phase=='before' and not state,'lab_initial_requires_empty_state')
    else:require(bool(state),'lab_existing_owned_state_required')
    planned=resource_map(plan.get('planned_values',{}).get('root_module',{}))
    changes=plan.get('resource_changes',[]);require(isinstance(changes,list) and changes,'lab_plan_changes_required')
    seen=set();counts={}
    for change in changes:
        address=change.get('address');require(address in ADDRESSES and address not in seen,'outside_lab_resource');seen.add(address)
        require(not change.get('previous_address') and not change.get('deposed'),'lab_move_or_deposed_forbidden')
        require(change.get('mode')=='managed' and change.get('provider_name')==PROVIDER,'lab_provider_invalid')
        body=change.get('change',{});actions=body.get('actions')
        require(not body.get('importing') and actions in (['create'],['update'],['delete'],['no-op']),'lab_import_or_replace_forbidden')
        if initial:require(actions==['create'],'lab_initial_create_only')
        elif phase=='destroy':require(actions==['delete'] and address in state,'lab_destroy_owned_only')
        else:
            require(address in state or actions==['create'],'lab_unowned_existing_change')
            allowed={'aws_subnet.internal':(['update'],['no-op'])}
            if address in STABLE:require(actions in allowed.get(address,(['no-op'],)),'lab_stable_resource_change_forbidden')
            elif address in BEFORE_ONLY:require(actions in ((['delete'],) if phase=='after' else (['create'],['no-op'])),'lab_transition_invalid')
            elif address in AFTER_ONLY:require(actions in ((['create'],['no-op']) if phase=='after' else (['delete'],)),'lab_transition_invalid')
        if address in state:
            before=body.get('before');require(isinstance(before,dict) and before.get('id')==state[address]['values'].get('id'),'lab_prior_identity_mismatch')
            if actions!=['delete']:require(body.get('after',{}).get('id')==before.get('id'),'lab_resource_id_changed')
        for key in ('before','after'):

            if body.get(key) is not None:reject_protected(body[key],protected)
        if actions!=['delete']:
            row={'address':address,'type':change['type'],'values':body.get('after')}
            ownership(row,tags,name)
            unknown_policy=row['type']=='aws_iam_role_policy' and row['values'].get('policy') is None
            if unknown_policy:
                require(body.get('after_unknown',{}).get('policy') is True,'lab_policy_unresolved')
                refs=config[base_address(address)].get('expressions',{}).get('policy',{}).get('references',[])
                require(refs and all(r in ('aws_cloudwatch_log_group.flow','aws_cloudwatch_log_group.flow.arn') for r in refs),'lab_policy_reference_invalid')
            settings(row,phase,account,name,unknown_policy)
            require(address in planned,'lab_planned_resource_missing')
            require(all(row['values'].get(k)==v for k,v in planned[address]['values'].items()),'lab_plan_value_mismatch')
            parent_links(row,planned,config[base_address(address)],body.get('after_unknown',{}))
        counts['/'.join(actions)]=counts.get('/'.join(actions),0)+1
    require(seen==set(state)|set(planned),'lab_plan_resource_coverage_incomplete')
    expected_set=set() if phase=='destroy' else STABLE | (BEFORE_ONLY if phase=='before' else AFTER_ONLY)
    require(set(planned)==expected_set,'lab_planned_phase_resources_mismatch')
    baseline=check_state(baseline_state,account,name,owner,protected) if baseline_state is not None else None
    from .aws_lab_drift import verify
    synchronization=verify(plan,baseline,state,planned,{c['address']:c for c in changes})
    return {'status':'VALID','approved_parent_readback_sync':synchronization,'phase':phase,'initial':initial,'resource_count':len(planned),'actions':counts,
            'network_access':False,'limitation':'offline_plan_not_live_ownership_attestation; direct_Terraform_bypass_not_prevented'}


def export_scope(outputs, state, base_scope_data, *, account, name, owner):
    """Use real Terraform output/state only. No guessed IDs; keep scope identical across phases."""
    base=AwsScope.from_dict(base_scope_data);require(base.schema_version==2,'lab_base_scope_v2_required')
    require(base.account_id==account and base.regions==('ap-northeast-2',),'lab_base_scope_mismatch')
    state_rows=check_state(state,account,name,owner,protected_ids(base))
    entry=outputs.get('audit_lab',{});require(entry.get('sensitive') is False,'lab_output_invalid')
    value=entry.get('value');require(isinstance(value,dict),'lab_output_invalid')
    fields={'schema_version','account_id','region','lab_name','owner','phase','tags','vpc_id','subnet_id','sg_id','nacl_id','route_table_id','igw_id','log_group_arn','flow_role_arn'}
    require(set(value)==fields and value['schema_version']==1,'lab_output_fields_invalid')
    tags=identity(account,name,owner)
    for key,expected in [('account_id',account),('region','ap-northeast-2'),('lab_name',name),('owner',owner),('tags',tags)]:require(value[key]==expected,'lab_output_identity_mismatch')
    require(value['phase'] in ('before','after'),'lab_phase_invalid')
    for row in state_rows.values():settings(row,value['phase'],account,name)
    require(set(state_rows)==STABLE | (BEFORE_ONLY if value['phase']=='before' else AFTER_ONLY),'lab_state_phase_mismatch')
    mappings={'vpc_id':('aws_vpc.lab','id'),'subnet_id':('aws_subnet.internal','id'),'sg_id':('aws_security_group.lab','id'),
        'nacl_id':('aws_network_acl.lab','id'),'route_table_id':('aws_route_table.lab','id'),'igw_id':('aws_internet_gateway.lab','id'),
        'log_group_arn':('aws_cloudwatch_log_group.flow','arn'),'flow_role_arn':('aws_iam_role.flow','arn')}
    for key,(address,field) in mappings.items():require(value[key]==state_rows[address]['values'].get(field),'lab_output_state_mismatch')
    scope=deepcopy(base_scope_data)
    scope['resources']['ec2']=[value[k] for k in ('vpc_id','subnet_id','sg_id','nacl_id','route_table_id','igw_id')]
    scope['resources']['cloudtrail']=[];scope['resources']['logs']=[value['log_group_arn']]
    scope['policy']['internal_subnet_ids']=[value['subnet_id']]
    scope['policy']['nacl_criteria_confirmed']=True;scope['policy']['flow_required']=True;scope['policy']['flow_scope']='vpc'
    scope['nacl_matrix']=[{'source_ip':'198.51.100.10','destination_port':p,'return_port':55000,'expected':'BLOCK'} for p in (22,23,3389)]
    role=[r for r in base.resources.get('iam',()) if ':role/' in r];require(len(role)==1,'lab_context_role_ambiguous')
    plan={'schema_version':2,'vpcs':{'ap-northeast-2':value['vpc_id']},'targets':{}}
    for check,resource in [('IAM-01',account),('IAM-02',account),('IAM-03',role[0]),('SG-01',value['sg_id']),('VPC-01',value['vpc_id']),('NACL-01',value['nacl_id']),('CT-01',account),('FL-01',value['vpc_id'])]:
        plan['targets'][check]={'region':'global' if check.startswith('IAM') else 'ap-northeast-2','resource_id':resource}
    parsed=AwsScope.from_dict(scope);validate_targets(parsed,plan,account,['ap-northeast-2'])
    return scope,plan


def save_export(root, scope, targets, sources):
    drive,_=ntpath.splitdrive(str(root))
    require(not drive.startswith('\\\\') and not str(root).startswith(('\\\\','//')), 'network_output_path_rejected')
    path=Path(root).absolute();require(path.is_dir(),'lab_export_parent_missing')
    require(not {'.git','.aws'} & {p.lower() for p in path.parts},'lab_export_path_forbidden')
    for item in [*path.parents,path]:
        require(not item.is_symlink() and not getattr(item.lstat(),'st_file_attributes',0)&0x400,'lab_export_link_forbidden')
    target=path/('scope-'+uuid4().hex);target.mkdir(exist_ok=False)
    artifacts=[]
    for name,data in [('scope.json',scope),('targets.json',targets)]:
        raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
        with (target/name).open('xb') as f:f.write(raw)
        artifacts.append({'file':name,'sha256':hashlib.sha256(raw).hexdigest()})
    receipt={'origin':'operator_supplied_Terraform_output_and_state_not_live_attestation','sources':sources,'artifacts':artifacts,'independently_verified':False}
    with (target/'receipt.json').open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
    return str(target)
