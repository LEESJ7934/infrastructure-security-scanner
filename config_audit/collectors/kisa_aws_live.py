"""Bounded, read-only supplemental inventory of the existing isolated LAB VPC.

Reuse the existing scope validator, standard AWS credential factory and engine.
No mutating AWS API, CLI process, or caller-provided PASS flags are accepted.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import time

from cloud_security.aws_scope import AwsScope, read_json
from cloud_security.aws_live import Limits, live_factory
from ..kisa_2026 import PROFILE, assess


def normalize(raw, scope):
    private=set(scope.policy.get('internal_subnet_ids',[]))
    subnets=raw['inventory']['subnets']
    routes=raw['inventory']['route_tables']
    enis=raw['inventory']['network_interfaces']
    known={x for x in scope.resources['ec2'] if x.startswith('subnet-')}
    complete=raw['complete'] and bool(private) and {s['SubnetId'] for s in subnets}==known and private<=known
    mapping={}
    for subnet in subnets:
        matches=[t for t in routes if any(a.get('SubnetId')==subnet['SubnetId'] for a in t.get('Associations',[]))]
        if not matches: matches=[t for t in routes if any(a.get('Main') is True for a in t.get('Associations',[]))]
        if len(matches)!=1: complete=False; continue
        mapping[subnet['SubnetId']]=matches[0]
    def safe_routes(table):
        for route in table.get('Routes',[]):
            if route.get('State')!='active': return False
            if route.get('GatewayId')=='local': continue
            # A private NAT route is permitted; public IGW/unknown targets are not.
            if route.get('NatGatewayId'): continue
            return False
        return bool(table.get('Routes'))
    private_safe=complete and all(s.get('MapPublicIpOnLaunch') is False and safe_routes(mapping[s['SubnetId']]) for s in subnets if s['SubnetId'] in private)
    address_safe=True
    for eni in enis:
        if eni.get('SubnetId') in private:
            if eni.get('Association',{}).get('PublicIp'): address_safe=False
            for item in eni.get('Ipv6Addresses',[]):
                if ipaddress.ip_address(item['Ipv6Address']).is_global: address_safe=False
    # Unknown purpose for a non-private subnet requires review, not auto public.
    all_subnets_classified=known==private
    web_management_exposure=False
    for group in raw['inventory']['security_groups']:
        for permission in group.get('IpPermissions',[]):
            broad=any(r.get('CidrIp')=='0.0.0.0/0' for r in permission.get('IpRanges',[])) or any(r.get('CidrIpv6')=='::/0' for r in permission.get('Ipv6Ranges',[]))
            admin=permission.get('IpProtocol')=='-1' or permission.get('IpProtocol') in ('tcp','6') and any(permission.get('FromPort',0)<=p<=permission.get('ToPort',65535) for p in (21,22,23,3389,3306))
            web_management_exposure |= broad and admin
    values={
        'CA-07':dict(subnet_resource_inventory_complete=True if complete else None,
                     effective_routes_reviewed=True if complete and len(mapping)==len(subnets) else None,
                     public_private_resources_separated=private_safe if complete and all_subnets_classified else None,
                     private_public_address_exposure_absent=address_safe if complete else None),
        'CA-09':dict(policy_inventory_complete=raw['complete'],unnecessary_rules_absent=None,management_sources_restricted=not web_management_exposure,periodic_review_records_present=None),
    }
    # A real current technical review is recorded. A previous configuration
    # baseline alone never establishes a periodic review program or rule purpose.
    packet={'profile':PROFILE,'observations':[dict(kisa_id=id,asset_id='aws',source_kind='SAVED_LAB',collection_status='COLLECTED',product_version='EC2 API 2016-11-15',collected_at=raw['collected_at'],evidence_reference='aws-selected-raw.json',value=value) for id,value in values.items()]}
    findings=['CA09_periodic_policy_review_history_not_proven','CA09_complete_rule_purpose_approval_not_proven']
    if web_management_exposure: findings.append('world_accessible_management_rule')
    if all_subnets_classified:
        findings.append('CA07_private_only_LAB_no_public_workloads; no_public_subnet_creation_or_connectivity_claim')
    return packet,findings


def collect(scope_path):
    data,scope_bytes=read_json(scope_path);scope=AwsScope.from_dict(data)
    private=scope.policy.get('internal_subnet_ids',[])
    vpcs=[x for x in scope.resources['ec2'] if x.startswith('vpc-')]
    if len(vpcs)!=1 or not private or len(scope.regions)!=1:
        raise ValueError('explicit_independent_private_LAB_scope_required')
    limits=Limits(max_calls=80,max_pages=10,max_seconds=120)
    factory=live_factory(scope,limits)
    identity=factory('sts',scope.regions[0]).get_caller_identity()
    if identity.get('Account')!=scope.account_id: raise ValueError('aws_account_mismatch')
    ec2=factory('ec2',scope.regions[0]);vpc_id=vpcs[0]
    vpc=ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
    if len(vpc)!=1 or vpc[0].get('OwnerId')!=scope.account_id or vpc[0].get('IsDefault') is not False:
        raise ValueError('default_or_foreign_VPC_rejected')
    calls=[];inventory={};complete=True;started=time.monotonic()
    operations=[('subnets','describe_subnets','Subnets','vpc-id'),('route_tables','describe_route_tables','RouteTables','vpc-id'),
                ('network_interfaces','describe_network_interfaces','NetworkInterfaces','vpc-id'),
                ('security_groups','describe_security_groups','SecurityGroups','vpc-id'),('network_acls','describe_network_acls','NetworkAcls','vpc-id')]
    for name,operation,key,filter_name in operations:
        records=[];token=None
        for page in range(limits.max_pages):
            if len(calls)+2>=limits.max_calls or time.monotonic()-started>limits.max_seconds:
                raise ValueError('aws_selected_collection_limit')
            params={'Filters':[{'Name':filter_name,'Values':[vpc_id]}]}
            if token: params['NextToken']=token
            start=datetime.now(timezone.utc).isoformat()
            response=getattr(ec2,operation)(**params)
            calls.append(dict(operation=operation,started_at=start,ended_at=datetime.now(timezone.utc).isoformat(),request_id=response.get('ResponseMetadata',{}).get('RequestId')))
            for row in response[key]:
                if row.get('VpcId')!=vpc_id or row.get('OwnerId')!=scope.account_id:
                    raise ValueError('foreign_VPC_child_rejected')
                # Metadata only. No tags, descriptions, attachment tokens or SDK metadata.
                fields={'subnets':['SubnetId','VpcId','MapPublicIpOnLaunch','AssignIpv6AddressOnCreation','CidrBlock'],
                        'route_tables':['RouteTableId','VpcId','Associations','Routes'],
                        'network_interfaces':['NetworkInterfaceId','SubnetId','VpcId','Association','Ipv6Addresses','Groups'],
                        'security_groups':['GroupId','VpcId','IpPermissions','IpPermissionsEgress'],
                        'network_acls':['NetworkAclId','VpcId','Associations','Entries']}[name]
                records.append({k:row[k] for k in fields if k in row})
            following=response.get('NextToken')
            if not following: break
            if following==token: complete=False;break
            token=following
        else: complete=False
        inventory[name]=records
    raw={'origin':'aws_live_read_only','collected_at':datetime.now(timezone.utc).isoformat(),'account_match':True,'region':scope.regions[0],
         'scope_sha256':hashlib.sha256(scope_bytes).hexdigest(),'vpc_id':vpc_id,'complete':complete,'inventory':inventory,'requests':calls,
         'AWS_changes_performed':False,'limitations':['Private-only existing isolated VPC; no public workload exercise.','No historical periodic review is inferred from before/after configuration snapshots.']}
    packet,findings=normalize(raw,scope)
    report=assess(packet)
    review={'reviewed_at':raw['collected_at'],'source':'current_live_readonly_inventory','scope_sha256':raw['scope_sha256'],
            'inventory_sha256':hashlib.sha256(json.dumps(raw,sort_keys=True).encode()).hexdigest(),
            'findings':findings,'periodic_history_established':False,'rule_purpose_approvals_established':False,
            'next_action':'Define genuine recurring policy review and resolve rule purposes; preserve actual timestamps.'}
    return raw,packet,report,review
