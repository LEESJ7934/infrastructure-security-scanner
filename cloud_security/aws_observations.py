"""Pure offline interpreters. No SDK/client construction or network operations.

Returns minimal facts and a criterion boolean/unknown, not AuditStatus.
The common config_audit engine alone converts these into diagnostic statuses.
"""
import ipaddress
import re

from .aws_scope import AwsOfflineError, require
from .aws_inventory import _normalize_sg
from .aws_sg_analyzer import analyze_resource


class ReviewRequired(ValueError):
    pass


def needed(data, keys):
    if not isinstance(data, dict) or not set(keys) <= set(data): raise ReviewRequired('required_fields_missing')


def flag(value):
    require(type(value) is bool, 'response_type_invalid')
    return value


def bit(value):
    require(type(value) is int and value in (0, 1), 'response_type_invalid')
    return value


def rows(value):
    require(isinstance(value, list) and len(value) <= 4096, 'response_type_invalid')
    return value


def outcome(met, reason, **facts):
    return {'criterion_met': met, 'reason': reason, 'facts': facts}


def root_keys(data, section, scope):
    needed(data, ['SummaryMap']); needed(data['SummaryMap'], ['AccountAccessKeysPresent'])
    present = bit(data['SummaryMap']['AccountAccessKeysPresent'])
    return outcome(present == 0, 'root_access_key_inventory', access_keys_present=present)


def root_mfa(data, section, scope):
    needed(data, ['SummaryMap'])
    summary = data['SummaryMap']; needed(summary, ['AccountMFAEnabled', 'AccountPasswordPresent', 'AccountAccessKeysPresent', 'AccountSigningCertificatesPresent'])
    mfa, password, keys, certificates = [bit(summary[k]) for k in ('AccountMFAEnabled', 'AccountPasswordPresent', 'AccountAccessKeysPresent', 'AccountSigningCertificatesPresent')]
    if mfa: return outcome(True, 'root_mfa_enabled', mfa_enabled=True)
    if password or keys or certificates: return outcome(False, 'root_credentials_without_mfa', mfa_enabled=False, root_credentials_present=True)
    central = data.get('CentralizedRootManagement')
    if isinstance(central, dict) and central.get('Verified') is True and central.get('CredentialsRemoved') is True:
        return {**outcome(None, 'centralized_root_credentials_removed', context_basis='input_declaration_not_online_attestation'), 'applicable': False}
    return outcome(None, 'centralized_root_context_unconfirmed', mfa_enabled=False, root_credentials_present=False)


# These selected EC2 Describe operations do not support a resource ARN scope.
# This is not a general exception for all IAM actions with Resource="*".
RESOURCE_STAR_ACTIONS = {'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVpcs', 'ec2:DescribeNetworkInterfaces'}


def role_permissions(data, section, scope):
    needed(data, ['RoleArn', 'PolicySetComplete', 'PolicyDocuments'])
    require(data['RoleArn'] == section['resource_id'], 'role_identity_mismatch')
    if flag(data['PolicySetComplete']) is not True: raise ReviewRequired('policy_set_incomplete')
    documents = rows(data['PolicyDocuments'])
    if not documents: raise ReviewRequired('policy_documents_missing')
    excessive = 0; allow_count = 0; unknown = False; safe_star = 0; observed_actions = set(); observed_resources = set()
    for document in documents:
        needed(document, ['Statement'])
        statements = document['Statement'] if isinstance(document['Statement'], list) else [document['Statement']]
        for statement in statements:
            needed(statement, ['Effect'])
            if statement['Effect'] == 'Deny':
                # Criterion concerns declarations, not complete effective access.
                continue
            if statement['Effect'] != 'Allow' or any(k in statement for k in ('NotAction', 'NotResource', 'Principal', 'Condition')):
                unknown = True; continue
            needed(statement, ['Action', 'Resource'])
            actions = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
            resources = statement['Resource'] if isinstance(statement['Resource'], list) else [statement['Resource']]
            require(actions and resources and all(isinstance(v, str) for v in actions + resources), 'policy_statement_invalid')
            require(all(re.fullmatch(r'(?:[a-z0-9-]+:[A-Za-z0-9*?]+|\*)', a) for a in actions), 'policy_action_invalid')
            require(all(r == '*' or r.startswith('arn:') for r in resources), 'policy_resource_invalid')
            observed_actions.update(actions)
            observed_resources.update(r if r == '*' or r in scope.role_allowed_resources else 'outside_LAB_scope' for r in resources)
            allow_count += 1
            for action in actions:
                if action not in scope.role_allowed_actions:
                    excessive += 1; continue
                for resource in resources:
                    if resource == '*' and action in RESOURCE_STAR_ACTIONS: safe_star += 1
                    elif resource not in scope.role_allowed_resources: excessive += 1
    if scope.schema_version == 2 and not scope.policy['iam_role_criteria_confirmed']:
        summaries=[]
        for document in documents:
            statements=document['Statement'] if isinstance(document['Statement'],list) else [document['Statement']]
            for statement in statements:
                summaries.append({'effect':statement.get('Effect'), 'actions':statement.get('Action'),
                    'resource_star':statement.get('Resource') == '*' or isinstance(statement.get('Resource'),list) and '*' in statement['Resource'],
                    'condition_present':'Condition' in statement})
        return outcome(None, 'internal_role_criteria_unconfirmed', policy_statements=summaries,
                       effective_permissions_verified=False, resource_star_alone_is_not_a_finding=True)
    if excessive: return outcome(False, 'allow_exceeds_internal_role_criteria', excessive_allow_count=excessive,
        observed_actions=sorted(observed_actions), observed_resource_patterns=sorted(observed_resources), effective_permissions_verified=False)
    if unknown or not allow_count: return outcome(None, 'policy_semantics_require_review', effective_permissions_verified=False)
    return outcome(True, 'supported_allow_declarations_within_lab_criteria', supported_allow_count=allow_count,
                   justified_resource_star_count=safe_star, observed_actions=sorted(observed_actions),
                   observed_resource_patterns=sorted(observed_resources), effective_permissions_verified=False)


def security_group(data, section, scope):
    needed(data, ['GroupId', 'VpcId', 'IpPermissions'])
    require(data['GroupId'] == section['resource_id'], 'group_identity_mismatch')
    permissions = rows(data['IpPermissions']); unknown = False
    for permission in permissions:
        needed(permission, ['IpProtocol', 'IpRanges', 'Ipv6Ranges', 'UserIdGroupPairs'])
        protocol = str(permission['IpProtocol']).lower()
        if protocol not in ('-1', 'tcp', '6', 'udp', '17', 'icmp', '1', 'icmpv6', '58'): unknown = True
        if protocol in ('tcp', '6', 'udp', '17'):
            needed(permission, ['FromPort', 'ToPort'])
            require(type(permission['FromPort']) is int and type(permission['ToPort']) is int and 0 <= permission['FromPort'] <= permission['ToPort'] <= 65535, 'port_range_invalid')
        for field, key, version in [('IpRanges', 'CidrIp', 4), ('Ipv6Ranges', 'CidrIpv6', 6)]:
            for entry in rows(permission[field]):
                needed(entry, [key])
                try: network = ipaddress.ip_network(entry[key], strict=False)
                except (ValueError, TypeError): raise AwsOfflineError('cidr_invalid') from None
                require(network.version == version, 'cidr_family_invalid')
                # Existing analyzer uses exact canonical /0 spellings.
                entry[key] = str(network)
        for pair in rows(permission['UserIdGroupPairs']): needed(pair, ['GroupId'])
        if permission.get('PrefixListIds'): unknown = True
    normalized = _normalize_sg(data)
    findings = analyze_resource({'resource_id': section['resource_id'], 'vpc_id': data['VpcId'], 'private_ip': None,
                                 'public_ip': None, 'security_groups': [normalized]})
    legacy = sorted({f['rule_id'] for f in findings})
    if findings: return outcome(False, 'explicit_worldwide_sensitive_ingress', legacy_rule_ids=legacy,
        matched_permissions=[p for f in findings for p in f['evidence']['matched_permissions']], internet_reachability_verified=False)
    if unknown: return outcome(None, 'unsupported_sg_source_or_protocol', internet_reachability_verified=False)
    return outcome(True, 'no_explicit_canonical_worldwide_sensitive_ingress', inspected_permissions=len(permissions),
        internet_reachability_verified=False, cidr_union_and_referenced_group_effects_verified=False)


def private_subnet(data, section, scope):
    if scope.schema_version == 2 and 'TopologySubnets' in data:
        needed(data,['VpcId','TopologySubnets'])
        require(data['VpcId']==section['resource_id'], 'topology_vpc_mismatch')
        topology=rows(data['TopologySubnets']); targets=scope.policy['internal_subnet_ids']
        if not targets: return outcome(None,'internal_subnet_purpose_unconfirmed',topology=topology,actual_reachability_verified=False)
        selected=[r for r in topology if r.get('SubnetId') in targets]
        if len(selected)!=len(targets): raise ReviewRequired('internal_subnet_evidence_missing')
        exposed=False
        for row in selected:
            needed(row,['AssociationResolved','MapPublicIpOnLaunch','Routes','PublicIPv4ENICount','PublicIPv6ENICount'])
            if not flag(row['AssociationResolved']): raise ReviewRequired('route_association_unresolved')
            if not row['Routes']: raise ReviewRequired('route_entries_missing')
            exposed |= flag(row['MapPublicIpOnLaunch']) or row['PublicIPv4ENICount']>0 or row['PublicIPv6ENICount']>0
            for route in rows(row['Routes']):
                needed(route,['State','GatewayKind'])
                if not any(k in route for k in ('DestinationCidrBlock','DestinationIpv6CidrBlock')): raise ReviewRequired('route_destination_missing')
                for key,version in [('DestinationCidrBlock',4),('DestinationIpv6CidrBlock',6)]:
                    if key in route: require(ipaddress.ip_network(route[key],strict=False).version==version, 'route_cidr_invalid')
                if route['State']!='active' or route['GatewayKind']=='unknown': raise ReviewRequired('unsupported_or_inactive_route')
                if route['GatewayKind']=='internet': exposed=True
        return outcome(not exposed,'confirmed_private_subnet_topology_only',topology=topology,actual_reachability_verified=False)
    if scope.schema_version == 2 and section['resource_id'] not in scope.policy['internal_subnet_ids']:
        return outcome(None,'internal_subnet_purpose_unconfirmed',subnet_id=section['resource_id'],actual_reachability_verified=False)
    needed(data, ['SubnetId', 'VpcId', 'MapPublicIpOnLaunch', 'RouteTableAssociationResolved', 'RouteTable', 'NetworkInterfaces'])
    require(data['SubnetId'] == section['resource_id'], 'subnet_identity_mismatch')
    if not flag(data['RouteTableAssociationResolved']): raise ReviewRequired('route_association_unresolved')
    table = data['RouteTable']; needed(table, ['VpcId', 'Associations', 'Routes'])
    require(table['VpcId'] == data['VpcId'], 'route_vpc_mismatch')
    associations = rows(table['Associations'])
    if not any(isinstance(a, dict) and (a.get('SubnetId') == data['SubnetId'] or a.get('Main') is True) for a in associations):
        raise ReviewRequired('route_association_missing')
    public = flag(data['MapPublicIpOnLaunch']); igw_routes = 0; unknown = False; address_count = 0
    routes = rows(table['Routes'])
    if not routes: raise ReviewRequired('route_entries_missing')
    for route in routes:
        needed(route, ['State'])
        if route['State'] != 'active': unknown = True; continue
        if not any(k in route for k in ('DestinationCidrBlock', 'DestinationIpv6CidrBlock')): raise ReviewRequired('route_destination_missing')
        for key, version in [('DestinationCidrBlock',4),('DestinationIpv6CidrBlock',6)]:
            if key in route:
                try: destination = ipaddress.ip_network(route[key], strict=False)
                except (ValueError, TypeError): raise AwsOfflineError('route_cidr_invalid') from None
                require(destination.version == version, 'route_cidr_family_invalid')
        gateway = route.get('GatewayId')
        if isinstance(gateway, str) and gateway.startswith('igw-'): igw_routes += 1
        elif gateway != 'local' and 'NatGatewayId' not in route: unknown = True
    for eni in rows(data['NetworkInterfaces']):
        needed(eni, ['NetworkInterfaceId', 'SubnetId', 'Association', 'Ipv6Addresses'])
        require(eni['SubnetId'] == data['SubnetId'], 'eni_subnet_mismatch')
        require(isinstance(eni['Association'], dict), 'association_invalid')
        if eni['Association'].get('PublicIp'):
            try: ipaddress.ip_address(eni['Association']['PublicIp'])
            except ValueError: raise AwsOfflineError('address_invalid') from None
            address_count += 1
        for address in rows(eni['Ipv6Addresses']):
            needed(address, ['Ipv6Address'])
            try: ip = ipaddress.ip_address(address['Ipv6Address'])
            except (ValueError, TypeError): raise AwsOfflineError('address_invalid') from None
            require(ip.version == 6, 'address_invalid')
            if ip.is_global: address_count += 1
    if public or igw_routes or address_count:
        return outcome(False, 'private_subnet_direct_exposure_settings_present', public_ip_on_launch=public, igw_route_count=igw_routes, public_address_count=address_count, actual_reachability_verified=False)
    if unknown: return outcome(None, 'unsupported_or_inactive_route', actual_reachability_verified=False)
    return outcome(True, 'private_subnet_settings_within_lab_scope', public_ip_on_launch=False, igw_route_count=0, actual_reachability_verified=False)


def nacl_rules(data, section, scope):
    if scope.schema_version == 2 and not scope.policy['nacl_criteria_confirmed']: return outcome(None,'nacl_criteria_unconfirmed')
    needed(data, ['NetworkAclId', 'VpcId', 'Associations', 'Entries'])
    require(data['NetworkAclId'] == section['resource_id'], 'nacl_identity_mismatch')
    associations = rows(data['Associations'])
    if not associations: raise ReviewRequired('nacl_not_associated')
    for a in associations: needed(a, ['SubnetId'])
    entries = rows(data['Entries']); seen = set(); parsed = []
    for entry in entries:
        needed(entry, ['RuleNumber', 'Egress', 'Protocol', 'RuleAction'])
        number = entry['RuleNumber']; egress = flag(entry['Egress']); protocol = str(entry['Protocol'])
        require(type(number) is int and 1 <= number <= 32767, 'nacl_rule_number_invalid')
        require((egress, number) not in seen, 'duplicate_nacl_rule_number'); seen.add((egress, number))
        require(entry['RuleAction'] in ('allow', 'deny'), 'nacl_action_invalid')
        cidr = entry.get('CidrBlock', entry.get('Ipv6CidrBlock'))
        if cidr is None: raise ReviewRequired('nacl_cidr_missing')
        try: network = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError): raise AwsOfflineError('cidr_invalid') from None
        require(network.version == (4 if 'CidrBlock' in entry else 6), 'nacl_cidr_family_invalid')
        require(protocol in ('-1', '6', '17', '1', '58'), 'unsupported_nacl_protocol')
        port_range = None
        if protocol in ('6', '17'):
            needed(entry, ['PortRange']); needed(entry['PortRange'], ['From', 'To'])
            low, high = entry['PortRange']['From'], entry['PortRange']['To']
            require(type(low) is int and type(high) is int and 0 <= low <= high <= 65535, 'port_range_invalid')
            port_range = (low, high)
        parsed.append((number, egress, protocol, entry['RuleAction'], network, port_range))
    results = []
    for test in scope.nacl_matrix:
        ip = ipaddress.ip_address(test['source_ip'])
        def first(egress, port):
            for number, direction, protocol, action, network, ports in sorted(parsed, key=lambda e: e[0]):
                if direction == egress and protocol in ('-1', '6') and ip.version == network.version and ip in network and (ports is None or ports[0] <= port <= ports[1]):
                    return action, number
            return None, None
        incoming, in_rule = first(False, test['destination_port']); outgoing, out_rule = first(True, test['return_port'])
        if incoming is None or outgoing is None: raise ReviewRequired('nacl_direction_or_default_rule_missing')
        met = incoming == 'deny' if test['expected'] == 'BLOCK' else incoming == outgoing == 'allow'
        results.append({'source_ip':test['source_ip'],'destination_port':test['destination_port'],'return_port':test['return_port'],
                        'expected': test['expected'], 'ingress_action': incoming, 'egress_return_action': outgoing,
                        'ingress_rule_number': in_rule, 'egress_rule_number': out_rule, 'criterion_met': met})
    return outcome(all(t['criterion_met'] for t in results), 'finite_tcp_management_matrix_only',
                   matrix_results=results, actual_reachability_verified=False, complete_traffic_space_verified=False)


def cloudtrail(data, section, scope):
    if scope.schema_version == 2 and not scope.policy['trail_required']: return outcome(None,'trail_requirement_unconfirmed',delivery_verification='NOT_TESTED')
    if scope.schema_version == 2 and 'TrailInventory' in data:
        trails=rows(data['TrailInventory'])
        if not trails: return outcome(False,'required_regional_trail_absent',event_history_is_not_continuous_trail=True,delivery_verification='NOT_TESTED')
        values=[cloudtrail(t, {**section,'resource_id':t.get('TrailARN')}, scope) for t in trails]
        met=True if any(v['criterion_met'] is True for v in values) else None if any(v['criterion_met'] is None for v in values) else False
        return outcome(met,'regional_trail_configuration_only',trail_results=values,delivery_verification='NOT_TESTED')
    needed(data, ['TrailPresent'])
    if not flag(data['TrailPresent']): return outcome(False, 'required_trail_absent', delivery_verification='NOT_TESTED')
    needed(data, ['TrailARN', 'HomeRegion', 'IsMultiRegionTrail', 'IncludeGlobalServiceEvents', 'Status', 'EventSelectors', 'AdvancedEventSelectors'])
    require(data['TrailARN'] == section['resource_id'] and data['HomeRegion'] in scope.regions
            and data['HomeRegion'] == section['resource_id'].split(':')[3], 'trail_identity_or_region_mismatch')
    needed(data['Status'], ['IsLogging'])
    if rows(data['AdvancedEventSelectors']): return outcome(None, 'advanced_selectors_require_review', delivery_verification='NOT_TESTED')
    selectors = rows(data['EventSelectors']); management = set()
    if not selectors: raise ReviewRequired('event_selectors_missing')
    for selector in selectors:
        needed(selector, ['IncludeManagementEvents', 'ReadWriteType', 'ExcludeManagementEventSources'])
        require(selector['ReadWriteType'] in ('All', 'ReadOnly', 'WriteOnly'), 'selector_invalid')
        if flag(selector['IncludeManagementEvents']) and not rows(selector['ExcludeManagementEventSources']):
            management.update(('ReadOnly', 'WriteOnly') if selector['ReadWriteType'] == 'All' else (selector['ReadWriteType'],))
    logging = flag(data['Status']['IsLogging']); multi = flag(data['IsMultiRegionTrail']); global_events = flag(data['IncludeGlobalServiceEvents'])
    delivery_error = bool(data['Status'].get('LatestDeliveryError'))
    regional_ok = True
    if 'RegionalStatuses' in data:
        needed(data, ['CollectionRequiredRegions'])
        require(set(data['CollectionRequiredRegions']) == set(scope.regions), 'trail_region_scope_mismatch')
        needed(data['RegionalStatuses'], scope.regions)
        regional_ok = all(flag(data['RegionalStatuses'][region]['IsLogging'])
            and not data['RegionalStatuses'][region].get('LatestDeliveryError') for region in scope.regions)
    met = logging and multi and global_events and management == {'ReadOnly', 'WriteOnly'} and not delivery_error
    met = met and regional_ok
    return outcome(met, 'trail_management_configuration_only', is_logging=logging, multi_region=multi,
                   global_service_events=global_events, read_and_write_management_events=management == {'ReadOnly', 'WriteOnly'},
                   delivery_error_present=delivery_error, regional_statuses_satisfy_scope=regional_ok, delivery_verification='NOT_TESTED')


def flow_logs(data, section, scope):
    needed(data, ['TargetResourceId', 'FlowLogs'])
    require(data['TargetResourceId'] == section['resource_id'], 'flow_target_mismatch')
    if scope.schema_version == 2 and not scope.policy['flow_required']: return outcome(None,'flow_requirement_unconfirmed',delivery_verification='NOT_TESTED')
    flows = rows(data['FlowLogs']); matches = []; pending = False
    for flow in flows:
        needed(flow, ['FlowLogId', 'ResourceId', 'TrafficType', 'FlowLogStatus', 'LogDestinationType'] + (['LogDestination'] if scope.schema_version == 1 else ['LogDestinationConfigured']))
        if flow['ResourceId'] != section['resource_id']: continue
        if scope.schema_version == 2 and flow['LogDestinationConfigured'] is not True: raise ReviewRequired('flow_destination_missing')
        if flow['LogDestinationType'] not in (('cloud-watch-logs',) if scope.schema_version == 1 else ('cloud-watch-logs','s3','kinesis-data-firehose')): raise ReviewRequired('flow_destination_type_not_supported')
        require(flow['TrafficType'] in ('ALL', 'ACCEPT', 'REJECT') and flow['FlowLogStatus'] in ('ACTIVE', 'PENDING', 'DELETING', 'DELETED'), 'flow_status_invalid')
        if flow.get('DeliverLogsStatus') not in (None, 'SUCCESS', 'FAILED'): raise AwsOfflineError('flow_delivery_status_invalid')
        if flow['FlowLogStatus'] == 'PENDING': pending = True
        if flow['TrafficType'] == 'ALL' and flow['FlowLogStatus'] == 'ACTIVE': matches.append(flow)
    if any(f.get('DeliverLogsStatus') == 'FAILED' for f in matches):
        return outcome(False, 'flow_delivery_reports_failure', delivery_verification='FAILED_METADATA_ONLY')
    if matches:
        return outcome(True, 'target_vpc_all_traffic_flow_configuration_active', matching_flow_count=len(matches), child_flow_count=sum(f.get('ResourceId') != section['resource_id'] for f in flows),
                       active_flow_log_ids=sorted(f['FlowLogId'] for f in matches), traffic_type='ALL', flow_log_status='ACTIVE',
                       delivery_verification='NOT_TESTED', actual_records_verified=False)
    if pending: return outcome(None, 'flow_configuration_pending', delivery_verification='NOT_TESTED')
    return outcome(False, 'target_vpc_all_traffic_flow_configuration_absent', delivery_verification='NOT_TESTED')


INTERPRETERS = {'IAM-01': root_keys, 'IAM-02': root_mfa, 'IAM-03': role_permissions, 'SG-01': security_group,
                'VPC-01': private_subnet, 'NACL-01': nacl_rules, 'CT-01': cloudtrail, 'FL-01': flow_logs}
