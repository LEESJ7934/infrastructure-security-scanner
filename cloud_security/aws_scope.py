"""Offline AWS identity/resource scope. No SDK, credential or network imports."""
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import json
import ntpath
from pathlib import Path
import re


class AwsOfflineError(ValueError):
    """Fixed codes only; never echo untrusted input or OS exceptions."""


def require(condition, code='schema_invalid'):
    if not condition: raise AwsOfflineError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def timestamp(value):
    try:
        require(isinstance(value, str) and len(value) <= 64)
        date = datetime.fromisoformat(value)
        require(date.utcoffset() is not None, 'timestamp_timezone_required')
        return date
    except (ValueError, TypeError): raise AwsOfflineError('timestamp_invalid') from None


def reject_secrets(value, depth=0):
    require(depth <= 32, 'nesting_limit')
    if isinstance(value, dict):
        require(len(value) <= 2048)
        for key, item in value.items():
            require(isinstance(key, str))
            require(not re.search(r'^(?:password|secret|secretaccesskey|accesskeyid|sessiontoken|authorization|credentials|privatekey|cookie|securitytoken)$', key.replace('_', '').replace('-', ''), re.I), 'sensitive_input_rejected')
            reject_secrets(item, depth + 1)
    elif isinstance(value, list):
        require(len(value) <= 4096, 'row_limit')
        for item in value: reject_secrets(item, depth + 1)
    elif isinstance(value, str):
        require(len(value) <= 65536, 'text_limit')
        require(not re.search(r'(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}', value), 'sensitive_input_rejected')
    else: require(value is None or type(value) in (bool, int, float))


def read_json(path):
    candidate = Path(path)
    drive, _ = ntpath.splitdrive(str(path))
    require(not drive.startswith('\\\\') and not str(path).startswith(('//', '\\\\')), 'network_path_rejected')
    require(candidate.suffix.lower() == '.json' and not {'.git', '.aws'} & {p.lower() for p in candidate.parts}, 'input_path_rejected')
    try:
        require(not candidate.is_symlink(), 'input_link_rejected')
        with candidate.open('rb') as stream: raw = stream.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, 'input_size_limit')
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(AwsOfflineError('nonfinite_json_rejected')))
        reject_secrets(data)
        return data, raw
    except (OSError, UnicodeError, json.JSONDecodeError): raise AwsOfflineError('input_unreadable_or_invalid_json') from None


@dataclass(frozen=True)
class AwsScope:
    account_id: str
    partition: str
    regions: tuple
    services: tuple
    resources: dict
    role_allowed_actions: tuple
    role_allowed_resources: tuple
    nacl_matrix: tuple
    schema_version: int = 1
    policy: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        reject_secrets(data)
        require(isinstance(data, dict), 'scope_object_required')
        version = data.get('schema_version')
        require(type(version) is int and version in (1, 2), 'scope_version_invalid')
        keys = {'schema_version', 'account_id', 'partition', 'regions', 'services', 'resources', 'role_allowed_actions', 'role_allowed_resources', 'nacl_matrix'}
        require(set(data) == keys | ({'policy'} if version == 2 else set()), 'scope_fields_invalid')
        policy = data.get('policy', {})
        if version == 2:
            require(isinstance(policy, dict) and set(policy) == {'criteria_version', 'iam_role_criteria_confirmed', 'internal_subnet_ids', 'nacl_criteria_confirmed', 'trail_required', 'flow_required', 'flow_scope'}, 'scope_policy_invalid')
            require(isinstance(policy['criteria_version'], str) and 0 < len(policy['criteria_version']) <= 64, 'criteria_version_required')
            for k in ('iam_role_criteria_confirmed', 'nacl_criteria_confirmed', 'trail_required', 'flow_required'):
                require(type(policy[k]) is bool, 'policy_boolean_required')
            require(policy['flow_scope'] == 'vpc', 'flow_scope_unsupported')
            require(isinstance(policy['internal_subnet_ids'], list) and len(policy['internal_subnet_ids']) <= 256 and all(isinstance(v,str) for v in policy['internal_subnet_ids']) and len(policy['internal_subnet_ids']) == len(set(policy['internal_subnet_ids'])), 'internal_subnet_scope_invalid')
        require(isinstance(data['account_id'], str) and re.fullmatch(r'\d{12}', data['account_id']), 'account_invalid')
        require(data['partition'] in ('aws', 'aws-us-gov', 'aws-cn'), 'partition_invalid')
        for key in ('regions', 'services', 'role_allowed_actions', 'role_allowed_resources'):
            require(isinstance(data[key], list) and (0 if version == 2 and key.startswith('role_allowed_') else 1) <= len(data[key]) <= 64 and all(isinstance(v, str) for v in data[key]))
            require(len(set(data[key])) == len(data[key]), 'duplicate_scope_entry')
        for region in data['regions']:
            require(re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+', region), 'region_invalid')
            require((region.startswith('cn-') if data['partition'] == 'aws-cn' else region.startswith('us-gov-') if data['partition'] == 'aws-us-gov' else not region.startswith(('cn-', 'us-gov-'))), 'partition_region_mismatch')
        require(set(data['services']) <= {'iam', 'ec2', 'cloudtrail', 'logs'}, 'service_not_allowed')
        require(isinstance(data['resources'], dict) and set(data['resources']) == set(data['services']))
        for service, ids in data['resources'].items():
            require(isinstance(ids, list) and (ids or version == 2 and service in ('cloudtrail', 'logs')) and len(ids) <= 256 and all(isinstance(v, str) and len(v) <= 512 for v in ids))
            require(len(set(ids)) == len(ids) and all('*' not in v for v in ids), 'resource_scope_invalid')
        for action in data['role_allowed_actions']: require(re.fullmatch(r'[a-z0-9-]+:[A-Za-z0-9]+', action), 'action_scope_invalid')
        for resource in data['role_allowed_resources']: require(resource.startswith('arn:'), 'policy_resource_scope_invalid')
        matrix = data['nacl_matrix']
        require(isinstance(matrix, list) and (0 if version == 2 else 1) <= len(matrix) <= 32)
        for row in matrix:
            require(isinstance(row, dict) and set(row) == {'source_ip', 'destination_port', 'return_port', 'expected'})
            try: ipaddress.ip_address(row['source_ip'])
            except (ValueError, TypeError): raise AwsOfflineError('matrix_address_invalid') from None
            require(row['expected'] in ('BLOCK', 'ALLOW'))
            require(all(type(row[k]) is int and 1 <= row[k] <= 65535 for k in ('destination_port', 'return_port')))
        obj = cls(data['account_id'], data['partition'], tuple(data['regions']), tuple(data['services']),
                  {k: tuple(v) for k, v in data['resources'].items()}, tuple(data['role_allowed_actions']), tuple(data['role_allowed_resources']), tuple(matrix), version, policy)
        for service, ids in obj.resources.items():
            for resource in ids: obj.check_resource(service, resource)
        if version == 2:
            if policy['iam_role_criteria_confirmed']:
                require(obj.role_allowed_actions and obj.role_allowed_resources, 'confirmed_role_criteria_missing')
            if policy['nacl_criteria_confirmed']: require(obj.nacl_matrix, 'confirmed_nacl_matrix_missing')
            for subnet in policy['internal_subnet_ids']:
                obj.check_resource('ec2', subnet)
                require(subnet.startswith('subnet-'), 'internal_subnet_scope_invalid')
        # Data-plane ARN patterns are criteria, not inventory targets. They may
        # end in /* but cannot authorize collecting an unrelated account.
        for arn in obj.role_allowed_resources:
            pieces = arn.split(':', 5)
            require(len(pieces) == 6 and pieces[1] == obj.partition and pieces[4] in ('', obj.account_id), 'policy_resource_scope_invalid')
        return obj

    def check_identity(self, data):
        require(data.get('account_id') == self.account_id, 'account_scope_mismatch')
        require(data.get('partition') == self.partition, 'partition_scope_mismatch')

    def check_resource(self, service, resource):
        require(service in self.services, 'service_scope_mismatch')
        discovery = self.schema_version == 2 and isinstance(resource, str) and (
            service == 'cloudtrail' and (resource == self.account_id or resource.startswith('arn:' + self.partition + ':cloudtrail:')))
        require(isinstance(resource, str) and (resource in self.resources[service] or discovery), 'resource_scope_mismatch')
        if service == 'cloudtrail' and self.schema_version == 2 and resource == self.account_id: return
        if resource.startswith('arn:'):
            pieces = resource.split(':', 5)
            aws_managed_policy = service == 'iam' and len(pieces) == 6 and pieces[4] == 'aws' and pieces[5].startswith('policy/')
            require(len(pieces) == 6 and pieces[1] == self.partition and pieces[2] == service
                    and (pieces[4] == self.account_id or aws_managed_policy), 'arn_scope_mismatch')
            if service == 'cloudtrail': require(pieces[5].startswith('trail/') and len(pieces[5]) > 6, 'trail_arn_invalid')
            require(pieces[3] == '' if service == 'iam' else pieces[3] in self.regions, 'arn_region_mismatch')
        elif service == 'iam': require(resource == self.account_id, 'account_resource_mismatch')
        else: require(service == 'ec2' and re.fullmatch(r'(?:vpc|subnet|sg|acl|eni|igw|rtb|fl|nat)-[0-9a-f]+', resource), 'resource_id_invalid')

    def check_section(self, check, section, service):
        require(isinstance(section, dict) and set(section) <= {'service', 'region', 'resource_id', 'state', 'pagination', 'collected_at', 'data', 'error_code'})
        require(section.get('service') == service, 'check_service_mismatch')
        require(section.get('region') == 'global' if service == 'iam' else section.get('region') in self.regions, 'region_scope_mismatch')
        self.check_resource(service, section.get('resource_id'))
        if check in ('IAM-01', 'IAM-02'): require(section['resource_id'] == self.account_id, 'check_resource_type_mismatch')
        if check == 'IAM-03': require(section['resource_id'].startswith('arn:' + self.partition + ':iam::' + self.account_id + ':role/'), 'check_resource_type_mismatch')
        prefixes = {'SG-01': 'sg-', 'VPC-01': 'subnet-', 'NACL-01': 'acl-', 'FL-01': 'vpc-'}
        if check == 'VPC-01' and self.schema_version == 2 and section['resource_id'].startswith('vpc-'): return
        if check in prefixes: require(section['resource_id'].startswith(prefixes[check]), 'check_resource_type_mismatch')
        if check == 'CT-01' and self.schema_version == 2 and section['resource_id'] == self.account_id: return
        if check == 'CT-01': require(':trail/' in section['resource_id'], 'check_resource_type_mismatch')
