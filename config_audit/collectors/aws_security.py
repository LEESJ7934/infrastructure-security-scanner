"""AWS offline envelope -> Observation -> existing evaluate(). No live path."""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import uuid4

from cloud_security.aws_scope import AwsOfflineError, AwsScope, read_json, reject_secrets, require, timestamp
from cloud_security.aws_observations import INTERPRETERS, ReviewRequired, outcome
from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation
from ..reporting import ReportResult, SourceSnapshot

RULE_VERSION = 'AWS-LAB-OFFLINE-0.1'
CHECKS = {
 'IAM-01': ('iam', 'No root access keys', 'Root credentials permit broad account access.', 'Remove existing root access keys safely; never create keys for this LAB.'),
 'IAM-02': ('iam', 'Root MFA or confirmed centralized credential removal', 'Root credentials without MFA increase account takeover risk.', 'Enable MFA or confirm the applicable centralized root-credential management context.'),
 'IAM-03': ('iam', 'Supported LAB role Allow declarations within explicit action/resource criteria', 'Excessive role declarations increase unintended access.', 'Restrict the LAB role policy to the required actions and resources.'),
 'SG-01': ('ec2', 'No explicit worldwide management/DB ingress in the inspected SG', 'Broad ingress increases management and database exposure.', 'Replace unnecessary /0 ingress with the intended private source or SG reference.'),
 'VPC-01': ('ec2', 'Target private subnet has no direct public exposure settings', 'Public addressing and direct IGW routes undermine the private-subnet design.', 'Remove unintended public addressing/direct IGW routes only in the LAB.'),
 'NACL-01': ('ec2', 'Associated NACL meets the finite TCP ingress/return matrix', 'Earlier Allow entries can defeat a later management Deny.', 'Place the intended Deny before broad Allow entries; preserve required return traffic.'),
 'CT-01': ('cloudtrail', 'Trail logging, multi-region/global and read/write management coverage', 'Missing management-event recording reduces audit visibility.', 'Correct the LAB trail configuration; verify delivery separately.'),
 'FL-01': ('ec2', 'Active ALL-traffic Flow Logs covering the exact target VPC', 'Missing VPC traffic recording limits incident investigation.', 'Enable the intended VPC Flow Logs and investigate delivery errors.'),
}
RESERVED_P2 = ('SG-02', 'CT-02', 'FL-02', 'FL-03')
ERROR_CODES = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'ExpiredToken', 'Throttling', 'RequestLimitExceeded', 'Timeout', 'ParseError', 'ServiceUnavailable'}
ERROR_CODES |= {'NoCredentials','NoSuchEntity','ScopeViolation','CallLimitExceeded','DeadlineExceeded','QueryFailed'}


def _graph_scope(scope, data):
    """Check explicitly supplied resource identities without opening references."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == 'FlowLogId' and scope.schema_version == 2:
                # Discovery is authorized by the exact queried parent, never a
                # general wildcard permission to request arbitrary FlowLog IDs.
                require(isinstance(value,str) and re.fullmatch(r'fl-[0-9a-f]+',value), 'flow_log_id_invalid')
                scope.check_resource('ec2', data.get('ResourceId'))
            elif key in {'VpcId', 'SubnetId', 'GroupId', 'NetworkInterfaceId', 'NetworkAclId', 'FlowLogId', 'RouteTableId', 'NatGatewayId', 'ResourceId', 'TargetResourceId'}:
                scope.check_resource('ec2', value)
            elif key == 'GatewayId' and value != 'local': scope.check_resource('ec2', value)
            elif key == 'RoleArn': scope.check_resource('iam', value)
            elif key == 'TrailARN': scope.check_resource('cloudtrail', value)
            elif key == 'LogDestination' and isinstance(value, str) and value.startswith('arn:'):
                pieces = value.split(':', 5)
                require(len(pieces) == 6, 'destination_arn_invalid')
                scope.check_resource(pieces[2], value)
            else: _graph_scope(scope, value)
    elif isinstance(data, list):
        for value in data: _graph_scope(scope, value)


def validate_document(document, scope):
    reject_secrets(document)
    require(isinstance(document, dict) and set(document) == {'schema_version', 'origin', 'account_id', 'partition', 'collected_at', 'sections'})
    require(type(document['schema_version']) is int and document['schema_version'] == 1)
    require(document['origin'] in ('synthetic', 'aws_collected_snapshot'), 'origin_invalid')
    scope.check_identity(document)
    end = timestamp(document['collected_at'])
    require(isinstance(document['sections'], dict) and set(document['sections']) <= set(CHECKS), 'check_id_invalid')
    for check, section in document['sections'].items():
        scope.check_section(check, section, CHECKS[check][0])
        require(section.get('state') in ('COLLECTED', 'NOT_TESTED', 'ERROR'), 'collection_state_invalid')
        require(timestamp(section.get('collected_at')) <= end, 'section_time_after_snapshot')
        if section['state'] == 'COLLECTED':
            require(isinstance(section.get('data'), dict), 'section_data_invalid')
            pagination = section.get('pagination')
            require(isinstance(pagination, dict) and set(pagination) == {'complete', 'pages', 'next_token_present'}, 'pagination_metadata_required')
            require(type(pagination['complete']) is bool and type(pagination['next_token_present']) is bool
                and type(pagination['pages']) is int and 1 <= pagination['pages'] <= 4096, 'pagination_metadata_invalid')
            require('error_code' not in section, 'unexpected_error_code')
            _graph_scope(scope, section['data'])
        else:
            require(section.get('data') in (None, {}), 'error_payload_rejected')
            if section['state'] == 'ERROR': require(section.get('error_code') in ERROR_CODES, 'error_code_invalid')
            else: require('error_code' not in section, 'unexpected_error_code')


def convert(check, section, scope, evidence_reference):
    if section is None or section['state'] == 'NOT_TESTED': return Observation(evidence_reference=evidence_reference)
    if section['state'] == 'ERROR': return Observation(evidence_reference=evidence_reference, collection_error=True)
    pagination = section['pagination']
    if not pagination['complete'] or pagination['next_token_present']:
        value = outcome(None, 'partial_collection_no_pass')
    else:
        try: value = INTERPRETERS[check](deepcopy(section['data']), section, scope)
        except ReviewRequired as error: value = outcome(None, str(error))
        except (AwsOfflineError, ValueError, TypeError, KeyError, IndexError, AttributeError):
            return Observation(evidence_reference=evidence_reference, collection_error=True)
    return Observation(value, evidence_reference)


def build_report(document, scope, *, source_reference, source_sha256, expected_sha256=None, scope_sha256=None):
    validate_document(document, scope)
    require(isinstance(source_sha256, str) and len(source_sha256) == 64 and all(c in '0123456789abcdef' for c in source_sha256), 'source_hash_invalid')
    if expected_sha256 is not None: require(expected_sha256 == source_sha256, 'input_hash_mismatch')
    rule_version = RULE_VERSION if scope.schema_version == 1 else 'AWS-LAB-COLLECTION-0.2'
    now = datetime.now(timezone.utc); execution = str(uuid4()); results = []
    for check, (service, criterion, risk, recommendation) in CHECKS.items():
        section = document['sections'].get(check)
        reference = 'sha256:' + source_sha256 + '#sections/' + check
        observation = convert(check, section, scope, reference)
        value = observation.observed_value
        not_applicable = isinstance(value, dict) and value.get('applicable') is False
        rule = AuditRule(check, rule_version, criterion, recommendation, condition=lambda v: v['criterion_met'], product='aws_' + service,
                         version_matches=(lambda _: False) if not_applicable else None)
        resource = section['resource_id'] if section else 'uncollected/' + check
        region = section['region'] if section else 'unknown'
        asset = AuditAsset('aws/' + scope.partition + '/' + scope.account_id + '/' + region + '/' + service + '/' + resource, 'aws_' + service, 'offline-envelope-1')
        result = evaluate(asset, rule, observation, execution_id=execution, checked_at=now)
        reason = section.get('error_code') if section and section['state'] == 'ERROR' else 'response_parse_failed' if observation.collection_error else value['reason'] if value else 'not_collected'
        results.append({**result.to_safe_dict(), 'product': asset.product, 'version': asset.version,
            'status': result.status.value, 'reason': reason, 'observed_value': deepcopy(value), 'expected_condition': criterion,
            'risk_description': risk, 'recommendation': recommendation, 'evidence_reference': reference,
            'evidence_references': [{'reference': source_reference, 'declared_sha256': expected_sha256}],
            'collection_status': section['state'] if section else 'NOT_TESTED',
            'collection_complete': section['pagination']['complete'] and not section['pagination']['next_token_present'] if section and section['state'] == 'COLLECTED' else False,
            'collected_at': section['collected_at'] if section else None, 'scope': criterion,
            'criteria_version': scope.policy.get('criteria_version') if scope.schema_version == 2 else RULE_VERSION,
            'verification_method': 'offline_saved_aws_configuration', 'origin': document['origin'],
            'analyses': {'data_plane_reachability': 'NOT_TESTED', 'log_delivery_records': 'NOT_TESTED'} })
    return {'schema_version': 1, 'mode': 'LAB_OFFLINE', 'origin': document['origin'], 'origin_basis': 'input_declaration_not_remote_attestation',
        'execution_id': execution, 'rule_version': rule_version, 'generated_at': now.isoformat(), 'snapshot_collected_at': document['collected_at'],
        'account_id': scope.account_id, 'partition': scope.partition, 'scope_sha256': scope_sha256, 'results': results,
        'summary': dict(Counter(row['status'] for row in results)),
        'evidence': {'reference': source_reference, 'file_sha256': source_sha256, 'expected_sha256': expected_sha256,
            'hash_comparison': 'MATCH_DECLARED_HASH' if expected_sha256 else 'NOT_VERIFIED', 'independently_verified': False,
            'verified_at': now.isoformat(), 'basis': 'local_file_bytes_only_not_source_authenticity'},
        'reserved_p2_checks': list(RESERVED_P2),
        'limitations': ['no_AWS_API_or_SDK_client_created', 'internal_LAB_not_KISA_or_customer_certification',
            'completeness_and_origin_are_input_declarations', 'no_actual_effective_IAM_permissions_or_network_reachability_proof',
            'CloudTrail_and_FlowLogs_configuration_not_record_delivery_proof', 'existing_OPEN_RESOLVED_DB_and_Day5_reports_unchanged']}


def load_report(input_path, scope_path, *, expected_sha256=None):
    scope_data, scope_raw = read_json(scope_path); scope = AwsScope.from_dict(scope_data)
    document, raw = read_json(input_path); hashed = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None:
        require(isinstance(expected_sha256, str) and len(expected_sha256) == 64 and all(c in '0123456789abcdefABCDEF' for c in expected_sha256), 'expected_hash_invalid')
        require(hashed == expected_sha256.lower(), 'input_hash_mismatch')
        expected_sha256 = expected_sha256.lower()
    return build_report(document, scope, source_reference=str(input_path), source_sha256=hashed,
                        expected_sha256=expected_sha256, scope_sha256=hashlib.sha256(scope_raw).hexdigest())


def as_snapshot(report, identifier):
    return SourceSnapshot(snapshot_id=identifier, day=0, source='phase2_aws_offline', input_kind='LAB',
        collection={'origin': report['origin'], 'collected_at': report['snapshot_collected_at'], 'scope_sha256': report['scope_sha256']},
        results=tuple(ReportResult(r['asset_id'], r['check_id'], r['rule_version'],
            automatic={k: r[k] for k in ('status', 'checked_at', 'collected_at', 'scope', 'verification_method', 'evidence_references')},
            analyses=deepcopy(r['analyses']), recommendation=r['recommendation']) for r in report['results']))


def compare_reports(before, after):
    """No reevaluation: explicit saved report pairing for a future retest view."""
    from ..comparison import TRANSITIONS
    from ..statuses import AuditStatus
    for report in (before,after):
        require(isinstance(report,dict) and isinstance(report.get('results'),list), 'comparison_schema_invalid')
        for row in report['results']:
            require(isinstance(row,dict) and {'check_id','asset_id','status','scope','verification_method'} <= set(row), 'comparison_schema_invalid')
            require(isinstance(row['status'],str) and row['status'] in {s.value for s in AuditStatus}, 'comparison_status_invalid')
    require(before.get('mode') == after.get('mode') == 'LAB_OFFLINE', 'comparison_mode_mismatch')
    issues = []
    for key in ('origin', 'account_id', 'partition', 'scope_sha256', 'rule_version'):
        if before.get(key) != after.get(key) or before.get(key) is None: issues.append(key + '_mismatch_or_unknown')
    if timestamp(before['snapshot_collected_at']) >= timestamp(after['snapshot_collected_at']): issues.append('collection_time_not_increasing')
    rows = []
    for check in CHECKS:
        a = [r for r in before['results'] if r['check_id'] == check]; b = [r for r in after['results'] if r['check_id'] == check]
        local = list(issues)
        if len(a) != 1 or len(b) != 1:
            rows.append({'check_id': check, 'comparison_result': 'UNVERIFIABLE', 'issues': ['missing_or_duplicate_result']}); continue
        a, b = a[0], b[0]
        if a['asset_id'] != b['asset_id'] or a['scope'] != b['scope'] or a['verification_method'] != b['verification_method']: local.append('asset_scope_or_method_mismatch')
        rows.append({'check_id': check, 'asset_id': b['asset_id'], 'before_status': a['status'], 'after_status': b['status'],
            'comparison_result': 'INCOMPARABLE' if local else TRANSITIONS.get((a['status'], b['status']), 'UNVERIFIABLE'), 'issues': local,
            'actual_remediation_proven': False, 'evidence_independently_verified': False})
    return {'results': rows, 'summary': dict(Counter(r['comparison_result'] for r in rows)), 'limitations': ['recorded_transition_not_proof_of_remediation_causality']}
