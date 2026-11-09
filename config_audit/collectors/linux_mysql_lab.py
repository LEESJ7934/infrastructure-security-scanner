"""Offline normalization or explicit local LAB reads; uses the existing engine.

Reuses Day2 SSH/MySQL parsers. No lifecycle or hardening commands are invoked.
No password/authentication columns, raw grants, file contents or logs exported.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from .linux_ssh import parse_ssh_settings
from .mysql_config import parse_mysql_settings
from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation
from ..reporting import ReportResult, SourceSnapshot
from ..comparison import TRANSITIONS

PROJECT = 'scanner-p2lm'
REPLAY_PROJECT = 'scanner-p2lm-replay'
PROFILES = {'current': PROJECT, 'replay': REPLAY_PROJECT}
RULE_VERSION = 'LINUX-MYSQL-LAB-0.1'
VERSIONS = {'linux': '24.04', 'mysql': '8.4.13'}
SCOPE = 'fixed_disposable_LAB_effective_settings_only'
CHECKS = {
 'LINUX-LAB-001': ('linux', 'SSH direct root login disabled', 'Set PermitRootLogin no.', 'LAB-SSH-002'),
 'LINUX-LAB-002': ('linux', 'SSH password authentication disabled', 'Set PasswordAuthentication no; prepare key-based access before applying outside this LAB.', None),
 'LINUX-LAB-003': ('linux', 'Root-owned regular shadow/sshd_config; approved restrictive modes', 'Set shadow 0640 or 0600 and sshd_config 0600 or 0644; remove symlinks and incorrect ownership.', None),
 'LINUX-LAB-004': ('linux', 'No listener on the unnecessary LAB demo TCP port 9000', 'Remove the LAB demo service; this is not an inventory of all services.', None),
 'LINUX-LAB-005': ('linux', 'Active rsyslog with the explicit LAB auth/authpriv route', 'Enable the LAB rsyslog auth route and restart the owned daemon.', None),
 'MYSQL-LAB-001': ('mysql', 'No anonymous account in mysql.user', 'Remove the LAB anonymous account.', None),
 'MYSQL-LAB-002': ('mysql', 'No root account with non-loopback Host', 'Remove remote root accounts; retain local administration.', None),
 'MYSQL-LAB-003': ('mysql', 'GLOBAL local_infile = 0', 'Disable local_infile when unused.', 'LAB-MYSQL-001'),
 'MYSQL-LAB-004': ('mysql', 'GLOBAL require_secure_transport = 1', 'Require secure transport; separately verify TCP TLS identity and cipher.', 'LAB-MYSQL-002'),
 'MYSQL-LAB-005': ('mysql', 'lab_app@localhost has SELECT only on lab_data.items; no roles/proxy/mandatory roles', 'Revoke broad grants and grant only SELECT on lab_data.items.', None),
}
SQL_SETTINGS = 'SELECT VERSION(), @@GLOBAL.local_infile, @@GLOBAL.require_secure_transport, @@GLOBAL.skip_name_resolve, @@GLOBAL.general_log'
SQL_ACCOUNTS = """SELECT
 (SELECT COUNT(*) FROM mysql.user WHERE User=''),
 (SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1')),
 (SELECT COUNT(*) FROM mysql.user WHERE User='lab_app' AND Host='localhost'),
 (SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER='lab_app' AND TO_HOST='localhost'),
 (SELECT COUNT(*) FROM mysql.proxies_priv WHERE User='lab_app' AND Host='localhost'),
 IF(@@GLOBAL.mandatory_roles='',0,1)"""
SQL_GRANTS = "SHOW GRANTS FOR 'lab_app'@'localhost'"
ERRORS = {'query_failed', 'parse_failed', 'startup_config_mismatch'}


class LabInputError(ValueError):
    """Contains only fixed diagnostic codes, never process output."""


def require(ok, code='lab_schema_invalid'):
    if not ok: raise LabInputError(code)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def timestamp(value):
    try:
        require(isinstance(value, str) and len(value) <= 64)
        parsed = datetime.fromisoformat(value)
        require(parsed.utcoffset() is not None)
        return parsed
    except (ValueError, TypeError): raise LabInputError('timestamp_invalid') from None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def section(value=None, error=False):
    return {'state': 'ERROR' if error else 'NOT_TESTED' if value is None else 'COLLECTED', 'value': None if error else value,
            **({'error_code': 'query_failed'} if error else {})}


def grants_summary(raw):
    """Complete SHOW GRANTS rows; never retain usernames/hashes from the text."""
    rows = raw.splitlines()
    require(0 < len(rows) <= 128, 'grant_rows_invalid')
    result = []
    suffix = r' TO `lab_app`@`localhost`'
    for row in rows:
        if row == 'GRANT USAGE ON *.* TO `lab_app`@`localhost`': value = 'USAGE'
        elif row == 'GRANT SELECT ON `lab_data`.`items` TO `lab_app`@`localhost`': value = 'SELECT_LAB_TABLE'
        elif re.fullmatch(r'GRANT [A-Z_, ]+ ON .+' + suffix + r'( WITH GRANT OPTION)?', row): value = 'EXCESSIVE'
        else: value = 'UNRECOGNIZED'
        result.append(value)
    return result


def normalize_linux(raw):
    require(isinstance(raw, dict) and set(raw) == {'version', 'components', 'ssh', 'ssh_error', 'files', 'files_error', 'demo_listener', 'logging', 'logging_error'}, 'linux_response_invalid')
    for key in ('ssh_error', 'files_error', 'logging_error'): require(type(raw[key]) is bool)
    require(raw['ssh'] is None or isinstance(raw['ssh'], str) and len(raw['ssh']) <= 4096)
    ssh = parse_ssh_settings(raw['ssh'] or '')
    checks = {}
    for check, key in [('LINUX-LAB-001', 'permitrootlogin'), ('LINUX-LAB-002', 'passwordauthentication')]:
        item = ssh[key]
        checks[check] = section(item.observed_value, raw['ssh_error'] or item.collection_error)
    checks['LINUX-LAB-003'] = section(raw['files'], raw['files_error'])
    checks['LINUX-LAB-004'] = section(raw['demo_listener'])
    checks['LINUX-LAB-005'] = section(raw['logging'], raw['logging_error'])
    return {'version': raw['version'], 'components': raw['components'], 'checks': checks}


def normalize_mysql(settings=None, accounts=None, grants=None):
    checks = {check: section(error=True) for check, info in CHECKS.items() if info[0] == 'mysql'}
    version = None
    if settings is not None:
        parsed = parse_mysql_settings(settings)
        version = parsed['version'].observed_value
        for check, key in [('MYSQL-LAB-003', 'local_infile'), ('MYSQL-LAB-004', 'require_secure_transport')]:
            item = parsed[key]; checks[check] = section(item.observed_value, item.collection_error or parsed['version'].collection_error)
    if accounts is not None:
        columns = accounts.strip().split('\t')
        require(len(columns) == 6 and all(re.fullmatch(r'\d{1,9}', c) for c in columns), 'account_counts_invalid')
        anonymous, remote, app, roles, proxy, mandatory = map(int, columns)
        require(mandatory in (0, 1), 'account_counts_invalid')
        checks['MYSQL-LAB-001'] = section(anonymous)
        checks['MYSQL-LAB-002'] = section(remote)
        if grants is not None:
            checks['MYSQL-LAB-005'] = section({'account_count': app, 'roles_assigned': roles, 'proxy_grants': proxy,
                'mandatory_roles': bool(mandatory), 'direct_grants': grants_summary(grants)})
    return {'version': version, 'components': {}, 'checks': checks}


def validate_value(check, value):
    if value is None: return
    if check in {'LINUX-LAB-001', 'LINUX-LAB-002'}:
        require(isinstance(value, str) and value in {'yes', 'no', 'without-password', 'prohibit-password', 'forced-commands-only', 'unrecognized'})
    elif check == 'LINUX-LAB-003':
        require(isinstance(value, list) and len(value) == 2)
        require({v.get('path') for v in value if isinstance(v, dict)} == {'/etc/shadow', '/etc/ssh/sshd_config'})
        for v in value:
            require(set(v) == {'path', 'mode', 'uid', 'regular', 'symlink', 'group_approved'})
            require(type(v['mode']) is int and 0 <= v['mode'] <= 0o7777 and type(v['uid']) is int and 0 <= v['uid'] <= 2**32)
            require(type(v['regular']) is bool and type(v['symlink']) is bool and type(v['group_approved']) is bool)
    elif check == 'LINUX-LAB-004': require(type(value) is bool)
    elif check == 'LINUX-LAB-005':
        require(isinstance(value, dict) and set(value) == {'daemon_running', 'auth_route_enabled', 'startup_config_matches'} and all(type(v) is bool for v in value.values()))
    elif check in {'MYSQL-LAB-001', 'MYSQL-LAB-002', 'MYSQL-LAB-003', 'MYSQL-LAB-004'}:
        require(type(value) is int and 0 <= value < 10**9)
        if check in {'MYSQL-LAB-003', 'MYSQL-LAB-004'}: require(value in (0, 1))
    elif check == 'MYSQL-LAB-005':
        require(isinstance(value, dict) and set(value) == {'account_count', 'roles_assigned', 'proxy_grants', 'mandatory_roles', 'direct_grants'})
        for key in ('account_count', 'roles_assigned', 'proxy_grants'): require(type(value[key]) is int and 0 <= value[key] < 10**9)
        require(type(value['mandatory_roles']) is bool and isinstance(value['direct_grants'], list) and 0 < len(value['direct_grants']) <= 128)
        require(all(isinstance(v, str) and v in {'USAGE', 'SELECT_LAB_TABLE', 'EXCESSIVE', 'UNRECOGNIZED'} for v in value['direct_grants']))


def validate(bundle):
    require(isinstance(bundle, dict) and {'schema_version', 'rule_version', 'origin', 'collected_at', 'nodes'} <= set(bundle)
        and set(bundle) <= {'schema_version', 'rule_version', 'origin', 'collected_at', 'nodes', 'project', 'capture_context'})
    require(bundle.get('project', PROJECT) in PROFILES.values(), 'project_not_allowed')
    if 'capture_context' in bundle:
        require(bundle['capture_context'] == ('new_reproduction_not_historical_baseline' if bundle.get('project') == REPLAY_PROJECT else 'current_state_snapshot'), 'capture_context_invalid')
    require(type(bundle['schema_version']) is int and bundle['schema_version'] == 1 and bundle['rule_version'] == RULE_VERSION)
    require(isinstance(bundle['origin'], str) and bundle['origin'] in {'synthetic', 'local_container_readonly'})
    timestamp(bundle['collected_at'])
    require(isinstance(bundle['nodes'], dict) and set(bundle['nodes']) == set(VERSIONS))
    for product, node in bundle['nodes'].items():
        require(isinstance(node, dict) and set(node) <= {'version', 'components', 'checks', 'image_id', 'container_id', 'started_at'})
        require(node.get('version') is None or isinstance(node['version'], str) and re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+(?:-log)?)?', node['version']))
        require(isinstance(node.get('components'), dict) and set(node['components']) <= {'openssh-server', 'rsyslog'})
        for v in node['components'].values(): require(isinstance(v, str) and re.fullmatch(r'(?:synthetic-)?[0-9][0-9A-Za-z:.+~_-]{0,79}', v))
        require(isinstance(node.get('checks'), dict) and set(node['checks']) <= {k for k, info in CHECKS.items() if info[0] == product})
        for check, item in node['checks'].items():
            require(isinstance(item, dict) and set(item) <= {'state', 'value', 'error_code'})
            require('value' in item)
            require(isinstance(item.get('state'), str) and item['state'] in {'COLLECTED', 'ERROR', 'NOT_TESTED'})
            if item['state'] != 'COLLECTED': require(item.get('value') is None)
            if item['state'] == 'ERROR': require(item.get('error_code') in ERRORS)
            else: require('error_code' not in item)
            validate_value(check, item.get('value'))
        for key, pattern in [('image_id', r'sha256:[a-f0-9]{64}'), ('container_id', r'[a-f0-9]{64}')]:
            if key in node: require(isinstance(node[key], str) and re.fullmatch(pattern, node[key]))
        if 'started_at' in node: require(timestamp(node['started_at']) <= timestamp(bundle['collected_at']), 'invalid_startup_time')


def load(path):
    try:
        with Path(path).open('rb') as f: raw = f.read(1024*1024 + 1)
        require(len(raw) <= 1024*1024, 'input_size_limit')
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
        bundle = data.get('bundle') if isinstance(data, dict) and 'bundle' in data else data
        validate(bundle)
        return bundle, digest(raw)
    except (OSError, UnicodeError, json.JSONDecodeError): raise LabInputError('input_unreadable_or_invalid_json') from None


def predicate(check, value):
    if check in {'LINUX-LAB-001', 'LINUX-LAB-002'}: return None if value == 'unrecognized' else value == 'no'
    if check == 'LINUX-LAB-003':
        return all(v['regular'] and not v['symlink'] and v['uid'] == 0 and v['group_approved'] and v['mode'] in ({0o400, 0o600, 0o640} if v['path'] == '/etc/shadow' else {0o600, 0o644}) for v in value)
    if check == 'LINUX-LAB-004': return not value
    if check == 'LINUX-LAB-005': return all(value.values())
    if check in {'MYSQL-LAB-001', 'MYSQL-LAB-002', 'MYSQL-LAB-003'}: return value == 0
    if check == 'MYSQL-LAB-004': return value == 1
    if check == 'MYSQL-LAB-005':
        if value['account_count'] != 1 or value['proxy_grants'] > 0 or 'EXCESSIVE' in value['direct_grants']: return False
        if value['roles_assigned'] > 0 or value['mandatory_roles'] or 'UNRECOGNIZED' in value['direct_grants']: return None
        return set(value['direct_grants']) == {'USAGE', 'SELECT_LAB_TABLE'}


def audit(bundle=None, *, synthetic=False):
    if bundle is not None:
        validate(bundle)
        require(synthetic == (bundle['origin'] == 'synthetic'), 'origin_flag_mismatch')
    now = datetime.now(timezone.utc); execution = str(uuid4()); results = []
    for check, (product, criterion, recommendation, legacy) in CHECKS.items():
        node = bundle['nodes'][product] if bundle else {}
        item = node.get('checks', {}).get(check, section())
        supported = node.get('version') == VERSIONS[product]
        value = item.get('value') if supported else None
        collected = bundle['collected_at'] if bundle else None
        ref = 'sha256:' + digest(json.dumps(item, sort_keys=True).encode()) + '#' + check if bundle else None
        rule = AuditRule(check, RULE_VERSION, criterion, recommendation, condition=lambda v, c=check: predicate(c, v), product=product)
        result = evaluate(AuditAsset((bundle.get('project', PROJECT) if bundle else PROJECT) + '/' + product, product, node.get('version')), rule,
            Observation(value, ref, item['state'] == 'ERROR'), execution_id=execution, checked_at=now)
        results.append({**result.to_safe_dict(), 'product': product, 'version': node.get('version'), 'observed_value': value,
            'expected_condition': criterion, 'recommendation': recommendation, 'evidence_reference': ref, 'collected_at': collected,
            'scope': SCOPE, 'verification_method': 'synthetic_fixture' if synthetic else 'readonly_local_Docker_queries' if bundle else 'not_executed',
            'legacy_check_id': legacy, 'reason': item.get('error_code') or ('unsupported_or_unknown_product_version' if bundle and not supported else 'internal_LAB_criterion')})
    return {'schema_version': 1, 'mode': 'LAB', 'origin': bundle['origin'] if bundle else 'not_executed', 'rule_version': RULE_VERSION,
        'generated_at': now.isoformat(), 'bundle': deepcopy(bundle), 'results': results, 'summary': dict(Counter(r['status'] for r in results)),
        'limitations': ['internal_LAB_not_KISA_certification', 'Linux_container_not_full_host_audit', 'SSH_Match_scope_root_loopback_only',
            'rsyslog_route_and_process_not_log_delivery', 'demo_TCP9000_only_not_all_services', 'TLS_transport_policy_not_TCP_TLS_handshake',
            'least_privilege_only_fixed_lab_app_account', 'measured_hash_not_independent_verification_or_authenticity']}


def as_snapshot(report, identifier):
    return SourceSnapshot(snapshot_id=identifier, day=0, source='phase2_linux_mysql', input_kind='LAB',
        collection={'origin': report['origin'], 'collected_at': report['bundle']['collected_at'] if report['bundle'] else None,
            'project': report['bundle'].get('project', PROJECT) if report['bundle'] else PROJECT,
            'capture_context': report['bundle'].get('capture_context') if report['bundle'] else None},
        results=tuple(ReportResult(r['asset_id'], r['check_id'], r['rule_version'],
            automatic={k: r[k] for k in ('status', 'checked_at', 'collected_at', 'scope', 'verification_method', 'evidence_reference')},
            recommendation=r['recommendation']) for r in report['results']))


def compare(report, path):
    before, file_hash = load(path); after = report['bundle']
    require(after is not None and before['origin'] == after['origin'], 'comparison_origin_mismatch')
    first = audit(before, synthetic=before['origin'] == 'synthetic')
    issues = []
    if before.get('project', PROJECT) != after.get('project', PROJECT): issues.append('logical_project_asset_mismatch')
    if timestamp(before['collected_at']) >= timestamp(after['collected_at']): issues.append('collection_time_not_increasing')
    for p in VERSIONS:
        if (before['nodes'][p]['version'], before['nodes'][p]['components']) != (after['nodes'][p]['version'], after['nodes'][p]['components']): issues.append(p + '_product_or_component_version_changed')
    rows = []
    for a, b in zip(first['results'], report['results']):
        transition = 'INCOMPARABLE' if issues else TRANSITIONS.get((a['status'], b['status']), 'UNVERIFIABLE')
        rows.append({'asset_id': b['asset_id'], 'check_id': b['check_id'], 'before_status': a['status'], 'after_status': b['status'],
            'before_values': a['observed_value'], 'after_values': b['observed_value'], 'comparison_result': transition,
            'remediation_complete_in_LAB': report['origin'] == 'local_container_readonly' and transition == 'IMPROVED_OBSERVED'})
    report['comparison'] = {'baseline_sha256': file_hash, 'issues': issues, 'results': rows,
        'summary': dict(Counter(r['comparison_result'] for r in rows)), 'basis': 'same_internal_rule_saved_observations',
        'independent_expected_hash_provided': False, 'remediation_causality_proven': False, 'mutations_performed_by_collector': False}
    return report


def run(args):
    try:
        done = subprocess.run(args, capture_output=True, timeout=30, encoding='utf-8', errors='strict', shell=False)
        require(done.returncode == 0 and len(done.stdout) <= 1024*1024, 'docker_query_failed')
        return done.stdout
    except (OSError, UnicodeError, subprocess.SubprocessError): raise LabInputError('docker_query_failed') from None


def docker_scope(project=PROJECT):
    require(project in PROFILES.values(), 'project_not_allowed')
    context = run(['docker', 'context', 'show']).strip()
    require(context in {'default', 'desktop-linux'}, 'local_context_required')
    try:
        endpoint = json.loads(run(['docker', 'context', 'inspect', context]))[0]['Endpoints']['docker']['Host']
        require(endpoint in {'unix:///var/run/docker.sock', 'npipe:////./pipe/docker_engine', 'npipe:////./pipe/dockerDesktopLinuxEngine'}, 'remote_docker_rejected')
        args = ['docker', '--context', context]
        require(run(args + ['info', '--format', '{{.OSType}}']).strip() == 'linux', 'linux_engine_required')
        nodes = {}
        for service in VERSIONS:
            obj = json.loads(run(args + ['inspect', project + '-' + service + '-1']))[0]
            labels = obj['Config'].get('Labels', {}); host = obj['HostConfig']
            require(labels.get('com.docker.compose.project') == project and labels.get('com.docker.compose.service') == service, 'foreign_container_rejected')
            # Same restrictions as before, with a precise failure stage. Missing
            # safety fields are not accepted as implicit safe defaults.
            require(obj['State'].get('Running') is True, service + '_container_not_running')
            require(host.get('Privileged') is False, service + '_privileged_or_unknown')
            require(host.get('NetworkMode') == project + '_isolated', service + '_network_mode_rejected')
            require(host.get('PidMode') in ('', 'private'), service + '_pid_namespace_rejected')
            require(host.get('IpcMode') in ('private', ''), service + '_ipc_namespace_rejected')
            require(isinstance(host.get('PortBindings'), dict) and not any(host['PortBindings'].values()), service + '_published_ports_rejected')
            require(isinstance(obj.get('Id'), str) and re.fullmatch(r'[a-f0-9]{64}', obj['Id']), 'container_identity_invalid')
            require(isinstance(obj.get('Image'), str) and re.fullmatch(r'sha256:[a-f0-9]{64}', obj['Image']), 'image_identity_invalid')
            images = {project + '-linux:before', project + '-linux:after'} if service == 'linux' else {project + '-mysql:local'}
            require(obj['Config'].get('Image') in images, 'unexpected_project_image')
            caps = {c.removeprefix('CAP_') for c in host.get('CapAdd') or []}
            allowed = {'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID'} | ({'NET_BIND_SERVICE', 'SYS_CHROOT'} if service == 'linux' else set())
            require(caps <= allowed, 'unsafe_capabilities')
            require(set(obj['NetworkSettings']['Networks']) == {project + '_isolated'}, 'unexpected_network_membership')
            # /var/run is /run on the MySQL image. Accept either canonical
            # spelling only for tmpfs, never a bind/volume or arbitrary path.
            allowed_mounts = {'/var/lib/mysql', '/run/lab', '/var/run/mysqld', '/run/mysqld'} if service == 'mysql' else set()
            require(all(m.get('Type') == 'tmpfs' and m.get('Destination') in allowed_mounts for m in obj.get('Mounts', [])), 'unexpected_mount')
            require(obj['Config'].get('Entrypoint') == (['python3', '/opt/lab/start-linux.py'] if service == 'linux' else ['bash', '/opt/lab/start-mysql.sh']), 'unknown_startup_command')
            nodes[service] = obj
        network = json.loads(run(args + ['network', 'inspect', project + '_isolated']))[0]
        require(network.get('Internal') is True and network.get('Driver') == 'bridge' and network.get('Labels', {}).get('com.docker.compose.project') == project
            and set(network.get('Containers', {})) == {v['Id'] for v in nodes.values()}, 'network_scope_invalid')
        return args, nodes
    except (ValueError, KeyError, IndexError, TypeError) as error:
        if isinstance(error, LabInputError): raise
        raise LabInputError('docker_response_invalid') from None


def collect_docker(project=PROJECT):
    args, containers = docker_scope(project)
    nodes = {}
    try:
        raw = json.loads(run(args + ['exec', containers['linux']['Id'], 'python3', '/opt/lab/collect-linux.py']), object_pairs_hook=unique)
        nodes['linux'] = normalize_linux(raw)
    except (LabInputError, ValueError, TypeError):
        nodes['linux'] = {'version': None, 'components': {}, 'checks': {c: section(error=True) for c, info in CHECKS.items() if info[0] == 'linux'}}
    values = []
    for query in (SQL_SETTINGS, SQL_ACCOUNTS, SQL_GRANTS):
        try:
            values.append(run(args + ['exec', containers['mysql']['Id'], 'mysql', '--defaults-extra-file=/run/lab/client.cnf',
                '--batch', '--raw', '--skip-column-names', '--connect-timeout=5', '--execute=' + query]))
        except LabInputError: values.append(None)
    try: nodes['mysql'] = normalize_mysql(*values)
    except LabInputError:
        nodes['mysql'] = normalize_mysql(values[0])
    for p in VERSIONS:
        nodes[p].update(image_id=containers[p]['Image'], container_id=containers[p]['Id'], started_at=containers[p]['State']['StartedAt'])
    bundle = {'schema_version': 1, 'rule_version': RULE_VERSION, 'origin': 'local_container_readonly', 'project': project,
        'capture_context': 'new_reproduction_not_historical_baseline' if project == REPLAY_PROJECT else 'current_state_snapshot',
        'collected_at': datetime.now(timezone.utc).isoformat(), 'nodes': nodes}
    validate(bundle)
    return bundle


def synthetic_bundle(stage):
    require(stage in {'before', 'after'}, 'synthetic_stage_invalid')
    good = stage == 'after'
    linux = normalize_linux({'version': '24.04', 'components': {'openssh-server': 'synthetic-9.6p1', 'rsyslog': 'synthetic-8'},
        'ssh': 'permitrootlogin ' + ('no' if good else 'yes') + '\npasswordauthentication ' + ('no' if good else 'yes'), 'ssh_error': False,
        'files': [{'path': p, 'mode': (0o640 if p == '/etc/shadow' else 0o600) if good else 0o666, 'uid': 0, 'regular': True, 'symlink': False, 'group_approved': True} for p in ('/etc/shadow', '/etc/ssh/sshd_config')],
        'files_error': False, 'demo_listener': not good, 'logging': {'daemon_running': True, 'auth_route_enabled': good, 'startup_config_matches': True}, 'logging_error': False})
    mysql = normalize_mysql('8.4.13\t' + ('0\t1' if good else '1\t0') + '\t1\t0\n', '0\t0\t1\t0\t0\t0' if good else '1\t1\t1\t0\t0\t0',
        'GRANT USAGE ON *.* TO `lab_app`@`localhost`\nGRANT SELECT ON `lab_data`.`items` TO `lab_app`@`localhost`' if good else 'GRANT ALL PRIVILEGES ON *.* TO `lab_app`@`localhost`')
    return {'schema_version': 1, 'rule_version': RULE_VERSION, 'origin': 'synthetic',
        'collected_at': '2026-01-01T00:01:00Z' if good else '2026-01-01T00:00:00Z', 'nodes': {'linux': linux, 'mysql': mysql}}
