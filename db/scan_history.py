"""V8 immutable observations. No migrations or synthetic backfills run at import/runtime.

Legacy installations retain their API with explicitly limited storage capability.
Only a selected V8 database enables namespaces, complete state history and replay.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re

STATES = {'open', 'closed', 'filtered', 'open|filtered', 'unknown', 'error', 'not_tested'}


class ScanImportConflict(ValueError):
    """An execution UID already identifies different immutable bytes."""


def supports_history(conn):
    cached = getattr(conn, '_scanner_history_v8', None)
    if type(cached) is bool:
        return cached
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT COUNT(*) AS table_count FROM information_schema.tables "
                           "WHERE table_schema = DATABASE() AND table_name IN "
                           "('scan_run_snapshots','scan_port_observations','finding_observation_links')")
            row = cursor.fetchone()
        supported = isinstance(row, dict) and row.get('table_count') == 3
    except (AttributeError, AssertionError):
        # Existing injected DB-API fixtures implement only their V6/V7 SELECTs.
        supported = False
    try:
        setattr(conn, '_scanner_history_v8', supported)
    except AttributeError:
        pass
    return supported


def namespace_for(document):
    value = document.get('asset_namespace', 'legacy')
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,189}', value):
        raise ValueError('Invalid explicit asset namespace')
    return value


def db_timestamp(value, *, declared_basis=None):
    """UTC-naive at the MySQL DATETIME boundary; never guess old naïve timezone."""
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(parsed, datetime):
        raise ValueError('Expected ISO datetime')
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    if declared_basis == 'UTC':
        raise ValueError('UTC scan timestamps must carry an offset')
    return parsed


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def safe_document(document):
    """Defence in depth for imported JSON, not only scanner-produced observations."""
    result = deepcopy(document)
    # Explicit sensitive keys are excluded recursively; HTTP headers are redacted
    # even when an old export packed them into a banner string.
    def clean(value):
        if isinstance(value, dict):
            return {k: '[REDACTED]' if str(k).casefold().replace('_', '-') in
                    {'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'password', 'token', 'secret'}
                    else clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            return re.sub(r'(?im)^(?:set-cookie|authorization|proxy-authorization|cookie):[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*',
                          '[REDACTED HTTP HEADER]', value)
        return value
    result = clean(result)
    result.pop('storage', None)
    return result


def execution_digest(document):
    return hashlib.sha256(canonical(safe_document(document)).encode()).hexdigest()


def identity_digest(row):
    value = {k: row.get(k) for k in ('port', 'protocol', 'state', 'service', 'product', 'version')}
    banner = safe_document(row).get('banner')
    if isinstance(banner, str):
        banner = re.sub(r'(?im)^(?:date|expires|last-modified|x-request-id):[^\r\n]*(?:\r?\n)?', '', banner)
    value['stable_banner'] = banner
    fp = row.get('fingerprint')
    value['fingerprint'] = {k: fp.get(k) for k in ('parser_version', 'source', 'evidence', 'tls')} if isinstance(fp, dict) else None
    value['package_evidence'] = row.get('package_evidence')
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def retained_port_id(conn, host_id, row, document):
    """Do not turn importing an older UTC run into a new current observation."""
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute('SELECT p.id,o.observed_at,r.time_basis FROM ports p '
            'LEFT JOIN scan_port_observations o ON o.port_id=p.id AND o.scan_id=p.last_scan_id '
            'LEFT JOIN scan_run_snapshots r ON r.scan_id=o.scan_id '
            'WHERE p.host_id=%s AND p.port=%s AND p.protocol=%s LIMIT 1 FOR UPDATE',
            (host_id, row['port'], row['protocol']))
        prior = cursor.fetchone()
    if not prior:
        return None
    if row['state'] == 'not_tested':
        return prior['id']
    if document.get('time_basis') == 'UTC' and prior.get('time_basis') == 'UTC' and prior.get('observed_at'):
        measured = db_timestamp(row.get('observed_at', document['finished_at']), declared_basis='UTC')
        if measured < prior['observed_at']:
            return prior['id']
    elif document.get('time_basis') != 'UTC' and prior.get('time_basis') == 'UTC':
        # Unknown old wall clocks cannot replace an explicitly timed current run.
        return prior['id']
    return None


def retained_asset_scan_id(conn, namespace, host_ip, document, proposed_id):
    """Import ordering must not rewind an asset's last measured execution."""
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute('SELECT h.last_scan_id,s.finished_at,r.time_basis FROM hosts h '
                       'LEFT JOIN scans s ON s.id=h.last_scan_id '
                       'LEFT JOIN scan_run_snapshots r ON r.scan_id=s.id '
                       'WHERE h.asset_namespace=%s AND h.host_ip=%s FOR UPDATE', (namespace, host_ip))
        previous = cursor.fetchone()
    if previous and previous.get('last_scan_id') and previous.get('time_basis') == 'UTC':
        if document.get('time_basis') != 'UTC' or db_timestamp(document['finished_at'], declared_basis='UTC') < previous['finished_at']:
            return previous['last_scan_id']
    return proposed_id


def existing_execution(conn, scan_uid, digest):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute('SELECT s.id AS scan_id, r.execution_sha256 FROM scans s '
                       'JOIN scan_run_snapshots r ON r.scan_id=s.id WHERE s.scan_uid=%s FOR UPDATE', (scan_uid,))
        row = cursor.fetchone()
    if row:
        if row['execution_sha256'] != digest:
            raise ScanImportConflict('Execution UID already has different immutable observations')
        return row['scan_id']
    return None


def save_snapshot(conn, scan_id, document):
    safe = safe_document(document)
    digest = execution_digest(safe)
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute('SELECT execution_sha256 FROM scan_run_snapshots WHERE scan_id=%s FOR UPDATE', (scan_id,))
        old = cursor.fetchone()
        if old:
            if old['execution_sha256'] != digest:
                raise ScanImportConflict('Execution UID already has different immutable observations')
            return False
        cursor.execute('INSERT INTO scan_run_snapshots '
                       '(scan_id,execution_sha256,time_basis,asset_namespace,requested_port_range,snapshot_json,imported_at) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                       (scan_id, digest, 'UTC' if safe.get('time_basis') == 'UTC' else 'LEGACY_UNSPECIFIED',
                        namespace_for(safe), safe.get('requested_port_range', safe.get('port_range', '')),
                        canonical(safe), datetime.now(timezone.utc).replace(tzinfo=None)))
    return True


def save_observation(conn, scan_id, host_id, port_id, row, document):
    value = safe_document(row)
    state = value['state'].replace('open_or_filtered', 'open|filtered')
    if state not in STATES:
        raise ValueError('Invalid observation state')
    # NOT_TESTED has no observation timestamp: attempt completion time is not proof
    # that this endpoint was inspected.
    at = None if state == 'not_tested' else db_timestamp(
        value.get('observed_at', document['finished_at']), declared_basis=document.get('time_basis'))
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO scan_port_observations '
            '(scan_id,host_id,port_id,port,protocol,state,reason,error_code,service,product,version,banner,fingerprint,observed_at,observation_json,identity_sha256) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (scan_id, host_id, port_id, value['port'], value['protocol'], state,
             value.get('reason'), value.get('error_code'), value.get('service'), value.get('product'),
             value.get('version'), value.get('banner'), canonical(value.get('fingerprint')),
             at, canonical(value), identity_digest(value)))
        return cursor.lastrowid


def link_finding(conn, vuln_id, observation_id=None, *, port_id=None, relation='CANDIDATE'):
    if relation not in {'CANDIDATE', 'VERIFIED'}:
        raise ValueError('Invalid observation relation')
    if not supports_history(conn):
        return
    if observation_id is None and port_id is not None:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute('SELECT o.id FROM scan_port_observations o JOIN ports p ON p.id=o.port_id '
                           'WHERE p.id=%s AND o.scan_id=p.last_scan_id AND o.state=\'open\' '
                           'ORDER BY o.id DESC LIMIT 1', (port_id,))
            row = cursor.fetchone()
        observation_id = row['id'] if row else None
    if observation_id is not None:
        with conn.cursor() as cursor:
            cursor.execute('INSERT IGNORE INTO finding_observation_links '
                           '(vuln_id,observation_id,relation,linked_at) VALUES (%s,%s,%s,%s)',
                           (vuln_id, observation_id, relation, datetime.now(timezone.utc).replace(tzinfo=None)))


def get_observations(conn, *, scan_id=None, asset_uid=None, current=False):
    """Historical scans or latest ATTEMPT per endpoint, retaining previous scopes.

    not_tested rows do not overwrite a prior observation in the current view.
    error/unknown rows do: a failed reinspection is visible and cannot look safe.
    """
    if not supports_history(conn):
        raise RuntimeError('V8 migration required for immutable history queries')
    params = []
    sql = ('SELECT o.id AS observation_id,o.port_id,o.host_id,h.asset_uid,h.host_ip,h.asset_namespace,'
           'o.scan_id,o.port,o.protocol,o.state,o.service,o.product,o.version,o.banner,o.fingerprint,'
           'o.reason,o.error_code,o.observed_at,o.identity_sha256,o.observation_json,r.time_basis AS observation_time_basis '
           'FROM scan_port_observations o JOIN hosts h ON h.id=o.host_id '
           'JOIN scan_run_snapshots r ON r.scan_id=o.scan_id WHERE 1=1')
    if scan_id is not None:
        sql += ' AND o.scan_id=%s'; params.append(scan_id)
    if asset_uid is not None:
        sql += ' AND h.asset_uid=%s'; params.append(asset_uid)
    if current:
        sql += (" AND o.state<>'not_tested' AND NOT EXISTS (SELECT 1 FROM scan_port_observations n "
                "JOIN scan_run_snapshots nr ON nr.scan_id=n.scan_id "
                "WHERE n.host_id=o.host_id AND n.port=o.port AND n.protocol=o.protocol "
                "AND n.state<>'not_tested' AND ((nr.time_basis='UTC' AND r.time_basis<>'UTC') OR "
                "(nr.time_basis=r.time_basis AND (n.observed_at>o.observed_at OR "
                "(n.observed_at=o.observed_at AND n.id>o.id)))))")
    sql += ' ORDER BY o.host_id,o.port,o.protocol,o.id'
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(sql, tuple(params))
        return cursor.fetchall()


def read_snapshot(conn, scan_id):
    if not supports_history(conn):
        raise RuntimeError('V8 migration required for immutable history queries')
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute('SELECT snapshot_json,execution_sha256,time_basis,asset_namespace '
                       'FROM scan_run_snapshots WHERE scan_id=%s', (scan_id,))
        row = cursor.fetchone()
    if not row:
        return None
    return {**row, 'snapshot_json': json.loads(row['snapshot_json'])
            if isinstance(row['snapshot_json'], str) else row['snapshot_json']}
