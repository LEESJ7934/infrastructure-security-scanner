from datetime import datetime

from db.asset_repository import (
    record_scan_asset,
    upsert_scan_scope,
)
from db.db_client import get_connection
from db.cloud_repository import find_cloud_host_by_ip
from db.query_helpers import (
    insert_scan,
    upsert_host,
    upsert_port,
)
from db.statuses import ScanStatus
from scanner.utils import format_port_range, resolve_hostname
from db.scan_history import (db_timestamp, execution_digest, existing_execution, namespace_for, retained_port_id, retained_asset_scan_id,
                             safe_document, save_observation, save_snapshot, supports_history)


def determine_scan_status(
    targets: list[dict],
) -> str:
    def failed(target):
        return bool(target.get('error')) or any(r.get('state') in {'error', 'unknown', 'not_tested'}
                                               or r.get('error_code') for r in target.get('results', []))
    failed_count = sum(failed(target) for target in targets)

    if failed_count == 0:
        return ScanStatus.COMPLETED.value

    if failed_count == len(targets) and not any(
        not target.get('error') and any(r.get('state') in {'open', 'closed', 'filtered', 'open|filtered'}
                                       and not r.get('error_code') for r in target.get('results', []))
        for target in targets):
        return ScanStatus.FAILED.value

    return ScanStatus.PARTIAL.value


def save_scan_results(
    scan_result: dict,
) -> int:
    scan_uid = scan_result["scan_id"]
    targets = scan_result["targets"]
    requested_targets = scan_result.get(
        "requested_targets"
    ) or [
        str(
            target.get(
                "input_target",
                target.get("ip", "unknown"),
            )
        )
        for target in targets
    ]

    target_text = ",".join(
        requested_targets
    )

    started_at = db_timestamp(scan_result['started_at'], declared_basis=scan_result.get('time_basis'))
    finished_at = db_timestamp(scan_result['finished_at'], declared_basis=scan_result.get('time_basis'))

    scan_status = determine_scan_status(
        targets
    )

    conn = get_connection()

    try:
        history_enabled = supports_history(conn)
        namespace = namespace_for(scan_result)
        if namespace != 'legacy' and not history_enabled:
            raise RuntimeError('V8 migration required for isolated asset namespaces')
        scan_result['storage'] = {'history_capability': 'IMMUTABLE_V8' if history_enabled else 'LEGACY_CURRENT_STATE_ONLY',
                                 'legacy_time_basis': 'UTC' if scan_result.get('time_basis') == 'UTC' else 'UNSPECIFIED'}
        if history_enabled:
            previous_id = existing_execution(conn, scan_uid, execution_digest(scan_result))
            if previous_id is not None:
                conn.rollback()  # Read/lock only: identical import never updates last_seen.
                return previous_id
        scope_data = scan_result.get("scope")
        scope_id = (
            upsert_scan_scope(conn, scope_data)
            if scope_data
            else None
        )

        scan_db_id = insert_scan(
            conn=conn,
            scan_uid=scan_uid,
            target=target_text,
            scan_type=scan_result.get(
                "scan_type",
                "tcp",
            ),
            port_range=format_port_range(
                scan_result.get(
                    "port_range",
                    "1-1024",
                )
            ),
            started_at=started_at,
            finished_at=finished_at,
            status=scan_status,
            scope_id=scope_id,
            requested_targets=requested_targets,
            config_snapshot=scan_result.get(
                "config"
            ),
        )

        if history_enabled and not save_snapshot(conn, scan_db_id, scan_result):
            conn.rollback()
            return scan_db_id

        for target in targets:
            if target.get("error"):
                continue

            host_ip = target["ip"]
            host_name = (
                target.get("input_target")
                if target.get("resolution_type")
                == "HOSTNAME"
                else resolve_hostname(host_ip)
            )

            # AWS inventory stores the canonical EC2 host on its private IP,
            # while an authorized external scan commonly targets the public IP.
            # Reuse the canonical cloud host instead of creating a duplicate
            # public-IP host row. Non-cloud targets keep the original behavior.
            # Explicit namespaces never merge with an arbitrary same-IP cloud
            # resource from a different customer/VPC.
            cloud_host = find_cloud_host_by_ip(conn, host_ip) if namespace == 'legacy' else None
            canonical_host_ip = (
                cloud_host.get("private_ip")
                if cloud_host and cloud_host.get("private_ip")
                else host_ip
            )

            host_kwargs = dict(
                conn=conn,
                host_ip=canonical_host_ip,
                host_name=host_name,
                last_scan_id=scan_db_id,
            )
            if history_enabled:
                host_kwargs['last_scan_id'] = retained_asset_scan_id(conn, namespace, canonical_host_ip, scan_result, scan_db_id)
                if host_kwargs['last_scan_id'] != scan_db_id:
                    host_kwargs['host_name'] = None
            if namespace != 'legacy':
                host_kwargs['asset_namespace'] = namespace
            host_id = upsert_host(**host_kwargs)

            target_results = target.get(
                "results",
                [],
            )

            for result in target_results:
                if not history_enabled and result.get("state") != "open":
                    continue
                safe_result = safe_document(result)
                retained = retained_port_id(conn, host_id, safe_result, scan_result) if history_enabled else None
                port_id = retained if retained is not None else upsert_port(
                    conn=conn,
                    host_id=host_id,
                    port=result["port"],
                    protocol=result["protocol"],
                    service=result.get(
                        "service"
                    ),
                    version=result.get(
                        "version"
                    ),
                    banner=safe_result.get(
                        "banner"
                    ),
                    last_scan_id=scan_db_id,
                    state=result["state"],
                    product=result.get("product"),
                    fingerprint=safe_result.get("fingerprint"),
                )
                if history_enabled:
                    save_observation(conn, scan_db_id, host_id, port_id, safe_result, scan_result)

            record_scan_asset(
                conn=conn,
                scan_id=scan_db_id,
                host_id=host_id,
                input_target=target.get(
                    "input_target",
                    host_ip,
                ),
                resolution_type=target.get(
                    "resolution_type",
                    "IP",
                ),
                result_status="SCANNED",
                open_port_count=sum(
                    1
                    for result in target_results
                    if result.get("state") == "open"
                ),
            )

        conn.commit()
        return scan_db_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
