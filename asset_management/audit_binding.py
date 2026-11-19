"""Explicit offline crosswalk from domain asset IDs to inventory UUIDs.

Never infer identity from an IP or fabricate database verification. The original
domain identifier, collection time and run remain intact. Binding is metadata,
not reclassification of an observation as a new live measurement.
"""
from copy import deepcopy
from uuid import UUID
from db.scan_history import namespace_for


def bind_audit_results(report, manifest):
    if not isinstance(report, dict) or not isinstance(report.get('results'), list):
        raise ValueError('audit_report_results_required')
    if not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'asset_namespace', 'bindings'} or manifest['schema_version'] != 1:
        raise ValueError('audit_asset_bindings_invalid')
    namespace = namespace_for(manifest)
    entries = manifest['bindings']
    if not isinstance(entries, dict) or not entries or len(entries) > 10000:
        raise ValueError('explicit_asset_bindings_required')
    mapping = {}
    for source_id, asset_uid in entries.items():
        if not isinstance(source_id, str) or not source_id or len(source_id) > 255:
            raise ValueError('domain_asset_identifier_invalid')
        try:
            mapping[source_id] = str(UUID(asset_uid))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError('inventory_uuid_required_not_ip') from error
    result = deepcopy(report)
    for row in result['results']:
        if not isinstance(row, dict) or row.get('asset_id') not in mapping:
            raise ValueError('audit_asset_missing_explicit_binding')
        row.update(source_asset_id=row['asset_id'], asset_uid=mapping[row['asset_id']],
                   asset_namespace=namespace, asset_binding_verification='DECLARED_NOT_DB_VERIFIED')
    result['asset_binding'] = {'asset_namespace': namespace, 'basis': 'EXPLICIT_OPERATOR_CROSSWALK',
                              'verification': 'NOT_INDEPENDENTLY_VERIFIED', 'source_identifiers_preserved': True}
    return result
