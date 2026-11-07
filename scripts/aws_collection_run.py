"""Explicit acquisition workflow; not imported on the offline CLI path."""
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
from uuid import uuid4

from cloud_security.aws_scope import AwsOfflineError, AwsScope, read_json, require


def _directory(root):
    drive,_=ntpath.splitdrive(str(root))
    require(not drive.startswith('\\\\') and not str(root).startswith(('\\\\','//')),'network_output_path_rejected')
    base=Path(root).absolute()
    require(not {'.aws','.git'} & {p.lower() for p in base.parts},'output_path_rejected')
    for parent in [*base.parents,base]:
        if parent.exists():require(not parent.is_symlink() and not getattr(parent.lstat(),'st_file_attributes',0)&0x400,'output_link_rejected')
    base.mkdir(parents=True,exist_ok=True)
    target=base/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex)
    target.mkdir(exist_ok=False)
    return target


def _save(path,data):
    raw=(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('utf-8')
    with path.open('xb') as stream:stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def run_collection(args):
    # Import here only: ordinary offline runs never construct a live dependency.
    from cloud_security.aws_live import Limits, collect, live_factory, mock_factory, validate_targets
    from config_audit.collectors.aws_security import build_report
    require(not args.dry_run,'live_or_mock_collection_not_dry_run')
    require(not any((args.input_json,args.output,args.pdf,args.baseline_json,args.expected_sha256)),'collection_output_options_conflict')
    require(args.scope_json and args.targets_json and args.expected_account_id and args.allowed_region and args.output_root,'collection_explicit_scope_required')
    scope_data,scope_raw=read_json(args.scope_json);scope=AwsScope.from_dict(scope_data)
    plan,_=read_json(args.targets_json)
    validate_targets(scope,plan,args.expected_account_id,args.allowed_region)
    limits=Limits(args.max_calls,args.max_pages,args.max_retries,args.connect_timeout,args.read_timeout,args.max_seconds);limits.validate()
    require(bool(args.mock_json)==bool(args.mock_collect),'mock_script_option_required_or_conflicting')
    script=read_json(args.mock_json)[0] if args.mock_collect else None
    # Preflight is complete before the session/client factory or any AWS call.
    target=_directory(args.output_root)
    mode='MOCK_COLLECTION' if args.mock_collect else 'LIVE_READ_ONLY'
    try:
        factory=mock_factory(script) if args.mock_collect else live_factory(scope,limits)
        document,audit=collect(scope,plan,expected_account=args.expected_account_id,allowed_regions=args.allowed_region,
            factory=factory,limits=limits,origin='synthetic' if args.mock_collect else 'aws_collected_snapshot')
        audit['acquisition_mode']=mode
        collection_hash=_save(target/'collection.json',audit)
        snapshot_hash=_save(target/'snapshot.json',document)
        report=build_report(document,scope,source_reference=str(target/'snapshot.json'),source_sha256=snapshot_hash,
            scope_sha256=hashlib.sha256(scope_raw).hexdigest())
        report['collection']={'mode':mode,'account_match':audit['account_match'],'reference':str(target/'collection.json'),
            'sha256':collection_hash,'call_count':audit['call_count'],'network_access_enabled':not args.mock_collect}
        if not args.mock_collect:
            report['limitations']=[l for l in report['limitations'] if l!='no_AWS_API_or_SDK_client_created']
            report['limitations'] += ['evaluation_offline_after_explicit_readonly_AWS_acquisition','AWS_responses_are_not_atomic_across_multiple_APIs']
            report['origin_basis']='runtime_STS_account_match_not_independent_source_attestation'
        _save(target/'report.json',report)
        from config_audit.aws_report import write_pdf
        with (target/'report.pdf').open('xb') as stream:write_pdf(report,stream)
        artifacts=[]
        for name in ('collection.json','snapshot.json','report.json','report.pdf'):
            raw=(target/name).read_bytes();artifacts.append({'file':name,'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)})
        _save(target/'manifest.json',{'schema_version':1,'mode':mode,'completed_at':datetime.now(timezone.utc).isoformat(),
            'artifacts':artifacts,'independently_verified':False,'AWS_changes_performed':False})
        return {'mode':mode,'run_directory':str(target),'summary':report['summary'],'account_match':True,
                'call_count':audit['call_count'],'network_access_enabled':not args.mock_collect,'AWS_changes_performed':False}
    except Exception as error:
        audit=getattr(error,'collection_audit',None)
        if audit is not None:
            audit['acquisition_mode']=mode
            if not (target/'collection.json').exists():_save(target/'collection.json',audit)
        code=str(error) if isinstance(error,AwsOfflineError) else 'collection_or_report_failed'
        _save(target/'failure.json',{'status':'ERROR','error_code':code,'acquisition_mode':mode,
            'snapshot_saved':(target/'snapshot.json').is_file(),'report_saved':(target/'report.json').is_file()})
        failure=AwsOfflineError(code);failure.run_directory=str(target);failure.json_saved=(target/'report.json').exists()
        raise failure from None
