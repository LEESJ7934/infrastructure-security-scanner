"""Offline by default; acquisition requires explicit live/mock collection flags."""
import argparse
import json
from pathlib import Path

from cloud_security.aws_scope import AwsOfflineError, read_json
from config_audit.collectors.aws_security import load_report, compare_reports


def main(argv=None):
    parser = argparse.ArgumentParser(description='AWS security audit: offline by default; explicit read-only acquisition')
    source=parser.add_mutually_exclusive_group()
    source.add_argument('--validate-inputs',action='store_true',help='Validate scope/targets only; no SDK or network')
    source.add_argument('--input-json')
    source.add_argument('--live-collect',action='store_true',help='Explicit AWS read-only collection; requires expected account, regions and target scope')
    source.add_argument('--mock-collect',action='store_true',help='Same collector using a local scripted fake SDK, without network')
    parser.add_argument('--scope-json')
    parser.add_argument('--expected-sha256', help='Optional independently supplied declaration; never auto-populated from current bytes')
    parser.add_argument('--baseline-json', help='Saved evaluated report; compare without modifying the baseline')
    parser.add_argument('--output')
    parser.add_argument('--pdf')
    parser.add_argument('--dry-run', action='store_true', help='Offline evaluation only; output file options are forbidden')
    parser.add_argument('--targets-json')
    parser.add_argument('--expected-account-id')
    parser.add_argument('--allowed-region',action='append')
    parser.add_argument('--output-root')
    parser.add_argument('--mock-json')
    parser.add_argument('--max-calls',type=int,default=100)
    parser.add_argument('--max-pages',type=int,default=10)
    parser.add_argument('--max-retries',type=int,default=1)
    parser.add_argument('--connect-timeout',type=int,default=3)
    parser.add_argument('--read-timeout',type=int,default=8)
    parser.add_argument('--max-seconds',type=int,default=120)
    args = parser.parse_args(argv)
    saved = False
    try:
        if args.validate_inputs:
            from cloud_security.aws_scope import AwsScope, require
            from cloud_security.aws_live import validate_targets
            require(args.scope_json and args.targets_json and args.expected_account_id and args.allowed_region, 'validation_explicit_scope_required')
            require(not any((args.output,args.pdf,args.output_root,args.mock_json,args.baseline_json,args.expected_sha256)), 'validation_output_options_conflict')
            scope=AwsScope.from_dict(read_json(args.scope_json)[0]);plan=read_json(args.targets_json)[0]
            validate_targets(scope,plan,args.expected_account_id,args.allowed_region)
            print(json.dumps({'status':'VALID','network_access':False,'scope_schema_version':scope.schema_version,
                'targets':len(plan['targets']),'policy':scope.policy},ensure_ascii=False));return 0
        if args.live_collect or args.mock_collect:

            from scripts.aws_collection_run import run_collection
            print(json.dumps(run_collection(args),ensure_ascii=False));return 0
        if any((args.targets_json,args.expected_account_id,args.allowed_region,args.output_root,args.mock_json)):
            raise AwsOfflineError('collection_flag_required')
        if not args.input_json and not args.scope_json and not any((args.output,args.pdf,args.baseline_json,args.expected_sha256)):
            print(json.dumps({'mode':'OFFLINE_ONLY','status':'NOT_TESTED','network_access':False,'required_options':['--input-json','--scope-json']}));return 0
        if not args.input_json or not args.scope_json: raise AwsOfflineError('input_and_scope_required')
        if args.dry_run and (args.output or args.pdf): raise AwsOfflineError('dry_run_forbids_file_outputs')
        for path in (args.output,args.pdf):
            if path and (Path(path).exists() or Path(path).is_symlink()): raise AwsOfflineError('new_output_path_required')
            if path and not Path(path).parent.is_dir(): raise AwsOfflineError('output_parent_missing')
        if args.output and args.pdf and Path(args.output).resolve()==Path(args.pdf).resolve(): raise AwsOfflineError('distinct_outputs_required')
        report = load_report(args.input_json,args.scope_json,expected_sha256=args.expected_sha256)
        if args.baseline_json:
            baseline,_ = read_json(args.baseline_json)
            report['comparison'] = compare_reports(baseline,report)
        if args.output:
            with Path(args.output).open('x',encoding='utf-8') as stream:json.dump(report,stream,ensure_ascii=False,indent=2,allow_nan=False)
            saved=True
        if args.pdf:
            from config_audit.aws_report import write_pdf
            with Path(args.pdf).open('xb') as stream:write_pdf(report,stream)
        print(json.dumps({'mode':report['mode'],'origin':report['origin'],'summary':report['summary'],'network_access':False,
            'json_saved':saved,'integrity':report['evidence']['hash_comparison'],'comparison_summary':report.get('comparison',{}).get('summary')},ensure_ascii=False))
        return 0
    except AwsOfflineError as error:
        message={'status':'ERROR','error_code':str(error),'json_saved':getattr(error,'json_saved',saved)}
        if hasattr(error,'run_directory'):message['run_directory']=error.run_directory
        print(json.dumps(message));return 2
    except (OSError,ValueError,TypeError,KeyError,ImportError):
        print(json.dumps({'status':'ERROR','error_code':'offline_aws_audit_failed','json_saved':saved}));return 2


if __name__=='__main__':raise SystemExit(main())
