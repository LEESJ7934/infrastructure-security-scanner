"""Offline guard/export only; no subprocess, SDK or network execution."""
import argparse
import hashlib
import json
from pathlib import Path
from cloud_security.aws_scope import AwsOfflineError, AwsScope, read_json, require
from cloud_security.aws_lab import check_plan, export_scope, save_export

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['check-plan','export-scope'])
    for name in ['expected-account-id','lab-name','owner','protected-scope-json']:parser.add_argument('--'+name,required=True)
    parser.add_argument('--baseline-state-json');parser.add_argument('--plan-json');parser.add_argument('--phase',choices=['before','after','destroy']);parser.add_argument('--initial',action='store_true')
    parser.add_argument('--outputs-json');parser.add_argument('--state-json');parser.add_argument('--output-root');parser.add_argument('--baseline-scope-json')
    args=parser.parse_args(argv)
    try:
        base,raw=read_json(args.protected_scope_json);scope=AwsScope.from_dict(base)
        if args.action=='check-plan':
            require(args.plan_json and args.phase and not any((args.outputs_json,args.state_json,args.output_root,args.baseline_scope_json)),'lab_guard_options_invalid')
            result=check_plan(read_json(args.plan_json)[0],account=args.expected_account_id,name=args.lab_name,owner=args.owner,phase=args.phase,protected_scope=scope,initial=args.initial,baseline_state=read_json(args.baseline_state_json)[0] if args.baseline_state_json else None)
        else:
            require(args.outputs_json and args.state_json and args.output_root and not any((args.plan_json,args.phase,args.initial,args.baseline_state_json)),'lab_export_options_invalid')
            reports=(Path(__file__).resolve().parents[1]/'reports').resolve()
            destination=Path(args.output_root).resolve()
            require(destination==reports or reports in destination.parents,'lab_export_reports_directory_required')
            outputs,o_raw=read_json(args.outputs_json);state,s_raw=read_json(args.state_json)
            lab_scope,targets=export_scope(outputs,state,base,account=args.expected_account_id,name=args.lab_name,owner=args.owner)
            if args.baseline_scope_json:require(lab_scope==read_json(args.baseline_scope_json)[0],'lab_scope_changed_between_phases')
            directory=save_export(args.output_root,lab_scope,targets,{'outputs_sha256':hashlib.sha256(o_raw).hexdigest(),'state_sha256':hashlib.sha256(s_raw).hexdigest(),'base_scope_sha256':hashlib.sha256(raw).hexdigest()})
            result={'status':'VALID','directory':directory,'network_access':False,'scope_compares_equal_to_baseline':bool(args.baseline_scope_json)}
        print(json.dumps(result));return 0
    except AwsOfflineError as error:print(json.dumps({'status':'ERROR','error_code':str(error)}));return 2
    except (OSError,ValueError,TypeError,KeyError,AttributeError):print(json.dumps({'status':'ERROR','error_code':'lab_input_invalid'}));return 2

if __name__=='__main__':raise SystemExit(main())
