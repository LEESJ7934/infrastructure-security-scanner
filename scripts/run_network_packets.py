"""Explicit packet probes only; no topology provisioning or firewall changes."""
import argparse
import json
import subprocess
from pathlib import Path
from config_audit.collectors.network_devices import NetworkInputError
from config_audit.network_packets import collect

def main(argv=None):
    parser=argparse.ArgumentParser(description='Scoped ICMP path diagnosis / verification')
    parser.add_argument('--profile',choices=('existing','fabric'),default='existing')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--config-evidence')
    parser.add_argument('--output')
    args=parser.parse_args(argv)
    try:
        if args.output and Path(args.output).exists():raise NetworkInputError('new_output_path_required')
        report=collect(args.profile,args.config_evidence) if args.execute else {'status':'NOT_TESTED','kind':'packet_verification','reason':'explicit_execute_required'}
        if args.output:
            with Path(args.output).open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
        print(json.dumps({'status':report['status'],'kind':'packet_verification','profile':args.profile,
                          'phases':[{'source':phase['source'],'destination':phase['destination'],'ping':phase['ping'],'path':phase['path']} for phase in report.get('phases',[])]}))
        return 0
    except (NetworkInputError,OSError,ValueError,KeyError,IndexError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'ERROR','kind':'packet_verification','error_code':str(error) if isinstance(error,NetworkInputError) else 'packet_probe_failed'}))
        return 2

if __name__=='__main__':raise SystemExit(main())
