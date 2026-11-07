"""Explicit isolated Docker IPS execution; offline by default."""
import argparse,json
from pathlib import Path
from config_audit.collectors.suricata_ips import EvidenceError,build_report,write_pdf

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);s=p.add_mutually_exclusive_group();s.add_argument('--execute',action='store_true');s.add_argument('--evidence-dir')
 p.add_argument('--output-root',default=str(Path(__file__).resolve().parents[1]/'reports/phase2-suricata-ips'));a=p.parse_args(argv)
 try:
  if a.execute:
   from config_audit.ips_execution import execute
   result=execute(a.output_root)
  elif a.evidence_dir:
   evidence=Path(a.evidence_dir).resolve();reports=(Path(__file__).resolve().parents[1]/'reports').resolve()
   if reports not in evidence.parents:raise EvidenceError('evidence_reports_only')
   r=build_report(evidence);result={'status':'PASS' if all(x['status']=='PASS' for x in r['results']) else 'NEEDS_REVIEW','phases':r['phases'],'independently_verified':False}
  else:result={'status':'NOT_TESTED','reason':'explicit_execute_required','network_access':False}
  print(json.dumps(result,ensure_ascii=False));return 0 if result['status'] in ('PASS','NOT_TESTED') else 2
 except (EvidenceError,OSError,ValueError,KeyError,TypeError,IndexError) as e:
  print(json.dumps({'status':'ERROR','error_code':str(e) if isinstance(e,EvidenceError) else 'IPS_evidence_failed'}));return 2

if __name__=='__main__':raise SystemExit(main())
