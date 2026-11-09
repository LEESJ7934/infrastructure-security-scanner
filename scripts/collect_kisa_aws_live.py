"""Read-only KISA AWS inventory of an explicitly scoped existing private LAB."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.kisa_aws_live import collect


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope-json',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    raw,packet,report,review=collect(args.scope_json)
    for name,data in [('aws-selected-raw.json',raw),('observations.json',packet),('assessment.json',report),('policy-review.json',review)]:
        with (args.output_dir/name).open('x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
    print(json.dumps({'account_match':raw['account_match'],'AWS_changes_performed':False,'summary':report['summary'],
                      'inventory_counts':{k:len(v) for k,v in raw['inventory'].items()},'findings':review['findings']}))


if __name__=='__main__': main()
