"""Collect selected MySQL checks using real SQL and two fixed isolated sources."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.kisa_mysql_live import collect_raw, normalize
from config_audit.kisa_2026 import assess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    raw=collect_raw()
    with (args.output_dir/'mysql-live-raw.json').open('x',encoding='utf-8') as f:
        json.dump(raw,f,ensure_ascii=False,indent=2)
    packet,analysis=normalize(raw);report=assess(packet)
    for name,data in [('observations.json',packet),('assessment.json',report),('role-analysis.json',analysis)]:
        with (args.output_dir/name).open('x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
    print(json.dumps(report['summary']))


if __name__=='__main__': main()
