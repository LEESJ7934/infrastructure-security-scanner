"""Read two selected checks from the existing, strictly scoped Docker replay.

U-01 full-context inference is allowed only for the exact simple LAB SSH config
with no Include or Match directives. Any other template needs manual review.
No configuration/lifecycle changes; use existing replay workflow for hardening.
"""
import argparse
import json
from pathlib import Path
from config_audit.collectors.linux_mysql_lab import REPLAY_PROJECT, docker_scope, run
from config_audit.kisa_2026 import PROFILE, assess
from config_audit.reporting import unique_object

QUERY = r'''
import json, pathlib, subprocess, hashlib
p = pathlib.Path('/etc/ssh/sshd_config')
raw = p.read_bytes()
lines = [s.strip().lower().split() for s in raw.decode().splitlines() if s.strip() and not s.lstrip().startswith('#')]
simple = not any(s[0] in ('include', 'match') for s in lines)
expected = pathlib.Path('/opt/lab/after/sshd_config').read_bytes()
before = pathlib.Path('/opt/lab/before/sshd_config').read_bytes()
inventory = raw in (expected, before) and simple
ports = []
for name in ('tcp', 'tcp6'):
    f = pathlib.Path('/proc/net') / name
    if not f.exists() and name == 'tcp6': continue
    for line in f.read_text().splitlines()[1:]:
        fields = line.split()
        if fields[3] == '0A' and not fields[1].startswith('0B00007F:'):
            ports.append(int(fields[1].split(':')[-1], 16))
r = subprocess.run(['/usr/sbin/sshd', '-T', '-C', 'user=root,host=lab,addr=127.0.0.1'],capture_output=True,text=True,check=True)
root = [s.split()[1] for s in r.stdout.splitlines() if s.startswith('permitrootlogin ')]
print(json.dumps({'ssh_root_denied_all_contexts': root == ['no'] if inventory else None,
 'other_remote_terminals_root_denied_or_absent': not any(p not in (22,9000) for p in ports) if inventory else None,
 'terminal_inventory_complete': inventory, 'listening_tcp_ports': ports,
 'sshd_config_sha256': hashlib.sha256(raw).hexdigest()}))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        raise ValueError('output_already_exists')
    report = json.loads(args.report.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    if report.get('origin') != 'local_container_readonly' or report.get('bundle', {}).get('project') != REPLAY_PROJECT:
        raise ValueError('fresh_replay_report_required')
    command, containers = docker_scope(REPLAY_PROJECT)
    raw = json.loads(run(command + ['exec', containers['linux']['Id'], 'python3', '-c', QUERY]))
    # Existing collector verifies running daemon and startup hash match.
    ssh = next(r for r in report['results'] if r['check_id'] == 'LINUX-LAB-001')
    shadow = next(r for r in report['results'] if r['check_id'] == 'LINUX-LAB-003')
    values = {'U-01': raw, 'U-18': next(v for v in (shadow.get('observed_value') or []) if v['path'] == '/etc/shadow')}
    observations = [dict(kisa_id=id, asset_id='linux', source_kind='SAVED_LAB',
        collection_status='ERROR' if ssh['status'] == 'ERROR' else 'COLLECTED',
        product_version=shadow.get('version'), collected_at=shadow.get('collected_at'),
        evidence_reference=args.report.name, value=value) for id, value in values.items()]
    packet = {'profile': PROFILE, 'observations': observations}
    output = {'packet': packet, 'assessment': assess(packet),
              'limitations': ['U-01 inventory confined to exact disposable LAB template and its network namespace.',
                              'No remote login success or host-wide assessment is claimed.']}
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=True, indent=2)


if __name__ == '__main__':
    main()
