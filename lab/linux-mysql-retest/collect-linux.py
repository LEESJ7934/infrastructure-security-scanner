"""Read-only, allowlisted metadata. Never read shadow or private-key contents."""
import hashlib
import grp
import json
from pathlib import Path
import stat
import subprocess
import sys


def running(name):
    try:
        pid = int(Path('/run/lab/' + name + '.pid').read_text())
        return Path('/proc/' + str(pid) + '/comm').read_text().strip() == name
    except (OSError, ValueError):
        return False


def collect():
    output = {'version': None, 'components': {}, 'ssh': None, 'ssh_error': False,
              'files': None, 'files_error': False, 'demo_listener': None,
              'logging': None, 'logging_error': False}
    try:
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if release.get('ID', '').strip('"') == 'ubuntu': output['version'] = release.get('VERSION_ID', '').strip('"')
        for package in ('openssh-server', 'rsyslog'):
            result = subprocess.run(['dpkg-query', '-W', '-f=${Version}', package], capture_output=True, text=True, timeout=5)
            if result.returncode == 0: output['components'][package] = result.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError): pass
    try:
        hashes = json.loads(Path('/run/lab/startup-hashes.json').read_text())
    except (OSError, ValueError): hashes = {}
    try:
        current = hashlib.sha256(Path('/etc/ssh/sshd_config').read_bytes()).hexdigest()
        result = subprocess.run(['/usr/sbin/sshd', '-T', '-C', 'user=root,host=lab,addr=127.0.0.1'], capture_output=True, text=True, timeout=5)
        if not running('sshd') or result.returncode != 0 or hashes.get('sshd_config') != current:
            raise ValueError()
        output['ssh'] = '\n'.join(line for line in result.stdout.splitlines() if line.split() and line.split()[0] in ('permitrootlogin', 'passwordauthentication'))
    except (OSError, ValueError, subprocess.SubprocessError): output['ssh_error'] = True
    try:
        output['files'] = []
        for name in ('/etc/shadow', '/etc/ssh/sshd_config'):
            metadata = Path(name).lstat()
            output['files'].append({'path': name, 'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid,
                'regular': stat.S_ISREG(metadata.st_mode), 'symlink': stat.S_ISLNK(metadata.st_mode),
                'group_approved': metadata.st_gid in ({0, grp.getgrnam('shadow').gr_gid} if name == '/etc/shadow' else {0})})
    except (OSError, KeyError): output['files'] = None; output['files_error'] = True
    try:
        listeners = []
        for name in ('tcp', 'tcp6'):
            p = Path('/proc/net') / name
            if not p.exists() and name == 'tcp6': continue
            for line in p.read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == '0A': listeners.append(int(fields[1].split(':')[-1], 16))
        output['demo_listener'] = 9000 in listeners
    except (OSError, ValueError, IndexError): pass
    try:
        raw = Path('/etc/rsyslog.conf').read_bytes()
        approved = Path('/opt/lab/after/rsyslog.conf').read_bytes()
        output['logging'] = {'daemon_running': running('rsyslogd'), 'auth_route_enabled': raw == approved,
            'startup_config_matches': hashes.get('rsyslog.conf') == hashlib.sha256(raw).hexdigest()}
    except OSError: output['logging_error'] = True
    return output


if __name__ == '__main__':
    if sys.argv[1:] == ['--health']:
        raise SystemExit(0 if Path('/run/lab/ready').exists() and running('sshd') and running('rsyslogd') else 1)
    print(json.dumps(collect()))
