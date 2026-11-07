"""Initialize only the disposable Linux LAB container, not the host."""
import hashlib
import json
from pathlib import Path
import shutil
import signal
import subprocess
import time


def main():
    stage = Path('/opt/lab/stage').read_text().strip()
    if stage not in {'before', 'after'}:
        raise SystemExit('Invalid LAB stage')
    Path('/run/lab').mkdir(parents=True, exist_ok=True)
    Path('/run/sshd').mkdir(exist_ok=True)
    Path('/var/spool/rsyslog').mkdir(exist_ok=True)
    hashes = {}
    for name, target in [('sshd_config', '/etc/ssh/sshd_config'), ('rsyslog.conf', '/etc/rsyslog.conf')]:
        shutil.copyfile('/opt/lab/' + stage + '/' + name, target)
        hashes[name] = hashlib.sha256(Path(target).read_bytes()).hexdigest()
    Path('/run/lab/startup-hashes.json').write_text(json.dumps(hashes))
    Path('/etc/shadow').chmod(0o666 if stage == 'before' else 0o640)
    Path('/etc/ssh/sshd_config').chmod(0o666 if stage == 'before' else 0o600)
    subprocess.run(['ssh-keygen', '-A'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['/usr/sbin/sshd', '-t'], check=True)
    subprocess.run(['/usr/sbin/rsyslogd', '-N1', '-f', '/etc/rsyslog.conf'], check=True)
    children = []
    for name, command in [('sshd', ['/usr/sbin/sshd', '-D', '-e']),
                          ('rsyslogd', ['/usr/sbin/rsyslogd', '-n', '-f', '/etc/rsyslog.conf'])]:
        process = subprocess.Popen(command)
        Path('/run/lab/' + name + '.pid').write_text(str(process.pid))
        children.append(process)
    if stage == 'before':
        public = Path('/opt/lab/public'); public.mkdir(exist_ok=True)
        (public / 'lab.txt').write_text('Non-sensitive LAB fixture')
        children.append(subprocess.Popen(['python3', '-m', 'http.server', '9000', '--bind', '0.0.0.0', '--directory', str(public)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    # Avoid reporting healthy during a short-lived daemon startup failure.
    time.sleep(.5)
    if any(p.poll() is not None for p in children):
        for p in children:
            if p.poll() is None: p.terminate()
        raise SystemExit('A required LAB process failed during startup')
    Path('/run/lab/ready').touch()
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping:
            if any(p.poll() is not None for p in children):
                raise SystemExit('A required LAB process exited')
            time.sleep(.25)
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()


if __name__ == '__main__': main()
