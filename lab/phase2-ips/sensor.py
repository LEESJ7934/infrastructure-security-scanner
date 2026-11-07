"""Suricata control only inside the dedicated sensor container namespace."""
import json,os,signal,subprocess,sys,time
from pathlib import Path
PID=Path('/tmp/ips.pid')

def status():
 pid=int(PID.read_text()) if PID.exists() and PID.read_text().strip().isdigit() else None
 command=[];running=False
 if pid and Path(f'/proc/{pid}/cmdline').exists():
  command=Path(f'/proc/{pid}/cmdline').read_bytes().decode().strip('\x00').split('\x00')
  running=bool(command) and '/usr/bin/suricata' in command and Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1][0]!='Z'
 queue=Path('/proc/net/netfilter/nfnetlink_queue')
 rows=queue.read_text().splitlines() if queue.exists() else []
 return {'pid':pid,'running':running,'command':command,'queue_rows':rows,'queue0_bound':any(r.split() and r.split()[0]=='0' for r in rows)}

def main():
 action=sys.argv[1]
 if action=='serve':
  while True:time.sleep(10)
 elif action=='start':
  phase=sys.argv[2]
  if phase not in ('before','after'):raise SystemExit('phase required')
  if status()['running']:raise SystemExit('existing Suricata process; stop')
  out=Path('/tmp')/phase;out.mkdir(exist_ok=False)
  rule='/opt/ips/alert.rules' if phase=='before' else '/opt/ips/drop.rules'
  common=['/usr/bin/suricata','-c','/opt/ips/suricata.yaml','-S',rule,'-l',str(out),'--pidfile',str(PID)]
  checked=subprocess.run(common+['-T','--init-errors-fatal'],capture_output=True,text=True)
  (out/'validation.txt').write_text(checked.stdout+checked.stderr)
  if checked.returncode:print(json.dumps({'validation_exit':checked.returncode,'output':checked.stdout+checked.stderr}));raise SystemExit(2)
  started=subprocess.run(common+['-q','0','--runmode','workers','-D'],capture_output=True,text=True)
  (out/'startup.txt').write_text(started.stdout+started.stderr)
  for _ in range(30):
   s=status()
   if s['running'] and s['queue0_bound']:break
   time.sleep(.2)
  print(json.dumps({'validation_exit':checked.returncode,'start_exit':started.returncode,**status()}))
 elif action=='status':print(json.dumps(status()))
 elif action=='stop':
  s=status()
  if s['running']:os.kill(s['pid'],signal.SIGTERM)
  for _ in range(40):
   if not status()['running']:break
   time.sleep(.2)
  print(json.dumps(status()))
 elif action=='read':
  phase,name=sys.argv[2:4]
  if phase not in ('before','after') or name not in ('eve.json','validation.txt','startup.txt','suricata.log'):raise SystemExit('unsafe read')
  p=Path('/tmp')/phase/name
  if not p.exists():raise SystemExit('evidence missing')
  sys.stdout.write(p.read_text())
 else:raise SystemExit('unsupported action')

if __name__=='__main__':main()
