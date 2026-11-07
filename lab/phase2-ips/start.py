"""Bootstrap only newly created scanner-p2ips namespaces. No host operations."""
import json,os,subprocess,time,sys
from pathlib import Path
ROLE=os.environ.get('IPS_LAB_ROLE')
ADDRESSES={'gateway':'10.207.10.254','client':'10.207.10.10','server':'10.207.20.10'}
if ROLE not in ADDRESSES:raise SystemExit('IPS role required')
def run(*args):
 result=subprocess.run(args,capture_output=True,text=True)
 if result.returncode:
  print(result.stderr,file=sys.stderr,flush=True)
  raise SystemExit('LAB namespace command failed; inline mode NOT verified')
 return result.stdout
address=ADDRESSES[ROLE]
original={'addresses':json.loads(run('ip','-j','addr','show','dev','data0')),'routes':json.loads(run('ip','-j','route')),'tables':json.loads(run('nft','-j','list','tables'))}
Path('/tmp/original-network.json').write_text(json.dumps(original))
if json.loads(run('ip','-j','route','show','default')):run('ip','route','del','default')
run('ip','addr','del',address+'/16','dev','data0');run('ip','addr','add',address+'/24','dev','data0')
if ROLE=='gateway':run('ip','addr','add','10.207.20.254/24','dev','data0')
elif ROLE=='client':run('ip','route','add','10.207.20.0/24','via','10.207.10.254','dev','data0')
else:run('ip','route','add','10.207.10.0/24','via','10.207.20.254','dev','data0')
for group in ('all','data0'):
 for key in ('accept_redirects','send_redirects'):
  if Path(f'/proc/sys/net/ipv4/conf/{group}/{key}').read_text().strip()!='0':raise SystemExit('Redirect safety not effective')
if ROLE=='gateway':
 # Probe queue expression in a hookless chain: never intercept traffic here.
 run('nft','add','table','inet','p2ips_kernel_probe')
 try:
  run('nft','add','chain','inet','p2ips_kernel_probe','probe')
  probe=subprocess.run(['nft','add','rule','inet','p2ips_kernel_probe','probe','queue','num','0'],capture_output=True,text=True)
 finally:run('nft','delete','table','inet','p2ips_kernel_probe')
 if probe.returncode:
  print(probe.stderr,file=sys.stderr,flush=True)
  raise SystemExit('NFQUEUE_KERNEL_UNAVAILABLE: no inline traffic tests performed')
 rules='''table inet p2ips_guard {
 chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state established,related accept; }
 chain forward { type filter hook forward priority 0; policy drop;
  ip saddr 10.207.10.10 ip daddr 10.207.20.10 tcp dport 8080 counter queue num 0
  ip saddr 10.207.20.10 ip daddr 10.207.10.10 tcp sport 8080 counter queue num 0
 }
 chain output { type filter hook output priority 0; policy drop; oifname "lo" accept; }
}'''
else:
 rules='''table inet p2ips_endpoint {
 chain forward { type filter hook forward priority 0; policy drop; }
 chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state established,related accept; ip saddr 10.207.10.10 tcp dport 8080 accept; }
 chain output { type filter hook output priority 0; policy drop; oifname "lo" accept; ip daddr 10.207.20.10 tcp dport 8080 accept; ip daddr 10.207.10.10 tcp sport 8080 accept; }
}'''
Path('/tmp/guard.nft').write_text(rules);run('nft','-f','/tmp/guard.nft')
Path('/tmp/ready').write_text(ROLE)
if ROLE=='server':
 os.execv('/usr/bin/python3',['python3','-B','/opt/ips/probe.py','serve'])
while True:time.sleep(10)
