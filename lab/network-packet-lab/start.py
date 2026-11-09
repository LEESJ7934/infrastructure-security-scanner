"""Provision ONLY a new packet LAB container, never the existing scanner-p2net."""
import json
import os
from pathlib import Path
import subprocess
import time

def run(*args): subprocess.run(args, check=True)

role=os.environ.get("PACKET_LAB_ROLE")
addresses={"router":"10.204.10.254", "client-a":"10.204.10.10", "client-b":"10.204.20.10"}
if role not in addresses: raise SystemExit("Packet LAB role required")
address=addresses[role]
# Docker's isolated fabric covers /16; endpoint IP routing uses /24. All IPs
# stay inside Docker's internal CIDR, avoiding its inter-CIDR isolation rule.
defaults=subprocess.run(["ip","-j","route","show","default"],check=True,capture_output=True,text=True).stdout
if json.loads(defaults): run("ip","route","del","default")
run("ip","addr","del",address+"/16","dev","data0")
run("ip","addr","add",address+"/24","dev","data0")
if role=="router": run("ip","addr","add","10.204.20.254/24","dev","data0")
elif role=="client-a":run("ip","route","replace","10.204.20.0/24","via","10.204.10.254","dev","data0")
else:run("ip","route","replace","10.204.10.0/24","via","10.204.20.254","dev","data0")
# Compose endpoint options set interface sysctls; never remount /proc/sys.
# Same-interface routing must not teach clients a direct L2 bypass route.
for group in ("all","data0"):
    for key in (("send_redirects","accept_redirects") if role=='router' else ("accept_redirects",)):
        actual=Path(f"/proc/sys/net/ipv4/conf/{group}/{key}").read_text().strip()
        if actual!='0':raise SystemExit(f'Redirect setting not applied: {role} {group}.{key}={actual}; stop rather than bypass checks')
run("nft","-f","/opt/packet-lab/router.nft" if role=="router" else "/opt/packet-lab/client.nft")
print("New packet LAB namespace ready; no default route; redirects disabled",flush=True)
while True:time.sleep(30)
