"""User-started LAB provisioning, container namespace only. Not a collector."""
import os
from pathlib import Path
import subprocess
import time

def run(*args): subprocess.run(args, check=True)

role = os.environ.get("NETWORK_LAB_ROLE")
if role not in {"router", "client-a", "client-b"}: raise SystemExit("LAB role required")
# All three networks are internal. Remove any Docker-provided default route;
# clients get only the explicitly required remote LAB subnet route.
routes = subprocess.run(["ip", "route", "show", "default"], check=True, capture_output=True, text=True).stdout
if routes.strip(): run("ip", "route", "del", "default")
if role == "client-a": run("ip", "route", "replace", "10.203.20.0/24", "via", "10.203.10.254", "dev", "data0")
elif role == "client-b": run("ip", "route", "replace", "10.203.10.0/24", "via", "10.203.20.254", "dev", "data0")
else:
    run("nft", "-f", "/opt/network-lab/before.nft")
    # Upstream zebra 10.2 requests SYS_ADMIN. Default to Linux connected routing
    # instead of granting it or bypassing the FRR capability checks. This opt-in
    # path is for later review, not a verified working FRR profile.
    if os.environ.get("NETWORK_LAB_START_FRR", "0") == "1":
        run("/usr/lib/frr/zebra", "-d", "-A", "127.0.0.1", "-u", "frr", "-g", "frr", "-f", "/etc/frr/frr.conf")
    demo = subprocess.Popen(["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/opt/network-lab/demo"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    Path("/run/network-lab-demo.pid").write_text(str(demo.pid))
while True: time.sleep(30)
