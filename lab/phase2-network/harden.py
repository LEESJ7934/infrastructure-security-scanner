"""Explicit user action: only the owned demo and nft table in this container."""
import argparse
import os
from pathlib import Path
import signal
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--apply", action="store_true")
args = parser.parse_args()
if not args.apply or os.environ.get("NETWORK_LAB_ROLE") != "router": raise SystemExit("Explicit --apply inside LAB router required")
pid_file = Path("/run/network-lab-demo.pid")
if pid_file.exists():
    pid = int(pid_file.read_text())
    command = Path(f"/proc/{pid}/cmdline")
    if command.exists():
        parts = command.read_bytes().split(b"\0")
        if not {b"http.server", b"8080", b"/opt/network-lab/demo"} <= set(parts): raise SystemExit("Demo process identity mismatch")
        os.kill(pid, signal.SIGTERM)
    pid_file.unlink()
# Never flush the global ruleset or touch host firewall rules.
subprocess.run(["nft", "delete", "table", "inet", "phase2_guard"], check=True)
subprocess.run(["nft", "-f", "/opt/network-lab/after.nft"], check=True)
print("LAB demo stopped; owned input guard hardened; requery before claiming PASS")
