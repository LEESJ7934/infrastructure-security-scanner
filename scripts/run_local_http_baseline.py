"""Run a disposable, loopback-only Windows HTTP baseline using Python stdlib.

Starts ONLY the parameterized SQL and hardened-header lab HTTP service.
Does not use Docker, AWS, MySQL or affect other project containers.
Stop with Ctrl+C. A second PowerShell window is needed for the scanner.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def launch(*, run=subprocess.run) -> int:
    env = os.environ.copy()
    env.update({
        "LAB_MODE": "http",
        "LAB_VULNERABLE": "0",
        "LAB_HTTP_BIND_HOST": "127.0.0.1",
        "LAB_HTTP_BIND_PORT": "8081",
    })
    print("Starting approved local HTTP baseline at http://127.0.0.1:8081", flush=True)
    print("Service uses fixed safe headers and parameterized SQL. Press Ctrl+C to stop.", flush=True)
    try:
        completed = run([sys.executable, "-u", str(PROJECT_ROOT / "lab" / "server.py")],
                        cwd=str(PROJECT_ROOT), env=env, check=False)
        return completed.returncode
    except KeyboardInterrupt:
        print("Local baseline stopped.", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(launch())
