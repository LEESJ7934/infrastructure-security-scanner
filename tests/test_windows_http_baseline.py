"""Loopback Windows HTTP baseline cannot affect unrelated Docker containers."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from urllib.parse import urlencode
from urllib.request import urlopen

from scripts.run_local_http_baseline import launch


class LocalWindowsHTTPBaselineTests(unittest.TestCase):
    def test_launcher_forces_loopback_safe_mode_without_shell(self):
        seen = {}
        def fake_run(argv, **kwargs):
            seen.update(argv=argv, **kwargs)
            return SimpleNamespace(returncode=0)
        self.assertEqual(launch(run=fake_run), 0)
        self.assertEqual(seen["env"]["LAB_MODE"], "http")
        self.assertEqual(seen["env"]["LAB_VULNERABLE"], "0")
        self.assertEqual(seen["env"]["LAB_HTTP_BIND_HOST"], "127.0.0.1")
        self.assertEqual(seen["env"]["LAB_HTTP_BIND_PORT"], "8081")
        self.assertEqual(seen["argv"][0], sys.executable)
        self.assertEqual(seen["argv"][1], "-u")
        self.assertFalse(seen["check"])

    def test_local_service_has_headers_and_parameterized_lookup(self):
        # Real subprocess, no Docker, no MySQL, no EC2.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(LAB_MODE="http", LAB_VULNERABLE="0",
                   LAB_HTTP_BIND_HOST="127.0.0.1",
                   LAB_HTTP_BIND_PORT=str(port))
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.Popen([sys.executable, "-u", str(root / "lab" / "server.py")],
                                cwd=str(root), env=env,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 8
            while True:
                try:
                    with urlopen(base, timeout=1) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
                        self.assertIn("default-src", response.headers["Content-Security-Policy"])
                    break
                except OSError:
                    if time.monotonic() > deadline or proc.poll() is not None:
                        self.fail("localhost HTTP baseline did not start")
                    time.sleep(.05)
            with urlopen(base + "/lookup?" + urlencode({"id": "1"}), timeout=2) as response:
                self.assertIn("First name: Alex", response.read().decode())
            with urlopen(base + "/lookup?" + urlencode({"id": "1' OR '1'='1"}), timeout=2) as response:
                self.assertEqual(response.read().decode(), "No results")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
