"""Synthetic nonproduction services for an isolated comparison lab."""
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

MODE = os.environ.get("LAB_MODE", "http")
VULNERABLE = os.environ.get("LAB_VULNERABLE") == "1"

if MODE == "ftp":
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    auth = DummyAuthorizer()
    if VULNERABLE:
        auth.add_anonymous("/lab/ftp", perm="elr")  # no write privileges
    handler = type("LabFTPHandler", (FTPHandler,), {"authorizer": auth,
                    "banner": "220 controlled-lab FTP ready"})
    FTPServer(("0.0.0.0", 2121), handler).serve_forever()
elif MODE == "http":
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self._handle(send_body=False)
        def do_GET(self):
            self._handle(send_body=True)
        def _handle(self, send_body):
            parts = urlsplit(self.path)
            status, body = 200, "Controlled laboratory HTTP service"
            if parts.path == "/lookup":
                param = parse_qs(parts.query).get("id", [""])[0]
                with sqlite3.connect(":memory:") as conn:
                    conn.execute("CREATE TABLE people (id TEXT, first_name TEXT)")
                    conn.executemany("INSERT INTO people VALUES (?, ?)", [("1", "Alex"), ("2", "Robin")])
                    # The baseline is intentionally parameterized. No SQL mutation path exists.
                    rows = conn.execute("SELECT first_name FROM people WHERE id=?", (param,)).fetchall()
                body = "\\n".join("First name: " + row[0] for row in rows) or "No results"
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            if not VULNERABLE:
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            if send_body:
                self.wfile.write(payload)
        def log_message(self, fmt, *args):
            pass
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
else:
    raise SystemExit("Unsupported LAB_MODE")
