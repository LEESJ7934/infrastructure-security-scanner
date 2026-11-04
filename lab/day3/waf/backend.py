"""Fixed responses for the isolated WAF lab. No request data is stored."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

BODY = b"day3-backend-ok\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path not in {"/day3-control", "/day3-policy"}:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    # A PUT reaching the backend is harmless and returns 200, exposing a missed block.
    do_PUT = do_GET


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
