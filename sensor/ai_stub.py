#!/usr/bin/env python3
"""Demo AI endpoint: tiny local HTTP server the bots call."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self):
        body = json.dumps({"ok": True, "model": "attest-demo-stub"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._ok()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._ok()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 18080), H)
    print("[STUB] demo AI endpoint on 127.0.0.1:18080")
    srv.serve_forever()
