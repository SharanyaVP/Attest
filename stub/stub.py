#!/usr/bin/env python3
"""Controlled AI endpoint stub for shadow agent detection demo.

Listens on 0.0.0.0:8080. Agent workloads POST to /v1/chat; the stub
reads the JSON body, logs the client IP and the 'agent' field to
stdout, and returns a deterministic 200 response. GET /healthz is a
health check. Anything else returns a JSON 404.
Stdlib only: http.server + json. No em dashes anywhere.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubHandler(BaseHTTPRequestHandler):
    server_version = "ShadowDemoStub/1.0"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._send_json(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
        else:
            self._not_found()

    def do_POST(self):
        if self.path != "/v1/chat":
            self._not_found()
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        agent = None
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
            if isinstance(data, dict):
                agent = data.get("agent")
        except (json.JSONDecodeError, UnicodeDecodeError):
            agent = None

        client_ip = self.client_address[0]
        print("chat request from %s agent=%r" % (client_ip, agent), flush=True)

        self._send_json(
            200,
            {"model": "stub-1", "reply": "summary-ok", "tokens": 42},
        )

    def log_message(self, format, *args):
        # Route request logging to stdout (captured by nohup log).
        print("%s - %s" % (self.client_address[0], format % args), flush=True)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8080), StubHandler)
    print("stub listening on 0.0.0.0:8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
