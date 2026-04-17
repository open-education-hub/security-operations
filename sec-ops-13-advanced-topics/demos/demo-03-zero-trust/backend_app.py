#!/usr/bin/env python3
"""
Protected backend application (not directly accessible from frontend network).
Represents a resource that should only be accessed via the ZT proxy.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class BackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        resources = {
            "/secret-data": {"data": "Confidential: Q4 financial results — internal use only"},
            "/api/secret-data": {"data": "Confidential: Q4 financial results — internal use only"},
            "/api/admin": {"data": "Admin panel: system configuration and user management"},
            "/api/admin/": {"data": "Admin panel: system configuration and user management"},
        }
        data = resources.get(self.path, {"data": "Resource not found"})
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9000), BackendHandler)
    print("[BACKEND] Listening on :9000 (internal network only)")
    server.serve_forever()
