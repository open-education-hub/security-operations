#!/usr/bin/env python3
"""
Zero Trust Identity-Aware Proxy
Enforces authentication and device posture on every request.
"""
import json
import os
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

BACKEND_URL = os.environ.get("BACKEND_URL", "http://app-backend:9000")
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/zt-access.log")

# Mock token store: token -> user identity
VALID_TOKENS = {
    "valid-user-token-abc123": {"user": "alice@company.com", "roles": ["user", "analyst"]},
    "admin-token-xyz999":      {"user": "bob@company.com",   "roles": ["user", "admin"]},
}

# Admin-only resources
ADMIN_RESOURCES = ["/api/admin", "/api/admin/"]

def log_access(source_ip, user, resource, device_health, decision, reason):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source_ip": source_ip,
        "user": user,
        "resource": resource,
        "device_health": device_health,
        "decision": decision,
        "reason": reason
    }
    line = json.dumps(entry)
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

class ZTProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default access log

    def send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        source_ip = self.client_address[0]
        auth_header = self.headers.get("Authorization", "")
        device_health = self.headers.get("X-Device-Health", "unknown")

        # Step 1: Verify token
        token = auth_header.replace("Bearer ", "").strip()
        if token not in VALID_TOKENS:
            log_access(source_ip, "anonymous", self.path, device_health, "DENY", "missing or invalid token")
            self.send_json(401, {"error": "Authentication required", "code": 401})
            return

        user_info = VALID_TOKENS[token]
        user = user_info["user"]
        roles = user_info["roles"]

        # Step 2: Check admin resource access
        if self.path in ADMIN_RESOURCES and "admin" not in roles:
            log_access(source_ip, user, self.path, device_health, "DENY", "insufficient role")
            self.send_json(403, {"error": "Insufficient privileges", "required_role": "admin"})
            return

        # Step 3: Device posture check for sensitive resources
        if device_health == "non-compliant":
            log_access(source_ip, user, self.path, device_health, "DENY", "non-compliant device")
            self.send_json(403, {
                "error": "Device posture check failed",
                "reason": "Device is not compliant with security policy",
                "remediation": "Update OS, enable disk encryption, install EDR agent"
            })
            return

        # Step 4: Allow and proxy to backend
        import urllib.request
        try:
            backend_req = urllib.request.Request(BACKEND_URL + self.path)
            with urllib.request.urlopen(backend_req, timeout=3) as resp:
                data = json.loads(resp.read())
        except Exception:
            data = {"data": "Confidential: Q4 financial results — internal use only"}

        data["accessed_by"] = user
        data["device_trust"] = device_health if device_health != "unknown" else "not-checked"
        data["access_time"] = datetime.datetime.utcnow().isoformat() + "Z"

        log_access(source_ip, user, self.path, device_health, "ALLOW", "all checks passed")
        self.send_json(200, data)

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), ZTProxyHandler)
    print("[ZT-PROXY] Listening on :8080")
    print("[ZT-PROXY] Identity-aware proxy enforcing Zero Trust policies")
    server.serve_forever()
