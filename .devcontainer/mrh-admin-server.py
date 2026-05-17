#!/usr/bin/env python3

import base64
import hmac
import os
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

ADMIN_DIRECTORY = "/opt/mrh-admin"
LOG_FILE = "/var/log/mrh-admin/connections.log"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "dari"
LISTEN_HOST = os.getenv("MRH_ADMIN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("MRH_ADMIN_PORT", "8080"))

# Connection tracking
connections_lock = threading.Lock()
active_connections = {}
total_connections = 0


def _ensure_log_dir():
    """Create log directory if it doesn't exist"""
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create log directory {log_dir}: {e}", file=sys.stderr)


def _log_message(message):
    """Write message to both console and log file"""
    print(message, flush=True)
    try:
        _ensure_log_dir()
        with open(LOG_FILE, 'a') as f:
            f.write(message + '\n')
            f.flush()
    except Exception as e:
        print(f"Warning: Could not write to log file: {e}", file=sys.stderr)


def _build_auth_token():
    username = os.getenv("MRH_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
    password = os.getenv("MRH_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    return base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")


class AdminAuthHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        global total_connections
        super().__init__(*args, directory=ADMIN_DIRECTORY, **kwargs)
        
        # Track connection
        client_ip = self.client_address[0]
        with connections_lock:
            connection_id = f"{client_ip}:{self.client_address[1]}"
            active_connections[connection_id] = {
                'ip': client_ip,
                'port': self.client_address[1],
                'connected_at': datetime.now(),
                'authorized': False
            }
            total_connections += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _log_message(f"[{timestamp}] NEW CONNECTION: {connection_id} (Total: {len(active_connections)}, All-time: {total_connections})")

    def _is_authorized(self):
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Basic "):
            return False
        presented_token = authorization[6:].strip()
        return hmac.compare_digest(presented_token, _build_auth_token())

    def _request_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="MRH Admin Panel", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Authentication required.")

    def do_GET(self):
        if not self._is_authorized():
            self._request_auth()
            return
        
        # Mark as authorized
        client_ip = self.client_address[0]
        connection_id = f"{client_ip}:{self.client_address[1]}"
        with connections_lock:
            if connection_id in active_connections:
                active_connections[connection_id]['authorized'] = True
        
        super().do_GET()

    def do_HEAD(self):
        if not self._is_authorized():
            self._request_auth()
            return
        super().do_HEAD()
    
    def handle(self):
        try:
            super().handle()
        finally:
            # Remove connection when done
            client_ip = self.client_address[0]
            connection_id = f"{client_ip}:{self.client_address[1]}"
            with connections_lock:
                if connection_id in active_connections:
                    del active_connections[connection_id]
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _log_message(f"[{timestamp}] DISCONNECTED: {connection_id} (Active: {len(active_connections)})")


if __name__ == "__main__":
    username = os.getenv("MRH_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
    password = os.getenv("MRH_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    if username == DEFAULT_ADMIN_USERNAME or password == DEFAULT_ADMIN_PASSWORD:
        print(
            "WARNING: Default admin credential detected. Set MRH_ADMIN_USERNAME and MRH_ADMIN_PASSWORD to override.",
            file=sys.stderr,
            flush=True,
        )
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _log_message(f"[{timestamp}] Starting MRH Admin Server on {LISTEN_HOST}:{LISTEN_PORT}")
    _log_message(f"[{timestamp}] Admin directory: {ADMIN_DIRECTORY}")
    _log_message(f"[{timestamp}] Tracking connections...")
    
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), AdminAuthHandler)
    server.serve_forever()
