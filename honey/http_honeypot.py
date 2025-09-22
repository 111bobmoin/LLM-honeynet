#!/usr/bin/env python3
"""
http_honeypot.py
A modular, config-driven HTTP honeypot.

Run:
    python3 http_honeypot.py

Description:
- Loads honeypot_http_config.json for config (bind_addr, bind_port, fake_files, rules...)
- Loads modules/*.py (optional) which can implement handle_request(method, path, headers, body, session)
- Logs requests to CSV and per-session logs
"""

import os
import sys
import json
import csv
import time
import glob
import importlib.util
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime
from urllib.parse import urlparse, unquote_plus

# Paths
CONFIG_FILE = "honeypot_http_config.json"
MODULES_DIR = "modules"
LOG_DIR = "honeypot_logs"
CSV_LOG = os.path.join(LOG_DIR, "http_requests.csv")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODULES_DIR, exist_ok=True)

# Default config (written if not exists)
DEFAULT_CONFIG = {
  "bind_addr": "0.0.0.0",
  "bind_port": 8080,
  "server_name": "SimpleHTTP/1.0 (honeypot)",
  "prompt": "honeypot-http> ",
  "default_user": "www-data",
  "fake_files": {
    "/": {"content": "<html><body><h1>Welcome</h1></body></html>", "mime": "text/html", "mode": "0644", "owner": "root"},
    "/index.html": {"content": "<html><body><h1>Index</h1></body></html>", "mime": "text/html", "mode": "0644", "owner": "root"},
    "/admin/secret.txt": {"content": "TOP-SECRET\n", "mime": "text/plain", "mode": "0600", "owner": "root"}
  },
  "routes": {
    "/admin": {"status": 401, "body": "Unauthorized"},
    "/health": {"status": 200, "body": "OK"}
  },
  "allow_file_write": True,
  "allow_file_delete": False,
  "max_body_len": 65536
}

def load_config(path=CONFIG_FILE):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[*] Created default config at {path}. Edit and restart to customize.")
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(cfg)
        return merged
    except Exception as e:
        print("[!] Failed to load config:", e)
        return DEFAULT_CONFIG.copy()

CONFIG = load_config()

# ensure csv header
if not os.path.exists(CSV_LOG):
    with open(CSV_LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp","client_ip","client_port","method","path","status","user_agent","session_id"])

# plugin loader
def load_modules():
    mods = []
    for path in glob.glob(os.path.join(MODULES_DIR, "*.py")):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, "handle_request"):
                mods.append(mod)
                print(f"[*] Loaded module: {name}")
        except Exception as e:
            print(f"[!] Failed to load module {path}: {e}")
    return mods

MODULES = load_modules()

# Session manager (simple)
_session_counter = 0
_sessions_lock = threading.Lock()
def new_session(client_addr):
    global _session_counter
    with _sessions_lock:
        _session_counter += 1
        sid = int(time.time()*1000) + _session_counter
    session_dir = os.path.join(LOG_DIR, f"session_{sid}")
    os.makedirs(session_dir, exist_ok=True)
    # session object
    session = {
        "id": sid,
        "client": client_addr,
        "start": datetime.utcnow().isoformat() + "Z",
        "dir": session_dir,
        "cwd": "/",
        "username": CONFIG.get("default_user", "www-data"),
        # structured fake_files copied per-session
        "fake_files": {}
    }
    # structured files
    for p, v in (CONFIG.get("fake_files") or {}).items():
        if isinstance(v, dict):
            session["fake_files"][p] = {
                "content": v.get("content",""),
                "mime": v.get("mime","text/plain"),
                "mode": v.get("mode","0644"),
                "owner": v.get("owner", CONFIG.get("default_user","www-data"))
            }
        else:
            session["fake_files"][p] = {"content": str(v), "mime":"text/plain", "mode":"0644", "owner":CONFIG.get("default_user","www-data")}
    session["allow_file_write"] = CONFIG.get("allow_file_write", True)
    session["allow_file_delete"] = CONFIG.get("allow_file_delete", False)
    # write meta
    with open(os.path.join(session_dir, "meta.json"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"client": client_addr, "start": session["start"], "session_id": sid}, ensure_ascii=False) + "\n")
    return session

def append_session_log(session, filename, data):
    path = os.path.join(session["dir"], filename)
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)

def log_request_csv(client_addr, method, path, status, ua, session_id):
    ts = datetime.utcnow().isoformat() + "Z"
    cip, cport = client_addr
    with open(CSV_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([ts, cip, cport, method, path, status, ua, session_id])

# default handler implementation (externalized to fake_http_handlers)
FAKE_HANDLERS_PATHS = [
    os.path.join(MODULES_DIR, "fake_http_handlers.py"),
    os.path.join(".", "fake_http_handlers.py")
]
FAKE_HANDLERS = None
for p in FAKE_HANDLERS_PATHS:
    if os.path.exists(p):
        spec = importlib.util.spec_from_file_location("fake_http_handlers", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        FAKE_HANDLERS = mod
        print(f"[*] Loaded fake HTTP handlers from {p}")
        break
if FAKE_HANDLERS is None:
    print("[!] Could not find fake_http_handlers.py - basic behavior used (see README)")

# Threading HTTP server
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class HoneypotHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = CONFIG.get("server_name", "SimpleHTTP/1.0 (honeypot)")

    def log_message(self, format, *args):
        # override to silence default stdout logs; we'll control logging
        pass

    def do_request_common(self):
        # create or retrieve session per-client for simplicity: new session per connection
        client = (self.client_address[0], self.client_address[1])
        session = new_session(client)
        # read body if any
        length = int(self.headers.get('Content-Length', "0") or 0)
        body = None
        if length:
            body = self.rfile.read(min(length, CONFIG.get("max_body_len", 65536)))
        path = unquote_plus(urlparse(self.path).path)
        method = self.command
        ua = self.headers.get("User-Agent", "")
        # let modules intercept first
        for mod in MODULES:
            try:
                res = mod.handle_request(method, path, dict(self.headers), body, session)
                if isinstance(res, dict) and res.get("handled"):
                    status = res.get("status", 200)
                    headers = res.get("headers", {})
                    resp_body = res.get("body", "")
                    # write session logs
                    append_session_log(session, "session.log",
                                       f"[{datetime.utcnow().isoformat()}] MODULE {mod.__name__} handled {method} {path} -> {status}\n")
                    # respond
                    self.send_response(status)
                    for k,v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    if isinstance(resp_body, str):
                        resp_body = resp_body.encode("utf-8")
                    if resp_body:
                        self.wfile.write(resp_body)
                    log_request_csv(client, method, path, status, ua, session["id"])
                    return
            except Exception as e:
                append_session_log(session, "errors.log", f"[{datetime.utcnow().isoformat()}] module {mod.__name__} error: {e}\n")
                # continue to other modules / fallback

        # else delegate to FAKE_HANDLERS if present
        if FAKE_HANDLERS and hasattr(FAKE_HANDLERS, "handle_request"):
            try:
                res = FAKE_HANDLERS.handle_request(method, path, dict(self.headers), body, session)
                # expected to return dict: {"status":int,"headers":{}, "body":bytes_or_str}
                status = res.get("status", 200)
                headers = res.get("headers", {})
                resp_body = res.get("body", "")
                self.send_response(status)
                for k,v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if isinstance(resp_body, str):
                    resp_body = resp_body.encode("utf-8")
                if resp_body:
                    self.wfile.write(resp_body)
                append_session_log(session, "session.log",
                                   f"[{datetime.utcnow().isoformat()}] HANDLED {method} {path} -> {status}\n")
                log_request_csv(client, method, path, status, ua, session["id"])
                return
            except Exception as e:
                append_session_log(session, "errors.log", f"[{datetime.utcnow().isoformat()}] fake handlers error: {e}\n")

        # final fallback: 404
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        b = b"Not Found"
        self.wfile.write(b)
        append_session_log(session, "session.log",
                           f"[{datetime.utcnow().isoformat()}] FALLBACK {method} {path} -> 404\n")
        log_request_csv(client, method, path, 404, ua, session["id"])

    def do_GET(self):
        try:
            self.do_request_common()
        except Exception as e:
            # log and try to fail gracefully
            try:
                client = (self.client_address[0], self.client_address[1])
                s = new_session(client)
                append_session_log(s, "errors.log", f"[{datetime.utcnow().isoformat()}] handler exception: {e}\n")
            except Exception:
                pass

    def do_POST(self):
        self.do_GET()  # same flow

    def do_PUT(self):
        self.do_GET()

    def do_DELETE(self):
        self.do_GET()

def run_http_server():
    bind_addr = CONFIG.get("bind_addr", "0.0.0.0")
    bind_port = int(CONFIG.get("bind_port", 8080))
    server = ThreadingHTTPServer((bind_addr, bind_port), HoneypotHTTPRequestHandler)
    print(f"[*] HTTP honeypot listening on {bind_addr}:{bind_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[*] Shutting down")
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    run_http_server()

