#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ftp_honeypot.py
Config-driven FTP honeypot with command logic delegated to fake_ftp_commands.py

Run:
    python3 ftp_honeypot.py
"""

import os, sys, csv, json, time, socket, threading, random
from datetime import datetime
import importlib.util

LOG_DIR = "honeypot_logs"
CSV_AUTH = os.path.join(LOG_DIR, "ftp_auth.csv")
MODULES_DIR = "modules"
SSH_CONFIG_FILE = "honeypot_config.json"           # shared config (preferred)
FTP_CONFIG_FILE = "honeypot_ftp_config.json"       # fallback if no SSH config

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODULES_DIR, exist_ok=True)

DEFAULT_CFG = {
    "ftp_bind_addr": "0.0.0.0",
    "ftp_port": 2121,
    "ftp_banner": "220 FTP Server (honeypot) ready\r\n",
    "default_user": "ftp",
    "allow_file_write": True,
    "allow_file_delete": False,
    "pasv_port_min": 50000,
    "pasv_port_max": 50100,
    "fake_files": {
        "/readme.txt": {"content": "Welcome to FTP honeypot\n", "mode": "0644", "owner": "root", "mime":"text/plain"},
        "/pub/index.html": {"content": "<h1>Hello</h1>\n", "mode": "0644", "owner": "root", "mime":"text/html"}
    }
}

# ---------- config ----------
def load_config():
    if os.path.exists(SSH_CONFIG_FILE):
        try:
            with open(SSH_CONFIG_FILE, "r", encoding="utf-8") as f:
                base = json.load(f)
            cfg = dict(DEFAULT_CFG)
            cfg["ftp_bind_addr"]   = base.get("bind_addr", DEFAULT_CFG["ftp_bind_addr"])
            cfg["ftp_port"]        = int(base.get("ftp_port", DEFAULT_CFG["ftp_port"]))
            cfg["ftp_banner"]      = base.get("ftp_banner", DEFAULT_CFG["ftp_banner"])
            cfg["default_user"]    = base.get("default_user", DEFAULT_CFG["default_user"])
            cfg["allow_file_write"]= base.get("allow_file_write", True)
            cfg["allow_file_delete"]= base.get("allow_file_delete", False)
            cfg["pasv_port_min"]   = int(base.get("pasv_port_min", DEFAULT_CFG["pasv_port_min"]))
            cfg["pasv_port_max"]   = int(base.get("pasv_port_max", DEFAULT_CFG["pasv_port_max"]))
            cfg["fake_files"]      = base.get("fake_files", DEFAULT_CFG["fake_files"])
            return cfg
        except Exception as e:
            print("[!] Failed to load honeypot_config.json:", e)

    if os.path.exists(FTP_CONFIG_FILE):
        try:
            with open(FTP_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print("[!] Failed to load honeypot_ftp_config.json:", e)

    with open(FTP_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CFG, f, indent=2, ensure_ascii=False)
    print(f"[*] Wrote default {FTP_CONFIG_FILE}. Edit to customize.")
    return dict(DEFAULT_CFG)

CONFIG = load_config()

# ---------- csv header ----------
if not os.path.exists(CSV_AUTH):
    with open(CSV_AUTH, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["timestamp","client_ip","client_port","event","username","password","session_id"])

def log_auth(client_addr, event, username, password, session_id):
    ts = datetime.utcnow().isoformat() + "Z"
    ip, port = client_addr
    with open(CSV_AUTH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([ts, ip, port, event, username, password, session_id])

def append_session_log(session_dir, filename, data):
    path = os.path.join(session_dir, filename)
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)

# ---------- import fake_ftp_commands ----------
def import_fake_ftp_commands():
    # prefer modules/fake_ftp_commands.py
    mod_path = os.path.join(MODULES_DIR, "fake_ftp_commands.py")
    if os.path.exists(mod_path):
        spec = importlib.util.spec_from_file_location("modules.fake_ftp_commands", mod_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        print("[*] Loaded FTP commands from modules/fake_ftp_commands.py")
        return mod
    # fallback ./fake_ftp_commands.py
    if os.path.exists("fake_ftp_commands.py"):
        spec = importlib.util.spec_from_file_location("fake_ftp_commands", "fake_ftp_commands.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        print("[*] Loaded FTP commands from ./fake_ftp_commands.py")
        return mod
    print("[!] No fake_ftp_commands.py found; exiting.")
    sys.exit(1)

FTP_CMDS = import_fake_ftp_commands()

# ---------- session ----------
class FTPSession:
    def __init__(self, client_addr, session_id):
        self.id = session_id
        self.client_addr = client_addr
        self.dir = os.path.join(LOG_DIR, f"session_{session_id}")
        os.makedirs(self.dir, exist_ok=True)
        self.start = datetime.utcnow().isoformat() + "Z"

        self.username = CONFIG.get("default_user","ftp")
        self.cwd = "/"
        self.type_binary = False
        self.pasv_sock = None
        self.pasv_addr = None
        self.last_user = None
        self.logged_in = False

        # copy fake files
        self.fake_files = {}
        for p, v in (CONFIG.get("fake_files") or {}).items():
            if isinstance(v, dict):
                self.fake_files[p] = {
                    "content": v.get("content",""),
                    "mode": v.get("mode","0644"),
                    "owner": v.get("owner", CONFIG.get("default_user","ftp")),
                    "mime":  v.get("mime","text/plain")
                }
            else:
                self.fake_files[p] = {"content": str(v), "mode": "0644", "owner": CONFIG.get("default_user","ftp"), "mime":"text/plain"}

        self.allow_file_write  = CONFIG.get("allow_file_write", True)
        self.allow_file_delete = CONFIG.get("allow_file_delete", False)

        with open(os.path.join(self.dir, "meta.json"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"client_addr": client_addr, "start": self.start, "session_id": session_id}, ensure_ascii=False) + "\n")

    def close_pasv(self):
        if self.pasv_sock:
            try: self.pasv_sock.close()
            except Exception: pass
            self.pasv_sock = None
            self.pasv_addr = None

# ---------- PASV helpers exposed to command module ----------
def open_pasv_socket(bind_addr, pmin, pmax):
    for _ in range(30):
        port = random.randint(pmin, pmax)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_addr, port))
            s.listen(1)
            return s, port
        except OSError:
            try: s.close()
            except Exception: pass
            continue
    raise OSError("No passive port available")

# ---------- per-client worker ----------
def handle_client(conn, addr, session_id):
    sess = FTPSession(addr, session_id)

    def send(line: str):
        try:
            conn.sendall(line.encode("utf-8", errors="ignore"))
        except Exception:
            raise

    def accept_data_and_send(payload: bytes):
        # accept a PASV data connection and send payload, then close
        if not sess.pasv_sock:
            send("425 Use PASV first.\r\n")
            return
        try:
            data_conn, _ = sess.pasv_sock.accept()
            data_conn.sendall(payload)
        finally:
            try: data_conn.close()
            except Exception: pass
            sess.close_pasv()

    def accept_data_and_recv(limit_bytes=1024*1024):
        # accept PASV data and read all (capped), return bytes
        if not sess.pasv_sock:
            send("425 Use PASV first.\r\n")
            return b""
        chunks = []
        total = 0
        try:
            data_conn, _ = sess.pasv_sock.accept()
            data_conn.settimeout(30)
            while True:
                b = data_conn.recv(4096)
                if not b:
                    break
                chunks.append(b)
                total += len(b)
                if total > limit_bytes:
                    break
        finally:
            try: data_conn.close()
            except Exception: pass
            sess.close_pasv()
        return b"".join(chunks)

    # Handlers context passed to module
    ctx = {
        "send": send,
        "log": lambda fn, s: append_session_log(sess.dir, fn, s),
        "open_pasv": lambda: open_pasv_socket(CONFIG.get("ftp_bind_addr","0.0.0.0"), CONFIG.get("pasv_port_min",50000), CONFIG.get("pasv_port_max",50100)),
        "set_pasv": lambda sock, addr: setattr(sess, "pasv_sock", sock) or setattr(sess, "pasv_addr", addr),
        "data_send": accept_data_and_send,
        "data_recv": accept_data_and_recv,
        "announce_ip": lambda: conn.getsockname()[0],
        "config": CONFIG
    }

    # Greeting
    send(CONFIG.get("ftp_banner", "220 FTP Server ready\r\n"))

    try:
        while True:
            raw = conn.recv(1024)
            if not raw:
                break
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            append_session_log(sess.dir, "commands.log", f"[{datetime.utcnow().isoformat()}] CMD: {line}\n")
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            action = FTP_CMDS.handle_command(sess, cmd, arg, ctx)  # <-- delegate
            # action can be: None / {"close": True}
            if isinstance(action, dict) and action.get("close"):
                break

    except (ConnectionResetError, BrokenPipeError):
        append_session_log(sess.dir, "errors.log", f"[{datetime.utcnow().isoformat()}] Peer reset connection\n")
    except Exception as e:
        append_session_log(sess.dir, "errors.log", f"[{datetime.utcnow().isoformat()}] Exception: {e}\n")
    finally:
        sess.close_pasv()
        try: conn.close()
        except Exception: pass
        append_session_log(sess.dir, "meta.json", json.dumps({"end_time": datetime.utcnow().isoformat() + "Z"}, ensure_ascii=False) + "\n")

# ---------- accept loop ----------
def server_ftp_loop():
    bind_addr = CONFIG.get("ftp_bind_addr", "0.0.0.0")
    bind_port = int(CONFIG.get("ftp_port", 2121))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_addr, bind_port))
    except OSError as e:
        print("Fatal error:", e)
        sys.exit(1)
    sock.listen(100)
    print(f"[*] FTP honeypot listening on {bind_addr}:{bind_port}")
    sid = 0
    while True:
        try:
            c, a = sock.accept()
            sid += 1
            session_id = int(time.time()*1000) + sid
            print(f"[+] Incoming connection from {a}, session {session_id}")
            log_auth(a, "connection", "", "", session_id)
            t = threading.Thread(target=handle_client, args=(c, a, session_id), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("[*] Shutting down.")
            try: sock.close()
            except Exception: pass
            break
        except Exception as e:
            print("[!] Accept loop exception:", e)
            continue

if __name__ == "__main__":
    server_ftp_loop()

