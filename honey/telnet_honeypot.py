#!/usr/bin/env python3
"""
telnet_honeypot.py

Telnet honeypot that reuses SSH honeypot's config (honeypot_config.json) and fake_commands module.
- Per-session fake filesystem (content/mode/owner)
- Loads modules/fake_commands.py or ./fake_commands.py and calls handle_command(cmd, session)
- Configurable port (telnet_port in config) default 2323
- Logs: honeypot_logs/telnet_auth.csv and per-session dirs

Run:
    python3 telnet_honeypot.py
"""
import socket
import threading
import os
import sys
import time
import csv
import json
import importlib.util
import re
from datetime import datetime

# Paths
CONFIG_FILE_SSH = "honeypot_config.json"  # reuse SSH config if present
ALT_CONFIG_FILE = "honeypot_telnet_config.json"
LOG_DIR = "honeypot_logs"
CSV_LOG = os.path.join(LOG_DIR, "telnet_auth.csv")
MODULES_DIR = "modules"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODULES_DIR, exist_ok=True)

# Default local config (used only if no SSH config present)
DEFAULT_CONFIG = {
    "telnet_bind_addr": "0.0.0.0",
    "telnet_port": 2323,
    "telnet_banner": "Welcome to BusyBox v1.32.0 (telnet honeypot)\r\n",
    "prompt": "honeypot> ",
    "default_user": "root",
    "fake_files": {
        "/etc/passwd": {"content": "root:x:0:0:root:/root:/bin/sh\n", "mode": "0644", "owner": "root"},
        "/root/secret.txt": {"content": "TOP-SECRET\n", "mode": "0600", "owner": "root"}
    },
    "allow_file_write": True,
    "allow_file_delete": False,
    "suspicious_tokens": ["wget", "curl", "nc", "netcat", "python", "perl", "bash", "sh", "rm -rf"],
    "max_cmd_output_len": 4096
}

def load_config():
    # prefer existing SSH config (honeypot_config.json) to reuse settings
    cfg = None
    if os.path.exists(CONFIG_FILE_SSH):
        try:
            with open(CONFIG_FILE_SSH, "r", encoding="utf-8") as f:
                base = json.load(f)
            # map fields we care about; allow telnet-specific overrides if present
            cfg = {}
            cfg["telnet_bind_addr"] = base.get("bind_addr", "0.0.0.0")
            # prefer telnet_port if present, else fallback to bind_port or default
            cfg["telnet_port"] = int(base.get("telnet_port", base.get("bind_port", 2323)))
            cfg["telnet_banner"] = base.get("telnet_banner", f"Welcome to {base.get('ssh_banner_version','Telnet Honeypot')}\r\n")
            cfg["prompt"] = base.get("prompt", "honeypot> ")
            cfg["default_user"] = base.get("default_user", "root")
            cfg["fake_files"] = base.get("fake_files", {})
            cfg["allow_file_write"] = base.get("allow_file_write", True)
            cfg["allow_file_delete"] = base.get("allow_file_delete", False)
            cfg["suspicious_tokens"] = base.get("suspicious_tokens", DEFAULT_CONFIG["suspicious_tokens"])
            cfg["max_cmd_output_len"] = base.get("max_cmd_output_len", DEFAULT_CONFIG["max_cmd_output_len"])
            return cfg
        except Exception as e:
            print("[!] Failed to load", CONFIG_FILE_SSH, ":", e)
    # fallback: alt config file or defaults
    if os.path.exists(ALT_CONFIG_FILE):
        try:
            with open(ALT_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print("[!] Failed to load", ALT_CONFIG_FILE, ":", e)
    # write default alt config for user convenience
    with open(ALT_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
    print(f"[*] No SSH config found; wrote default {ALT_CONFIG_FILE}. Edit it to customize.")
    return DEFAULT_CONFIG.copy()

CONFIG = load_config()

# ensure CSV header
if not os.path.exists(CSV_LOG):
    with open(CSV_LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "client_ip", "client_port", "event", "username", "session_id"])

# try to load fake_commands (prefer modules)
FAKE_CMDS = None
def import_fake_commands():
    global FAKE_CMDS
    mod_path = os.path.join(MODULES_DIR, "fake_commands.py")
    if os.path.exists(mod_path):
        try:
            spec = importlib.util.spec_from_file_location("modules.fake_commands", mod_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            print("[*] Loaded fake_commands from modules/fake_commands.py")
            FAKE_CMDS = mod
            return
        except Exception as e:
            print("[!] Failed to import modules/fake_commands.py:", e)
    # try root fake_commands.py
    if os.path.exists("fake_commands.py"):
        try:
            spec = importlib.util.spec_from_file_location("fake_commands", "fake_commands.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            print("[*] Loaded fake_commands from ./fake_commands.py")
            FAKE_CMDS = mod
            return
        except Exception as e:
            print("[!] Failed to import ./fake_commands.py:", e)
    print("[!] No fake_commands found; using internal simple handlers")
import_fake_commands()

# logging helpers
def log_auth(client_addr, event, username, session_id):
    ts = datetime.utcnow().isoformat() + "Z"
    cip, cport = client_addr
    with open(CSV_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([ts, cip, cport, event, username, session_id])

def append_session_log(session_dir, filename, data):
    path = os.path.join(session_dir, filename)
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)

# Session object
class Session:
    def __init__(self, client_addr, session_dir):
        self.client_addr = client_addr
        self.session_dir = session_dir
        self.start_time = datetime.utcnow().isoformat() + "Z"
        self.cwd = "/root"
        self.username = CONFIG.get("default_user", "root")
        self.history = []
        # structured fake_files copy
        raw = CONFIG.get("fake_files", {}) or {}
        self.fake_files = {}
        for path, val in raw.items():
            if isinstance(val, dict):
                self.fake_files[path] = {
                    "content": val.get("content", ""),
                    "mode": val.get("mode", "0644"),
                    "owner": val.get("owner", CONFIG.get("default_user", "root"))
                }
            else:
                self.fake_files[path] = {"content": str(val), "mode": "0644", "owner": CONFIG.get("default_user", "root")}
        self.allow_file_write = CONFIG.get("allow_file_write", True)
        self.allow_file_delete = CONFIG.get("allow_file_delete", False)

# minimal builtin fallback command processor (only used if FAKE_CMDS not available)
def builtin_fake_response(cmd, session: Session):
    if not cmd or cmd.strip() == "":
        return ""
    lc = cmd.lower().strip()
    # quick matches
    if lc == "whoami":
        return session.username
    if lc == "pwd":
        return session.cwd
    if lc.startswith("ls"):
        # naive listing: show file basenames under cwd
        out = []
        for p in session.fake_files:
            if p.startswith(session.cwd.rstrip("/") + "/") or p == session.cwd:
                out.append(os.path.basename(p))
        return "  ".join(sorted(set(out)))
    if lc.startswith("cat "):
        path = cmd.split(None,1)[1]
        if not path.startswith("/"):
            path = (session.cwd.rstrip("/") + "/" + path).replace("//","/")
        meta = session.fake_files.get(path)
        if not meta:
            return f"cat: {path}: No such file or directory"
        return meta.get("content","")
    # suspicious tokens
    if any(tok in lc for tok in CONFIG.get("suspicious_tokens", [])):
        return f"sh: {cmd}: command not found"
    return f"Executed: {cmd}"

# call into FAKE_CMDS.handle_command if present
def handle_command(cmd, session):
    cmd = (cmd or "").strip()
    if FAKE_CMDS and hasattr(FAKE_CMDS, "handle_command"):
        try:
            res = FAKE_CMDS.handle_command(cmd, session)
            if res is not None:
                return res
        except Exception as e:
            append_session_log(session.session_dir, "errors.log", f"[{datetime.utcnow().isoformat()}] fake_commands error: {e}\n")
    return builtin_fake_response(cmd, session)

# server worker for each connection
def client_worker(conn_sock, client_addr, session_id):
    session_dir = os.path.join(LOG_DIR, f"session_{session_id}")
    os.makedirs(session_dir, exist_ok=True)
    session = Session(client_addr, session_dir)

    append_session_log(session_dir, "meta.json", json.dumps({
        "client_addr": client_addr,
        "start_time": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id
    }, ensure_ascii=False) + "\n")

    # record initial connection
    log_auth(client_addr, "connection", "", session_id)

    try:
        conn_sock.settimeout(120)
        # send banner + prompt on new line
        banner = CONFIG.get("telnet_banner") or CONFIG.get("ssh_banner_version", "Telnet Honeypot\r\n")
        try:
            conn_sock.sendall(banner.encode("utf-8", errors="ignore"))
        except Exception:
            # client disconnected quickly
            raise

        # very simple telnet interaction: read line by line
        buffer = ""
        prompt = CONFIG.get("prompt", "honeypot> ")
        conn_sock.sendall(prompt.encode("utf-8", errors="ignore"))

        while True:
            try:
                data = conn_sock.recv(2048)
            except (ConnectionResetError, BrokenPipeError):
                raise
            if not data:
                break
            # filter basic telnet IAC sequences (we'll ignore options)
            try:
                s = data.decode("utf-8", errors="ignore")
            except Exception:
                s = ""
            # strip common telnet control sequences (IAC)
            s = re.sub(r'(\xff[\xfb-\xff].?)', '', s)
            for ch in s:
                if ch in ("\r", "\n"):
                    cmd = buffer.strip()
                    ts = datetime.utcnow().isoformat() + "Z"
                    append_session_log(session_dir, "commands.log", f"{ts} CMD: {cmd}\n")
                    session.history.append(cmd)
                    out = ""
                    try:
                        out = handle_command(cmd, session) or ""
                    except Exception as e:
                        out = f"Error executing command: {e}"
                    append_session_log(session_dir, "session.log", f"{ts} RESP: {out}\n")

                    # send newline + output + prompt
                    try:
                        conn_sock.sendall(b"\r\n")
                        if out:
                            maxlen = CONFIG.get("max_cmd_output_len", 4096)
                            if len(out) > maxlen:
                                out = out[:maxlen] + "\n...[truncated]"
                            conn_sock.sendall(out.encode("utf-8", errors="ignore"))
                            conn_sock.sendall(b"\r\n")
                        conn_sock.sendall(prompt.encode("utf-8", errors="ignore"))
                    except Exception:
                        raise
                    buffer = ""
                elif ch in ("\x08", "\x7f"):
                    # backspace handling
                    buffer = buffer[:-1]
                    try:
                        conn_sock.sendall(b"\b \b")
                    except Exception:
                        pass
                else:
                    # printable accumulation
                    if ch.isprintable():
                        buffer += ch
                        try:
                            conn_sock.sendall(ch.encode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                    else:
                        # ignore others
                        pass

    except (ConnectionResetError, BrokenPipeError) as e:
        append_session_log(session_dir, "errors.log", f"[{datetime.utcnow().isoformat()}] Peer reset: {e}\n")
    except Exception as e:
        append_session_log(session_dir, "errors.log", f"[{datetime.utcnow().isoformat()}] Exception: {e}\n")
    finally:
        try:
            conn_sock.close()
        except Exception:
            pass
        append_session_log(session_dir, "meta.json", json.dumps({
            "end_time": datetime.utcnow().isoformat() + "Z"
        }, ensure_ascii=False) + "\n")

# server loop
def server_telnet_loop():
    bind_addr = CONFIG.get("telnet_bind_addr", "0.0.0.0")
    bind_port = int(CONFIG.get("telnet_port", 2323))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_addr, bind_port))
    except OSError as e:
        print("Fatal error:", e)
        sys.exit(1)
    sock.listen(100)
    print(f"[*] Telnet honeypot listening on {bind_addr}:{bind_port}")
    session_counter = 0
    while True:
        try:
            client_sock, client_addr = sock.accept()
            session_counter += 1
            session_id = int(time.time() * 1000) + session_counter
            print(f"[+] Incoming connection from {client_addr}, session {session_id}")
            t = threading.Thread(target=client_worker, args=(client_sock, client_addr, session_id), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("[*] Shutting down.")
            try:
                sock.close()
            except Exception:
                pass
            break
        except Exception as e:
            print("[!] Accept loop exception:", e)
            continue

if __name__ == "__main__":
    server_telnet_loop()

