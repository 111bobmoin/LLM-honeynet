#!/usr/bin/env python3
"""
ssh_honeypot.py (config-driven + external fake_commands + robust handshake)

- 从 honeypot_config.json 读取配置（包含 bind_addr/bind_port、SSH banner、提示符、fake_files 等）
- fake commands 拆分为外部模块 fake_commands.py（优先加载 modules/fake_commands.py）
- 会话级“伪文件系统”带 metadata（content/mode/owner），配合 fake_commands 实现上下文逻辑
- 对端扫描/半开连接更健壮：优雅记录，不打印长栈
- 仍保留 CSV + per-session 日志

依赖：
    pip install paramiko

用法：
    python3 ssh_honeypot.py
"""

import socket
import socket as _socket  # for explicit error catching
import threading
import os
import sys
import time
import csv
import json
import importlib.util
import importlib
import re
from datetime import datetime
import paramiko
from paramiko import RSAKey, ServerInterface, AUTH_SUCCESSFUL, OPEN_SUCCEEDED

# -------------------- 常量与路径 --------------------
HOST_KEY_FILE = "honeypot_host_rsa.key"
LOG_DIR = "honeypot_logs"
CSV_LOG = os.path.join(LOG_DIR, "auth_log.csv")
CONFIG_FILE = "honeypot_config.json"
MODULES_DIR = "modules"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODULES_DIR, exist_ok=True)

# -------------------- 默认配置（首次运行会写入） --------------------
DEFAULT_CONFIG = {
    "bind_addr": "0.0.0.0",
    "bind_port": 2222,

    "ssh_banner_version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "prompt": "honeypot$ ",
    "default_user": "root",

    # 支持两种写法：
    # 1) 简写：path -> "content"
    # 2) 结构化：path -> {"content":"...", "mode":"0644", "owner":"root"}
    "fake_files": {
        "/etc/passwd": {
            "content": "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
            "mode": "0644",
            "owner": "root"
        },
        "/etc/hostname": {"content": "webserver\n", "mode": "0644", "owner": "root"},
        "/root/secret.txt": {"content": "TOP-SECRET\n", "mode": "0600", "owner": "root"},
        "/var/www/html/index.html": {
            "content": "<html><body><h1>Welcome</h1></body></html>\n",
            "mode": "0644",
            "owner": "root"
        },
        "/home/ubuntu/.bash_history": {"content": "", "mode": "0600", "owner": "ubuntu"}
    },

    # 可选：regex 响应（先匹配，匹配到就直接返回）
    "regex_responses": [
        {"pattern": "^whoami$", "response": "root"},
        {"pattern": "^id$", "response": "uid=0(root) gid=0(root) groups=0(root)"}
    ],

    # 给主脚本备用（多数“可疑命令”在 fake_commands 中也会兜底）
    "suspicious_tokens": ["wget", "curl", "nc", "netcat", "python", "perl", "bash", "sh", "ssh", "scp", "rm -rf"],

    "simulate_uname": "Linux webserver 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux",

    # 会话行为开关
    "allow_file_write": True,     # 是否允许 echo "..." > file 等写入
    "allow_file_delete": False,   # 是否允许 rm 真删

    "max_cmd_output_len": 4096
}

# -------------------- 配置加载 --------------------
def load_config(path=CONFIG_FILE):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[*] No config found. Wrote default config to {path}. Edit it and restart to customize.")
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(cfg)
        return merged
    except Exception as e:
        print("[!] Failed to load config, using defaults:", e)
        return DEFAULT_CONFIG.copy()

CONFIG = load_config()

# -------------------- host key --------------------
if not os.path.exists(HOST_KEY_FILE):
    print("[*] Generating host RSA key...")
    key = RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    print("[*] Host key written to", HOST_KEY_FILE)

HOST_KEY = RSAKey(filename=HOST_KEY_FILE)

# -------------------- CSV 头 --------------------
if not os.path.exists(CSV_LOG):
    with open(CSV_LOG, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "client_ip", "client_port", "username", "password", "event", "session_id"])

# -------------------- fake_commands 导入（根目录或 modules/） --------------------
def import_fake_commands():
    """
    优先从 modules/fake_commands.py 导入；否则尝试从根目录 fake_commands.py 导入。
    """
    # 1) modules/fake_commands.py
    mod_path = os.path.join(MODULES_DIR, "fake_commands.py")
    if os.path.exists(mod_path):
        spec = importlib.util.spec_from_file_location("modules.fake_commands", mod_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        print("[*] Loaded fake commands from modules/fake_commands.py")
        return mod

    # 2) 根目录 fake_commands.py
    try:
        import fake_commands as mod  # type: ignore
        print("[*] Loaded fake commands from ./fake_commands.py")
        return mod
    except Exception as e:
        print("[!] Could not import fake_commands:", e)
        return None

FAKE_CMDS = import_fake_commands()

# -------------------- Paramiko 服务器 --------------------
class HoneypotServer(ServerInterface):
    def __init__(self, client_addr, session_id):
        self.event = threading.Event()
        self.client_addr = client_addr
        self.session_id = session_id
        self.auth_username = None
        self.auth_password = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.auth_username = username
        self.auth_password = password
        log_auth(self.client_addr, username, password, "password_auth", self.session_id)
        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

# -------------------- 日志工具 --------------------
def log_auth(client_addr, username, password, event, session_id):
    ts = datetime.utcnow().isoformat() + "Z"
    client_ip, client_port = client_addr
    with open(CSV_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([ts, client_ip, client_port, username, password, event, session_id])

def append_session_log(session_dir, filename, data):
    path = os.path.join(session_dir, filename)
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)

# -------------------- 会话对象 --------------------
class Session:
    def __init__(self, client_addr, session_dir):
        self.client_addr = client_addr
        self.session_dir = session_dir
        self.start_time = datetime.utcnow().isoformat() + "Z"
        self.cwd = "/root"
        self.username = CONFIG.get("default_user", "root")
        self.env = {}
        self.history = []

        # 结构化 fake_files: path -> {"content": str, "mode": "0644", "owner": "root"}
        raw = CONFIG.get("fake_files", {})
        self.fake_files = {}
        for path, val in raw.items():
            if isinstance(val, dict):
                self.fake_files[path] = {
                    "content": val.get("content", ""),
                    "mode": val.get("mode", "0644"),
                    "owner": val.get("owner", CONFIG.get("default_user", "root"))
                }
            else:
                self.fake_files[path] = {
                    "content": str(val),
                    "mode": "0644",
                    "owner": CONFIG.get("default_user", "root")
                }

        # 权限/行为开关供 fake_commands 使用
        self.allow_file_delete = CONFIG.get("allow_file_delete", False)
        self.allow_file_write  = CONFIG.get("allow_file_write", True)

# -------------------- 命令处理 --------------------
def apply_regex_responses(cmd: str):
    """先应用配置中的 regex_responses（如命中，直接返回结果）。"""
    if not cmd:
        return ""
    for rr in CONFIG.get("regex_responses", []):
        flags = 0
        if rr.get("flags") and "IGNORECASE" in rr["flags"]:
            flags |= re.IGNORECASE
        try:
            if re.match(rr["pattern"], cmd, flags):
                return rr.get("response", "")
        except re.error:
            continue
    return None

def fake_command_response(cmd, session: Session):
    """主处理器：先 regex，其次交给 fake_commands；最后兜底。"""
    cmd = (cmd or "").strip()
    if cmd == "":
        return ""

    # 1) regex 响应
    r = apply_regex_responses(cmd)
    if r is not None:
        return r

    # 2) 委派给外部 fake_commands
    if FAKE_CMDS and hasattr(FAKE_CMDS, "handle_command"):
        try:
            res = FAKE_CMDS.handle_command(cmd, session)
            if res is not None:
                return res
        except Exception as e:
            append_session_log(session.session_dir, "errors.log",
                               f"[{datetime.utcnow().isoformat()}] fake_commands error: {e}\n")

    # 3) 最后兜底（简单 echo 或“not found”）
    lc = cmd.lower()
    if any(tok in lc for tok in CONFIG.get("suspicious_tokens", [])):
        return f"bash: {cmd}: command not found"
    return f"Executed: {cmd}"

# -------------------- 客户端处理 --------------------
def handle_client(client_sock, client_addr, session_id):
    session_dir = os.path.join(LOG_DIR, f"session_{session_id}")
    os.makedirs(session_dir, exist_ok=True)

    session = Session(client_addr, session_dir)

    append_session_log(session_dir, "meta.json", json.dumps({
        "client_addr": client_addr,
        "start_time": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id
    }, ensure_ascii=False) + "\n")

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    server = HoneypotServer(client_addr, session_id)

    try:
        transport.start_server(server=server)
    except (paramiko.SSHException, ConnectionResetError, EOFError, _socket.error) as e:
        # 常见于端口扫描/半开连接：优雅记录并返回
        append_session_log(session_dir, "errors.log",
            f"[{datetime.utcnow().isoformat()}] Peer dropped during handshake: {type(e).__name__}: {e}\n")
        try:
            transport.close()
        except Exception:
            pass
        return

    chan = None
    try:
        chan = transport.accept(20)
        if chan is None:
            append_session_log(session_dir, "errors.log",
                               f"[{datetime.utcnow().isoformat()}] No channel.\n")
            transport.close()
            return

        # banner + 提示符
        banner = f"Welcome to {CONFIG.get('ssh_banner_version')}\r\n"
        try:
            chan.send(banner)
        except Exception:
            # 对端可能又断开了
            raise

        append_session_log(session_dir, "session.log",
                           f"[{datetime.utcnow().isoformat()}] Shell opened\r\n")
        chan.send("\r\n" + CONFIG.get("prompt", "honeypot$ "))

        line = ""
        while True:
            data = chan.recv(2048)
            if not data:
                break

            text = data.decode("utf-8", errors="ignore")
            for ch in text:
                if ch in ("\r", "\n"):
                    cmd = line.strip()
                    ts = datetime.utcnow().isoformat() + "Z"
                    append_session_log(session_dir, "commands.log", f"{ts} CMD: {cmd}\n")
                    session.history.append(cmd)

                    try:
                        out = fake_command_response(cmd, session) or ""
                    except Exception as e:
                        out = f"Error executing command: {e}"

                    append_session_log(session_dir, "session.log", f"{ts} RESP: {out}\n")

                    try:
                        chan.send("\r\n")
                        if out:
                            maxlen = CONFIG.get("max_cmd_output_len", 4096)
                            if len(out) > maxlen:
                                out = out[:maxlen] + "\n...[truncated]"
                            chan.send(out + "\r\n")
                        chan.send(CONFIG.get("prompt", "honeypot$ "))
                    except Exception:
                        # 客户端可能在命令执行中断开
                        raise

                    line = ""
                    continue

                if ch in ("\b", "\x7f"):
                    if len(line) > 0:
                        line = line[:-1]
                        try:
                            chan.send("\b \b")
                        except Exception:
                            raise
                    continue

                if ch.isprintable():
                    line += ch
                    try:
                        chan.send(ch)
                    except Exception:
                        raise
                else:
                    # 忽略其他控制字符
                    pass

    except (ConnectionResetError, EOFError, _socket.error) as e:
        append_session_log(session_dir, "errors.log",
            f"[{datetime.utcnow().isoformat()}] Peer reset/closed connection: {type(e).__name__}: {e}\n")
    except Exception as e:
        # 其它异常才算真正的程序问题
        append_session_log(session_dir, "errors.log",
            f"[{datetime.utcnow().isoformat()}] Exception: {e}\n")
    finally:
        if chan:
            try:
                chan.close()
            except Exception:
                pass
        try:
            transport.close()
        except Exception:
            pass
        append_session_log(session_dir, "meta.json", json.dumps({
            "end_time": datetime.utcnow().isoformat() + "Z"
        }, ensure_ascii=False) + "\n")

# -------------------- 监听循环 --------------------
def server_ssh_loop():
    bind_addr = CONFIG.get("bind_addr", "0.0.0.0")
    bind_port = int(CONFIG.get("bind_port", 2222))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_addr, bind_port))
    except OSError as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

    sock.listen(100)
    print(f"[*] SSH honeypot listening on {bind_addr}:{bind_port}")
    session_counter = 0
    while True:
        try:
            client_sock, client_addr = sock.accept()
            session_counter += 1
            session_id = int(time.time() * 1000) + session_counter
            print(f"[+] Incoming connection from {client_addr}, session {session_id}")
            log_auth(client_addr, "", "", "connection", session_id)
            thr = threading.Thread(target=handle_client,
                                   args=(client_sock, client_addr, session_id),
                                   daemon=True)
            thr.start()
        except KeyboardInterrupt:
            print("[*] Shutting down.")
            try:
                sock.close()
            except Exception:
                pass
            break
        except Exception as e:
            print("[!] Exception in accept loop:", e)
            continue

# -------------------- main --------------------
if __name__ == "__main__":
    try:
        server_ssh_loop()
    except Exception as ex:
        print("Fatal error:", ex)
        sys.exit(1)

