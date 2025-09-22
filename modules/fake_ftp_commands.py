# modules/fake_ftp_commands.py
# Command logic for the FTP honeypot.

from datetime import datetime

def _norm_path(cwd, path):
    if not path:
        return cwd
    if not path.startswith("/"):
        path = (cwd.rstrip("/") + "/" + path).replace("//","/")
    parts = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts: parts.pop()
        else:
            parts.append(seg)
    return "/" + "/".join(parts)

def _unix_mode_string(mode="0644", is_dir=False):
    try:
        m = int(mode, 8)
    except Exception:
        m = 0o644
    def bits(val):
        return "".join(["r" if val & 4 else "-", "w" if val & 2 else "-", "x" if val & 1 else "-"])
    s = "d" if is_dir else "-"
    s += bits((m >> 6) & 7) + bits((m >> 3) & 7) + bits(m & 7)
    return s

def _build_list_lines(session, path):
    items = []
    if path in session.fake_files:
        meta = session.fake_files[path]
        size = len(meta.get("content","").encode("utf-8", errors="ignore"))
        perm = _unix_mode_string(meta.get("mode","0644"), is_dir=False)
        name = path.split("/")[-1] or "/"
        items.append(f"{perm} 1 {meta.get('owner','root')} {meta.get('owner','root')} {size:>6} Jan 01 00:00 {name}")
        return items

    prefix = path.rstrip("/") + "/"
    children = set()
    for p in session.fake_files.keys():
        if p.startswith(prefix):
            child = p[len(prefix):].split("/")[0]
            children.add(child)
    for name in sorted(children):
        p = f"{prefix}{name}"
        if p in session.fake_files:
            meta = session.fake_files[p]
            size = len(meta.get("content","").encode("utf-8", errors="ignore"))
            perm = _unix_mode_string(meta.get("mode","0644"), is_dir=False)
        else:
            size = 4096
            perm = _unix_mode_string("0755", is_dir=True)
        items.append(f"{perm} 1 root root {size:>6} Jan 01 00:00 {name}")
    return items

def handle_command(session, cmd, arg, ctx):
    """
    session: FTPSession
    cmd: upper-case command
    arg: raw argument (may be empty)
    ctx: dict with helpers:
        send(str_line), log(fn, text), open_pasv() -> (sock, port),
        set_pasv(sock, (ip,port)), data_send(bytes), data_recv() -> bytes,
        announce_ip() -> str, config -> CONFIG mapping
    Returns:
        None or {"close": True} to end control connection.
    """
    send = ctx["send"]
    log  = ctx["log"]
    cfg  = ctx["config"]

    if cmd == "USER":
        session.last_user = arg or "anonymous"
        send("331 Please specify the password.\r\n")
        return

    if cmd == "PASS":
        # accept any creds
        session.username = session.last_user or cfg.get("default_user","ftp")
        session.logged_in = True
        send("230 Login successful.\r\n")
        return

    if cmd == "SYST":
        send("215 UNIX Type: L8\r\n"); return

    if cmd == "TYPE":
        if (arg or "").upper().startswith("I"):
            session.type_binary = True
            send("200 Switching to Binary mode.\r\n")
        else:
            session.type_binary = False
            send("200 Switching to ASCII mode.\r\n")
        return

    if cmd == "PWD":
        send(f'257 "{session.cwd}" is the current directory\r\n'); return

    if cmd == "CWD":
        newp = _norm_path(session.cwd, arg)
        prefix = newp.rstrip("/") + "/"
        ok = (newp in session.fake_files) or any(p.startswith(prefix) for p in session.fake_files)
        if ok:
            session.cwd = newp if newp else "/"
            send("250 Directory successfully changed.\r\n")
        else:
            send("550 Failed to change directory.\r\n")
        return

    if cmd == "PASV":
        # close old, open new
        session.close_pasv()
        s, port = ctx["open_pasv"]()
        ctx["set_pasv"](s, (ctx["announce_ip"](), port))
        ip = session.pasv_addr[0].split(".")
        p1, p2 = port // 256, port % 256
        send(f"227 Entering Passive Mode ({ip[0]},{ip[1]},{ip[2]},{ip[3]},{p1},{p2}).\r\n")
        return

    if cmd == "LIST":
        if not session.pasv_sock:
            send("425 Use PASV first.\r\n"); return
        target = _norm_path(session.cwd, arg) if arg else session.cwd
        lines = _build_list_lines(session, target)
        send("150 Here comes the directory listing.\r\n")
        payload = ("\r\n".join(lines) + "\r\n").encode("utf-8", errors="ignore")
        ctx["data_send"](payload)
        send("226 Directory send OK.\r\n")
        return

    if cmd == "RETR":
        if not session.pasv_sock:
            send("425 Use PASV first.\r\n"); return
        path = _norm_path(session.cwd, arg)
        meta = session.fake_files.get(path)
        if not meta:
            send("550 Failed to open file.\r\n"); return
        content = meta.get("content","").encode("utf-8", errors="ignore")
        send("150 Opening data connection.\r\n")
        ctx["data_send"](content)
        send("226 Transfer complete.\r\n")
        return

    if cmd == "STOR":
        if not cfg.get("allow_file_write", True):
            send("553 Permission denied.\r\n"); return
        if not session.pasv_sock:
            send("425 Use PASV first.\r\n"); return
        path = _norm_path(session.cwd, arg)
        send("150 Ok to send data.\r\n")
        blob = ctx["data_recv"]()
        text = blob.decode("utf-8", errors="ignore")
        session.fake_files[path] = {
            "content": text, "mode":"0644", "owner": session.username, "mime": "application/octet-stream"
        }
        log("session.log", f"[{datetime.utcnow().isoformat()}] STOR {path} ({len(text)} bytes)\n")
        send("226 Transfer complete.\r\n")
        return

    if cmd == "DELE":
        path = _norm_path(session.cwd, arg)
        if not cfg.get("allow_file_delete", False):
            send("450 Delete operation not permitted.\r\n"); return
        if path in session.fake_files:
            del session.fake_files[path]
            log("session.log", f"[{datetime.utcnow().isoformat()}] DELE {path}\n")
            send("250 Delete operation successful.\r\n")
        else:
            send("550 File not found.\r\n")
        return

    if cmd == "QUIT":
        send("221 Goodbye.\r\n")
        return {"close": True}

    # common but not implemented
    if cmd in ("FEAT","OPTS","NOOP","ALLO","REST","APPE","RNFR","RNTO","SIZE","MDTM"):
        send("502 Command not implemented.\r\n"); return

    # default
    send("500 Unknown command.\r\n")
    return

