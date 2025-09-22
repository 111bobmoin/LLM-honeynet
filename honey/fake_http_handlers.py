# fake_http_handlers.py
"""
Core fake HTTP handlers for the honeypot.

Implements:
- GET/HEAD/POST/PUT/DELETE semantics against a per-session fake_files store
- Path mapping: if file exists in session['fake_files'] -> return content and mime
- Routes from config: quick responses for configured routes (e.g. /health)
- Write semantics:
    - PUT/POST to path: create/update content if session.allow_file_write True
    - DELETE to path: remove if session.allow_file_delete True
- Simple permission model using mode (owner + octal perms): owner can read/write if bits allow,
  others only if 'other' bits allow.
"""

import os
import re
from datetime import datetime
from urllib.parse import unquote_plus

from http_honeypot import CONFIG, append_session_log  # import helper

def norm_path(path):
    if not path:
        return "/"
    p = unquote_plus(path.split("?")[0])
    if not p.startswith("/"):
        p = "/" + p
    return os.path.normpath(p)

def can_read(session, path):
    meta = session["fake_files"].get(path)
    if not meta:
        return False
    mode = meta.get("mode", "0644")
    try:
        m = int(mode, 8)
    except Exception:
        m = 0o644
    if meta.get("owner") == session.get("username"):
        return bool(m & 0o400)
    return bool(m & 0o004)

def can_write(session, path):
    meta = session["fake_files"].get(path)
    if not meta:
        # creating new files allowed if session.allow_file_write
        return session.get("allow_file_write", True)
    mode = meta.get("mode", "0644")
    try:
        m = int(mode, 8)
    except Exception:
        m = 0o644
    if meta.get("owner") == session.get("username"):
        return bool(m & 0o200)
    return bool(m & 0o002)

def handle_request(method, path, headers, body, session):
    """
    Return a dict: {"status":int, "headers":{}, "body":bytes_or_str}
    """
    p = norm_path(path)
    # 1) quick route config
    routes = CONFIG.get("routes", {})
    for route_prefix, info in routes.items():
        if p == route_prefix or p.startswith(route_prefix + "/"):
            status = info.get("status", 200)
            body = info.get("body", "")
            return {"status": status, "headers": {"Content-Type":"text/plain"}, "body": body}

    # 2) if exact file exists
    fmeta = session["fake_files"].get(p)
    if method in ("GET","HEAD"):
        if fmeta:
            if not can_read(session, p):
                return {"status": 403, "headers":{"Content-Type":"text/plain"}, "body":"Forbidden"}
            body = fmeta.get("content","")
            mime = fmeta.get("mime","text/plain")
            return {"status": 200, "headers":{"Content-Type":mime}, "body": body}
        else:
            # try index fallback for directories
            idx = p.rstrip("/") + "/index.html"
            if idx in session["fake_files"]:
                if not can_read(session, idx):
                    return {"status":403, "headers":{"Content-Type":"text/plain"}, "body":"Forbidden"}
                return {"status":200, "headers":{"Content-Type": session["fake_files"][idx].get("mime","text/html")}, "body": session["fake_files"][idx].get("content","")}
            return {"status":404, "headers":{"Content-Type":"text/plain"}, "body":"Not Found"}

    if method in ("PUT","POST"):
        # write/replace resource
        if not session.get("allow_file_write", True):
            return {"status":403, "headers":{"Content-Type":"text/plain"}, "body":"Write not allowed"}
        # cap size
        maxlen = CONFIG.get("max_body_len", 65536)
        b = body or b""
        if isinstance(b, bytes):
            if len(b) > maxlen:
                b = b[:maxlen]
            content = b.decode("utf-8", errors="ignore")
        else:
            content = str(b)
        # create/overwrite
        session["fake_files"][p] = {"content": content, "mime": headers.get("Content-Type","text/plain"), "mode": "0644", "owner": session.get("username")}
        append_session_log(session, "session.log", f"[{datetime.utcnow().isoformat()}] WRITE {p} ({len(content)} bytes)\n")
        return {"status":201, "headers":{"Content-Type":"text/plain"}, "body":"Created"}

    if method == "DELETE":
        if not session.get("allow_file_delete", False):
            return {"status":403, "headers":{"Content-Type":"text/plain"}, "body":"Delete not allowed"}
        if p in session["fake_files"]:
            del session["fake_files"][p]
            append_session_log(session, "session.log", f"[{datetime.utcnow().isoformat()}] DELETE {p}\n")
            return {"status":204, "headers":{}, "body":""}
        else:
            return {"status":404, "headers":{"Content-Type":"text/plain"}, "body":"Not Found"}

    # fallback
    return {"status":405, "headers":{"Content-Type":"text/plain"}, "body":"Method Not Allowed"}

