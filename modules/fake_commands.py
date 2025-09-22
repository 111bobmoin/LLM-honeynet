# fake_commands.py
"""
Fake command handler module (context-aware).
Provides handle_command(cmd: str, session: Session) -> Optional[str]

Session is expected to have:
- fake_files: dict mapping absolute path -> { "content": str, "mode": "0644", "owner": "root" }
- cwd: current working dir (string)
- username: active username
- session_dir: path for logs
- other attrs (start_time, etc.)

This module implements:
- ls, ls -l
- cat
- chmod (numeric like 600 or symbolic simple ugo)
- touch
- rm (will respect session.allow_file_delete via CONFIG in main)
- echo "..." > file
- basic detection of suspicious tokens -> "command not found"
"""

import os
import re
from datetime import datetime

# helper: prettify mode bits (e.g. "0644" -> "-rw-r--r--")
def mode_to_rwx(mode_str):
    try:
        mode_int = int(mode_str, 8)
    except Exception:
        mode_int = 0o644
    perms = []
    for who in (6, 3, 0):  # user, group, other (bits shift)
        trip = (mode_int >> who) & 0o7
        perms.append('r' if trip & 4 else '-')
        perms.append('w' if trip & 2 else '-')
        perms.append('x' if trip & 1 else '-')
    return "-" + "".join(perms)

def ensure_structured_files(session):
    """Convert session.fake_files entries that are plain strings into structured dicts."""
    new = {}
    for path, val in list(session.fake_files.items()):
        if isinstance(val, dict):
            new[path] = val
        else:
            # plain string -> content
            new[path] = {"content": str(val), "mode": "0644", "owner": session.username}
    session.fake_files = new

def normpath(session, path):
    if not path:
        return session.cwd
    if not path.startswith("/"):
        return os.path.normpath(os.path.join(session.cwd, path))
    return os.path.normpath(path)

def file_exists(session, path):
    return path in session.fake_files

def get_file(session, path):
    return session.fake_files.get(path)

def write_file(session, path, content):
    session.fake_files[path] = {
        "content": content,
        "mode": session.fake_files.get(path, {}).get("mode", "0644"),
        "owner": session.fake_files.get(path, {}).get("owner", session.username)
    }
    append_session_log(session, f"[{datetime.utcnow().isoformat()}] write {path}\n")

def append_session_log(session, text):
    # lightweight logging, append to session.log
    try:
        p = session.session_dir
        with open(p + "/session.log", "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass

def can_read(session, path):
    """Very simple permission model: if owner==session.username -> check user read bit; else check other read bit."""
    meta = get_file(session, path)
    if not meta:
        return False
    mode = meta.get("mode", "0644")
    try:
        m = int(mode, 8)
    except Exception:
        m = 0o644
    # user read bit
    if meta.get("owner") == session.username:
        return bool(m & 0o400)
    return bool(m & 0o004)

def can_write(session, path):
    meta = get_file(session, path)
    if not meta:
        # assume allowed to create if config allows
        return True
    mode = meta.get("mode", "0644")
    try:
        m = int(mode, 8)
    except Exception:
        m = 0o644
    if meta.get("owner") == session.username:
        return bool(m & 0o200)
    return bool(m & 0o002)

# main handler exported
def handle_command(cmd, session):
    """
    Return a string response for cmd, or None if this module does not handle it.
    """
    if cmd is None:
        return None
    cmd = cmd.strip()
    if cmd == "":
        return ""

    # ensure file structure
    ensure_structured_files(session)

    lc = cmd.lower()

    # Basic suspicious tokens (let main or config handle more complex lists)
    suspicious = ("nc ", "netcat", "wget", "curl", "bash ", "python ", "perl ")
    if any(tok in lc for tok in suspicious):
        # pretend not found
        return f"bash: {cmd}: command not found"

    # parse tokens (simple)
    tokens = re.findall(r'''(?:[^\s"']+|"(?:\\.|[^"])*"|'(?:\\.|[^'])*')+''', cmd)

    # ls and ls -l
    if tokens and tokens[0] in ("ls", "dir"):
        longfmt = "-l" in tokens or tokens.count("-l") > 0
        # choose target: last token if not option
        target = session.cwd
        for t in tokens[1:]:
            if not t.startswith("-"):
                target = normpath(session, t)
                break
        # gather entries under target
        entries = set()
        # if path itself is a file, show file
        if file_exists(session, target):
            base = os.path.basename(target)
            entries.add(base)
        else:
            # list children: any path that starts with target + '/'
            prefix = target.rstrip("/") + "/"
            for p in session.fake_files.keys():
                if p.startswith(prefix):
                    remainder = p[len(prefix):].split("/")[0]
                    entries.add(remainder)
        if not entries:
            return "" if not longfmt else ""

        out_lines = []
        for e in sorted(entries):
            p = target
            if p.endswith("/"):
                p = p + e
            elif file_exists(session, target):
                p = target  # listed itself
            else:
                p = os.path.normpath(os.path.join(target, e))
            meta = get_file(session, p)
            if meta:
                if longfmt:
                    mode = mode_to_rwx(meta.get("mode", "0644"))
                    owner = meta.get("owner", session.username)
                    size = len(meta.get("content", ""))
                    out_lines.append(f"{mode} 1 {owner} {owner} {size} {e}")
                else:
                    out_lines.append(e)
            else:
                # directory stub
                if longfmt:
                    out_lines.append(f"drwxr-xr-x 1 root root 4096 {e}")
                else:
                    out_lines.append(e)
        return "\n".join(out_lines)

    # cat
    if tokens and tokens[0] == "cat":
        if len(tokens) < 2:
            return ""
        path = normpath(session, tokens[1])
        meta = get_file(session, path)
        if not meta:
            return f"cat: {tokens[1]}: No such file or directory"
        if not can_read(session, path):
            return f"cat: {tokens[1]}: Permission denied"
        return meta.get("content", "")

    # chmod (support numeric only e.g. chmod 600 file)
    if tokens and tokens[0] == "chmod":
        if len(tokens) < 3:
            return "chmod: missing operand"
        mode_token = tokens[1]
        filepath = normpath(session, tokens[2])
        meta = get_file(session, filepath)
        if not meta:
            return f"chmod: cannot access '{tokens[2]}': No such file or directory"
        # allow only numeric perms like 600 or 0644
        m = mode_token
        if re.match(r"^[0-7]{3,4}$", m):
            # normalize to 4-digit with leading 0
            if len(m) == 3:
                m = "0" + m
            session.fake_files[filepath]["mode"] = m
            append_session_log(session, f"[{datetime.utcnow().isoformat()}] chmod {m} {filepath}\n")
            return ""
        else:
            return f"chmod: invalid mode: '{mode_token}'"

    # touch
    if tokens and tokens[0] == "touch":
        if len(tokens) < 2:
            return ""
        path = normpath(session, tokens[1])
        if not file_exists(session, path):
            write_file(session, path, "")
        # update mtime: just log
        append_session_log(session, f"[{datetime.utcnow().isoformat()}] touch {path}\n")
        return ""

    # rm
    if tokens and tokens[0] == "rm":
        if len(tokens) < 2:
            return "rm: missing operand"
        path = normpath(session, tokens[1])
        if not file_exists(session, path):
            return f"rm: cannot remove '{tokens[1]}': No such file or directory"
        # consult session allow flag (main script stored this in CONFIG originally - we expect session has attr or fallback)
        allow = getattr(session, "allow_file_delete", False)
        if allow:
            try:
                del session.fake_files[path]
                append_session_log(session, f"[{datetime.utcnow().isoformat()}] rm {path}\n")
                return ""
            except KeyError:
                return f"rm: cannot remove '{tokens[1]}': No such file or directory"
        else:
            return f"rm: cannot remove '{tokens[1]}': Operation not permitted"

    # echo "text" > file
    m = re.match(r'^echo\s+(?P<quoted>["\'].*?["\']|[^>]+)\s*>\s*(?P<file>.+)$', cmd)
    if m:
        payload = m.group("quoted").strip()
        if (payload.startswith('"') and payload.endswith('"')) or (payload.startswith("'") and payload.endswith("'")):
            payload = payload[1:-1]
        path = normpath(session, m.group("file").strip())
        # write file (respect can_write)
        if can_write(session, path):
            write_file(session, path, payload + ("\n" if not payload.endswith("\n") else ""))
            return ""
        else:
            return f"bash: {cmd}: Permission denied"

    # default: not handled by this module -> return None to let others handle
    return None

