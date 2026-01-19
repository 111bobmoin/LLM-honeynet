from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from ..base import BaseService
from ..filesystem import FakeFilesystem, FilesystemError, NodeNotFound

try:  # pragma: no cover - optional dependency
    import asyncssh
except Exception:  # noqa: BLE001
    asyncssh = None  # type: ignore[assignment]


def userspace_default_response(command: str) -> str:
    return f"bash: {command}: command not found"


class HoneySSHServer(asyncssh.SSHServer):  # type: ignore[misc]
    def __init__(self, service: "SshService"):
        self.service = service
        self._conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:  # type: ignore[override]
        self._conn = conn
        peer = conn.get_extra_info("peername")
        client_version = conn.get_extra_info("client_version", "")
        self.service.log_event(
            "handshake",
            client=str(peer),
            client_version=client_version,
        )

    def begin_auth(self, username: str) -> bool:  # type: ignore[override]
        return True

    def password_auth_supported(self) -> bool:  # type: ignore[override]
        return True

    def validate_password(self, username: str, password: str) -> bool:  # type: ignore[override]
        users = self.service.config.get("users", {})
        conn = self._conn
        peer = conn.get_extra_info("peername") if conn else None
        success = username in users and password in users[username].get("passwords", [])
        self.service.log_event(
            "login_attempt",
            client=str(peer),
            protocol="ssh",
            username=username,
            password=password,
            success=success,
        )
        return success

    def session_requested(self) -> "HoneySSHSession":  # type: ignore[override]
        conn = self._conn
        username = conn.get_extra_info("username") if conn else ""
        return HoneySSHSession(self.service, username or "")


class HoneySSHSession(asyncssh.SSHServerSession):  # type: ignore[misc]
    def __init__(self, service: "SshService", username: str):
        self.service = service
        self.username = username
        self.channel: Optional[asyncssh.SSHServerChannel] = None  # type: ignore[name-defined]
        self._buffer = ""
        self.cwd = "/"
        self.home = "/"

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:  # type: ignore[override]
        self.channel = chan
        self.cwd = self.service.resolve_home(self.service.user_home(self.username))
        self.home = self.cwd
        motd = self.service.user_motd(self.username)
        for line in motd:
            chan.write(line + "\r\n")

    def session_started(self) -> None:  # type: ignore[override]
        if self.channel:
            try:
                self.channel.set_line_mode()
                self.channel.set_echo(True)
            except Exception:
                pass
        self._write_prompt()

    def shell_requested(self) -> bool:  # type: ignore[override]
        return True

    def pty_requested(self, term: str, width: int, height: int, *rest: object) -> bool:  # type: ignore[override]
        if self.channel:
            try:
                self.channel.set_line_mode()
                self.channel.set_echo(True)
            except Exception:
                pass
            try:
                self.channel.set_terminal_type(term)
            except Exception:
                pass
        return True

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:  # type: ignore[override]
        self._buffer += data
        while "\r" in self._buffer or "\n" in self._buffer:
            if "\n" in self._buffer:
                sep = "\n"
            else:
                sep = "\r"
            line, self._buffer = self._buffer.split(sep, 1)
            line = line.rstrip("\r")
            self._handle_command(line)

    def eof_received(self) -> bool:  # type: ignore[override]
        if self.channel:
            self.channel.write("logout\n")
            self.channel.exit(0)
        return True

    def connection_lost(self, exc: Optional[BaseException]) -> None:  # type: ignore[override]
        error = str(exc) if exc else ""
        self.service.log_event("session_closed", username=self.username, error=error)

    def _handle_command(self, command: str) -> None:
        if self.channel is None:
            return
        command = command.strip()
        if command in {"exit", "logout", "quit"}:
            self.channel.write("logout\n")
            self.channel.exit(0)
            return
        if command == "":
            self._write_prompt()
            return

        try:
            response = None
            fake_commands: Dict[str, str] = self.service.config.get("fake_commands", {})
            filesystem: Optional[FakeFilesystem] = self.service.filesystem  # type: ignore[attr-defined]
            if command in fake_commands:
                response = fake_commands[command]
            elif filesystem:
                response, self.cwd = self.service.execute_filesystem_command(
                    filesystem,
                    command,
                    self.cwd,
                    self.home,
                    self.username,
                )
            if response is None:
                response = userspace_default_response(command)
            if response and self.channel:
                self.channel.write(response + "\r\n")
            self.service.log_event("command", username=self.username, command=command, response=(response or "")[:120])
        except Exception as exc:  # noqa: BLE001
            if self.channel:
                self.channel.write(f"Internal error: {exc}\r\n")
            self.service.log_event("error", error=str(exc), username=self.username)
        self._write_prompt()

    def _write_prompt(self) -> None:
        if self.channel is None:
            return
        prompt = self.service.config.get("shell_prompt", "root@honeypot:~# ")
        label = prompt.replace("~", self.cwd if self.cwd != self.home else "~")
        self.channel.write(label)


class SshService(BaseService):
    name = "ssh"

    async def start(self) -> None:
        if asyncssh is None:  # type: ignore[truthy-bool]
            raise RuntimeError(
                "asyncssh package is required for SSH honeypot. Install it via 'pip install asyncssh'."
            )
        host_keys = self._ensure_host_keys()
        self.server = await asyncssh.create_server(  # type: ignore[attr-defined]
            lambda: HoneySSHServer(self),
            host=self.host,
            port=self.port,
            server_host_keys=host_keys,
        )
        self.log_event("startup", host=self.host, port=self.port)

    def _ensure_host_keys(self):
        key_paths = self.config.get("host_keys")
        if key_paths:
            resolved = [str(self.resolve_path(path)) for path in key_paths]
            return resolved
        default_path = self.resolve_path("../certs/ssh_host_ed25519")
        if not default_path.exists():
            if asyncssh is None:  # pragma: no cover
                raise RuntimeError("asyncssh is required to generate SSH host keys.")
            default_path.parent.mkdir(parents=True, exist_ok=True)
            key = asyncssh.generate_private_key("ssh-ed25519")  # type: ignore[attr-defined]
            pem_bytes = key.export_private_key()
            if isinstance(pem_bytes, str):
                default_path.write_text(pem_bytes, encoding="utf-8")
            else:
                default_path.write_bytes(pem_bytes)
            os.chmod(default_path, 0o600)
        return [str(default_path)]

    def user_home(self, username: str) -> str:
        users = self.config.get("users", {})
        record = users.get(username, {})
        return record.get("home", "/")

    def user_motd(self, username: str):
        users = self.config.get("users", {})
        record = users.get(username, {})
        return record.get("motd", [])

    def execute_filesystem_command(
        self,
        filesystem: FakeFilesystem,
        command: str,
        cwd: str,
        home: str,
        username: str,
    ) -> Tuple[Optional[str], str]:
        parts = command.split()
        if not parts:
            return ("", cwd)
        cmd = parts[0]
        args = parts[1:]
        try:
            if cmd == "pwd":
                return (cwd, cwd)
            if cmd == "whoami":
                return (username, cwd)
            if cmd == "cd":
                target = args[0] if args else home
                new_cwd = filesystem.normalize(target, cwd=cwd)
                node = filesystem.resolve(new_cwd)
                if not node.is_dir:
                    return (f"bash: cd: {target}: Not a directory", cwd)
                return ("", new_cwd)
            if cmd == "ls":
                detailed = any(flag in ("-l", "-la", "-al") for flag in args)
                include_hidden = any(flag in ("-a", "-la", "-al") for flag in args)
                target = args[-1] if args and not args[-1].startswith("-") else "."
                listing = filesystem.format_ls(target, cwd=cwd, detailed=detailed, include_hidden=include_hidden)
                return (listing if listing else "", cwd)
            if cmd == "cat" and args:
                content = filesystem.read_file(args[0], cwd=cwd)
                return (content, cwd)
        except FilesystemError as exc:
            return (f"bash: {cmd}: {exc}", cwd)
        except NodeNotFound:
            return (f"bash: {cmd}: No such file or directory", cwd)
        return (None, cwd)

    def resolve_home(self, desired: str) -> str:
        filesystem: Optional[FakeFilesystem] = self.filesystem
        if not filesystem:
            return desired
        try:
            resolved = filesystem.normalize(desired, cwd="/")
            node = filesystem.resolve(resolved)
            if node.is_dir:
                return resolved
        except (FilesystemError, NodeNotFound):
            pass
        return "/"
