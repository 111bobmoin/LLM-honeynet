from __future__ import annotations

import asyncio
import contextlib
from typing import Any, Dict, Iterable, Optional, Tuple

from ..base import BaseService
from ..filesystem import FakeFilesystem, FilesystemError, NodeNotFound


class TelnetService(BaseService):
    name = "telnet"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        banner = self.config.get("banner", "")
        login_prompt = self.config.get("login_prompt", "login: ")
        password_prompt = self.config.get("password_prompt", "Password: ")
        shell_prompt = self.config.get("shell_prompt", "$ ")
        motd: Iterable[str] = self.config.get("motd", [])
        fake_commands: Dict[str, str] = self.config.get("fake_commands", {})
        users: Dict[str, Dict[str, Any]] = self.config.get("users", {})
        max_attempts = int(self.config.get("max_attempts", 3))

        try:
            if banner:
                writer.write((banner + "\r\n").encode())
                await writer.drain()

            for _ in range(max_attempts):
                username = await self.prompt(reader, writer, login_prompt)
                password = await self.prompt(reader, writer, password_prompt, echo=False)
                success = username in users and password in users[username].get("passwords", [])
                self.log_event(
                    "login_attempt",
                    client=str(peer),
                    protocol="telnet",
                    username=username,
                    password=password,
                    success=success,
                )
                if success:
                    for line in motd:
                        writer.write((line + "\r\n").encode())
                    await writer.drain()
                    home = self.resolve_home(users[username].get("home", "/"))
                    await self.shell_session(reader, writer, shell_prompt, fake_commands, username=username, home=home)
                    return
                failure_msg = self.config.get("failure_message", "Login incorrect")
                writer.write((failure_msg + "\r\n").encode())
                await writer.drain()

            writer.write(b"Connection closed by foreign host.\r\n")
            await writer.drain()
        except Exception as exc:  # noqa: BLE001
            self.log_event("error", error=str(exc), client=str(peer))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def prompt(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, message: str, echo: bool = True) -> str:
        writer.write(message.encode())
        await writer.drain()
        data = await reader.readline()
        if not echo:
            writer.write(b"\r\n")
            await writer.drain()
        return data.decode("utf-8", "ignore").strip()

    async def shell_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        prompt: str,
        fake_commands: Dict[str, str],
        username: str,
        home: str,
    ) -> None:
        filesystem: Optional[FakeFilesystem] = self.filesystem
        cwd = home
        while True:
            prompt_label = prompt.replace("~", cwd if cwd != home else "~")
            writer.write(prompt_label.encode())
            await writer.drain()
            data = await reader.readline()
            if not data:
                return
            command = data.decode("utf-8", "ignore").strip()
            if command.lower() in {"exit", "quit", "logout"}:
                writer.write(b"logout\r\n")
                await writer.drain()
                return
            if command == "":
                continue
            response = None
            if command in fake_commands:
                response = fake_commands[command]
            elif filesystem:
                response, cwd = self.execute_filesystem_command(filesystem, command, cwd, home, username)
            if response is None:
                response = self.config.get("unknown_command", "bash: command not found")
            if response:
                writer.write((response + "\r\n").encode())
            await writer.drain()
            self.log_event("command", username=username, command=command, response=(response or "")[:120])

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
                    return (f"cd: {target}: Not a directory", cwd)
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
            return (f"{cmd}: {exc}", cwd)
        except NodeNotFound:
            return (f"{cmd}: No such file or directory", cwd)
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
