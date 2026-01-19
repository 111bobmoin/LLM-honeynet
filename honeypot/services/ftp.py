from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

from ..base import BaseService
from ..filesystem import FakeFilesystem, FilesystemError, NodeNotFound


@dataclass
class _PassiveChannel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


@dataclass
class _DataChannel:
    mode: str  # "active" or "passive"
    payload: Any


class FtpService(BaseService):
    name = "ftp"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        users: Dict[str, Dict[str, Any]] = self.config.get("users", {})
        banner = self.config.get("banner", "220 (vsFTPd 3.0.3)")
        writer.write((banner + "\r\n").encode())
        await writer.drain()

        username: Optional[str] = None
        authed = False
        filesystem: Optional[FakeFilesystem] = self.filesystem
        cwd = self.resolve_home(self.config.get("default_home", "/"))
        home = cwd
        active_target: Optional[Tuple[str, int]] = None
        passive_server: Optional[asyncio.AbstractServer] = None
        passive_future: Optional[asyncio.Future] = None

        async def close_passive() -> None:
            nonlocal passive_server, passive_future
            if passive_server:
                passive_server.close()
                with contextlib.suppress(Exception):
                    await passive_server.wait_closed()
            passive_server = None
            passive_future = None

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", "ignore").rstrip("\r\n")
                if " " in decoded:
                    command, arg = decoded.split(" ", 1)
                else:
                    command, arg = decoded, ""
                command_upper = command.upper()

                if command_upper == "USER":
                    username = arg
                    prompt = users.get(username, {}).get("user_prompt", "Please specify the password.")
                    writer.write(f"331 {prompt}\r\n".encode())
                    await writer.drain()
                    continue

                if command_upper == "PASS":
                    password = arg
                    success = username in users and password in users[username].get("passwords", [])
                    self.log_event(
                        "login_attempt",
                        client=str(peer),
                        protocol="ftp",
                        username=username,
                        password=password,
                        success=success,
                    )
                    if success and username:
                        authed = True
                        welcome = users[username].get("welcome", "230 Login successful.")
                        writer.write((welcome + "\r\n").encode())
                        home = self.resolve_home(users[username].get("home", self.config.get("default_home", "/")))
                        cwd = home
                        active_target = None
                        await close_passive()
                    else:
                        authed = False
                        writer.write(b"530 Login incorrect.\r\n")
                    await writer.drain()
                    continue

                if not authed and command_upper not in {"USER", "PASS", "QUIT", "NOOP"}:
                    writer.write(b"530 Please login with USER and PASS.\r\n")
                    await writer.drain()
                    continue

                if command_upper == "SYST":
                    writer.write((self.config.get("syst_response", "215 UNIX Type: L8") + "\r\n").encode())
                    await writer.drain()
                    continue

                if command_upper in {"PWD", "XPWD"}:
                    writer.write((f'257 "{cwd}" is the current directory\r\n').encode())
                    self.log_event("command", client=str(peer), username=username, command="PWD", cwd=cwd)
                    await writer.drain()
                    continue

                if command_upper == "TYPE":
                    mode = arg.upper() if arg else "I"
                    if mode in {"I", "A"}:
                        writer.write(b"200 Switching to Binary mode.\r\n")
                    else:
                        writer.write(b"504 Command not implemented for that parameter.\r\n")
                    await writer.drain()
                    continue

                if command_upper == "FEAT":
                    features: Iterable[str] = self.config.get(
                        "features",
                        ["211-Features:", " UTF8", " SIZE", "211 End"],
                    )
                    for entry in features:
                        writer.write((entry + "\r\n").encode())
                    await writer.drain()
                    continue

                if command_upper == "PORT":
                    parts = arg.split(",")
                    if len(parts) == 6:
                        host = ".".join(parts[:4])
                        try:
                            port = (int(parts[4]) << 8) + int(parts[5])
                        except ValueError:
                            port = 0
                        if self._test_active_address(host, port):
                            active_target = (host, port)
                            writer.write(b"200 PORT command successful.\r\n")
                            self.log_event("command", client=str(peer), username=username, command=f"PORT {arg}", cwd=cwd)
                            await close_passive()
                        else:
                            writer.write(b"501 Syntax error in parameters or arguments.\r\n")
                    else:
                        writer.write(b"501 Syntax error in parameters or arguments.\r\n")
                    await writer.drain()
                    continue

                if command_upper == "PASV":
                    await close_passive()
                    loop = asyncio.get_running_loop()
                    passive_future = loop.create_future()

                    async def _handler(data_reader: asyncio.StreamReader, data_writer: asyncio.StreamWriter) -> None:
                        nonlocal passive_future
                        if passive_future and not passive_future.done():
                            passive_future.set_result(_PassiveChannel(data_reader, data_writer))
                        else:
                            data_writer.close()
                            with contextlib.suppress(Exception):
                                await data_writer.wait_closed()

                    passive_server = await asyncio.start_server(_handler, host=self.host, port=0)
                    sock = passive_server.sockets[0]
                    pasv_host, pasv_port = sock.getsockname()[:2]
                    if pasv_host == "0.0.0.0":
                        pasv_host = writer.get_extra_info("sockname")[0] or "127.0.0.1"
                    h1, h2, h3, h4 = pasv_host.split(".")
                    p1, p2 = divmod(pasv_port, 256)
                    reply = f"227 Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})."
                    writer.write((reply + "\r\n").encode())
                    await writer.drain()
                    continue

                if command_upper == "CWD":
                    target = arg or home
                    if not filesystem:
                        cwd = target
                        writer.write(b"250 Directory successfully changed.\r\n")
                        await writer.drain()
                        continue
                    try:
                        new_dir = filesystem.normalize(target, cwd=cwd)
                        node = filesystem.resolve(new_dir)
                        if not node.is_dir:
                            writer.write(b"550 Failed to change directory.\r\n")
                        else:
                            cwd = new_dir
                            writer.write(b"250 Directory successfully changed.\r\n")
                            self.log_event(
                                "command", client=str(peer), username=username, command=f"CWD {target}", cwd=cwd
                            )
                    except (NodeNotFound, FilesystemError):
                        writer.write(b"550 Failed to change directory.\r\n")
                    await writer.drain()
                    continue

                if command_upper in {"LIST", "NLST", "XNLST"}:
                    channel = await self._prepare_data_channel(
                        writer,
                        active_target=active_target,
                        passive_future=passive_future,
                        passive_server=passive_server,
                    )
                    if channel is None:
                        writer.write(b"425 Use PORT or PASV first.\r\n")
                        await writer.drain()
                        continue

                    target_path = arg or "."
                    try:
                        if filesystem:
                            listing = filesystem.format_ftp_list(target_path, cwd=cwd)
                        else:
                            listing = self.config.get(
                                "listing",
                                [
                                    "-rw-r--r--    1 ftp      ftp          531 Jan 01 12:00 README",
                                    "drwxr-xr-x    2 ftp      ftp         4096 Jan 01 12:00 pub",
                                ],
                            )

                        if command_upper in {"NLST", "XNLST"}:
                            payload: Iterable[str] = [line.split()[-1] for line in listing]
                        else:
                            payload = listing

                        writer.write(b"150 Opening data connection.\r\n")
                        await writer.drain()
                        if await self._send_data(payload, channel):
                            writer.write(b"226 Transfer complete.\r\n")
                            self.log_event(
                                "command",
                                client=str(peer),
                                username=username,
                                command=f"{command_upper} {target_path}".strip(),
                                cwd=cwd,
                            )
                        else:
                            writer.write(b"425 Could not establish connection.\r\n")
                    except (NodeNotFound, FilesystemError):
                        writer.write(b"550 Failed to list directory.\r\n")

                    if channel.mode == "active":
                        active_target = None
                    else:
                        await close_passive()
                    await writer.drain()
                    continue

                if command_upper == "RETR":
                    channel = await self._prepare_data_channel(
                        writer,
                        active_target=active_target,
                        passive_future=passive_future,
                        passive_server=passive_server,
                    )
                    if channel is None:
                        writer.write(b"425 Use PORT or PASV first.\r\n")
                        await writer.drain()
                        continue
                    if not filesystem:
                        writer.write(b"550 File unavailable.\r\n")
                        await writer.drain()
                        continue
                    if not arg:
                        writer.write(b"501 Missing filename.\r\n")
                        await writer.drain()
                        continue
                    try:
                        content = filesystem.read_file(arg, cwd=cwd)
                        writer.write(b"150 Opening data connection.\r\n")
                        await writer.drain()
                        if await self._send_data(content.splitlines(), channel):
                            writer.write(b"226 Transfer complete.\r\n")
                            self.log_event(
                                "command",
                                client=str(peer),
                                username=username,
                                command=f"RETR {arg}",
                                cwd=cwd,
                                size=len(content.encode("utf-8")),
                            )
                        else:
                            writer.write(b"425 Could not establish connection.\r\n")
                    except NodeNotFound:
                        writer.write(b"550 File not found.\r\n")
                    except FilesystemError:
                        writer.write(b"550 File unavailable.\r\n")

                    if channel.mode == "active":
                        active_target = None
                    else:
                        await close_passive()
                    await writer.drain()
                    continue

                if command_upper == "NOOP":
                    writer.write(b"200 NOOP ok.\r\n")
                    await writer.drain()
                    continue

                if command_upper == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                default_responses = self.config.get("command_responses", {})
                response = default_responses.get(command_upper, "502 Command not implemented.")
                if isinstance(response, list):
                    for entry in response:
                        writer.write((entry + "\r\n").encode())
                else:
                    writer.write((response + "\r\n").encode())
                await writer.drain()
                self.log_event("command", client=str(peer), username=username, command=decoded, cwd=cwd)

        except Exception as exc:  # noqa: BLE001
            self.log_event("error", error=str(exc), client=str(peer))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await close_passive()

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

    async def _send_active_data(self, lines: Iterable[str], target: Tuple[str, int]) -> bool:
        host, port = target
        try:
            _, writer = await asyncio.open_connection(host, port)
        except Exception:
            return False
        try:
            for line in lines:
                writer.write((line + "\r\n").encode())
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        return True

    async def _prepare_data_channel(
        self,
        ctrl_writer: asyncio.StreamWriter,
        *,
        active_target: Optional[Tuple[str, int]],
        passive_future: Optional[asyncio.Future],
        passive_server: Optional[asyncio.AbstractServer],
    ) -> Optional[_DataChannel]:
        if active_target:
            return _DataChannel("active", active_target)
        if passive_server and passive_future:
            try:
                channel = await asyncio.wait_for(passive_future, timeout=10.0)
            except asyncio.TimeoutError:
                ctrl_writer.write(b"425 Passive data connection timed out.\r\n")
                await ctrl_writer.drain()
                return None
            return _DataChannel("passive", channel)
        return None

    async def _send_data(self, lines: Iterable[str], channel: _DataChannel) -> bool:
        if channel.mode == "active":
            return await self._send_active_data(lines, channel.payload)
        if channel.mode == "passive":
            payload: _PassiveChannel = channel.payload
            success = True
            try:
                for line in lines:
                    payload.writer.write((line + "\r\n").encode())
                await payload.writer.drain()
            except Exception:
                success = False
            finally:
                payload.writer.close()
                with contextlib.suppress(Exception):
                    await payload.writer.wait_closed()
            return success
        return False

    @staticmethod
    def _test_active_address(host: str, port: int) -> bool:
        if port <= 0 or port > 65535:
            return False
        parts = host.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
