from __future__ import annotations

import asyncio
import contextlib
from typing import Iterable

from ..base import BaseService


class PostgresqlService(BaseService):
    name = "postgresql"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        version = self.config.get("version", "PostgreSQL 13.10")
        notes: Iterable[str] = self.config.get("notes", [])
        default_response = self.config.get("default_response", "ERROR: permission denied for relation secrets")
        farewell = self.config.get("farewell", "server closed the connection unexpectedly")

        try:
            greeting_lines = [
                f"PostgreSQL server ready: {version}",
                *[f"- {note}" for note in notes],
            ]
            for line in greeting_lines:
                writer.write((line + "\n").encode("utf-8"))
            writer.write(b"postgres=# ")
            await writer.drain()
            self.log_event("handshake", client=str(peer), version=version)

            while True:
                data = await reader.readline()
                if not data:
                    break
                command = data.decode("utf-8", "ignore").strip()
                if not command:
                    writer.write(b"postgres=# ")
                    await writer.drain()
                    continue
                lower_command = command.lower()
                if lower_command in {"quit", "\\q", "exit"}:
                    writer.write((farewell + "\n").encode("utf-8"))
                    await writer.drain()
                    self.log_event("command", client=str(peer), command=command, response="BYE")
                    break
                writer.write((default_response + "\npostgres=# ").encode("utf-8"))
                await writer.drain()
                self.log_event("command", client=str(peer), command=command, response=default_response[:160])
        except Exception as exc:  # noqa: BLE001
            self.log_event("error", client=str(peer), error=str(exc))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


__all__ = ["PostgresqlService"]
