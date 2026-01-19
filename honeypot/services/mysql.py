from __future__ import annotations

import asyncio
import contextlib
from typing import Dict, Optional

from ..base import BaseService


class MysqlService(BaseService):
    name = "mysql"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        handshake = self.config.get("handshake_banner", "5.7.41-0ubuntu0.20.04.1-log")
        greeting_lines = self.config.get(
            "greeting_lines",
            [
                "Welcome to the MySQL monitor.  Commands end with ; or \\g.",
                "Your MySQL connection id is 54",
                "Server version: 5.7.41-0ubuntu0.20.04.1-log (Ubuntu)",
            ],
        )
        prompt = self.config.get("prompt", "mysql> ")
        command_responses: Dict[str, str] = {
            key.lower(): value for key, value in self.config.get("command_responses", {}).items()
        }
        default_response = self.config.get(
            "default_response",
            "ERROR 1064 (42000): You have an error in your SQL syntax; "
            "check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
        )
        farewell = self.config.get("farewell", "Bye")

        try:
            writer.write((handshake + "\n").encode())
            await writer.drain()
            for line in greeting_lines:
                writer.write((line + "\n").encode())
            await writer.drain()

            self.log_event("handshake", client=str(peer), handshake=handshake)

            while True:
                writer.write(prompt.encode())
                await writer.drain()
                data = await reader.readline()
                if not data:
                    break
                command = data.decode("utf-8", "ignore").strip()
                if not command:
                    continue
                lower_command = command.lower()
                response = command_responses.get(lower_command)
                if response is None:
                    if lower_command in {"quit", "exit"}:
                        writer.write(f"{farewell}\n".encode())
                        await writer.drain()
                        self.log_event("command", client=str(peer), command=command, response="BYE")
                        break
                    response = default_response
                writer.write((response + "\n").encode())
                await writer.drain()
                self.log_event("command", client=str(peer), command=command, response=response[:160])
        except Exception as exc:  # noqa: BLE001
            self.log_event("error", client=str(peer), error=str(exc))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


__all__ = ["MysqlService"]
