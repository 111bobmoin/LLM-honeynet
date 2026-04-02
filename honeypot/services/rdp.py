from __future__ import annotations

import asyncio
import contextlib

from ..base import BaseService


class RdpService(BaseService):
    name = "rdp"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        banner = self.config.get("banner", "RDP Honeypot")
        try:
            writer.write((banner + "\r\n").encode("utf-8"))
            await writer.drain()
            self.log_event("handshake", client=str(peer), banner=banner)

            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self.log_event("command", client=str(peer), bytes_received=len(data))
        except Exception as exc:  # noqa: BLE001
            self.log_event("error", client=str(peer), error=str(exc))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


__all__ = ["RdpService"]
