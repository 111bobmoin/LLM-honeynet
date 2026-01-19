from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import ensure_parent_dir, load_json, timestamp


class BaseService:
    """Base class for honeypot services providing config loading and logging helpers."""

    name: str = "service"

    def __init__(self, config_path: Path, **kwargs):
        self.config_path = config_path
        self.config = load_json(config_path)
        self.host: str = self.config.get("host", "0.0.0.0")
        self.port: int = int(self.config["port"])
        log_location = self.config.get("log_file", f"../logs/{self.name}.log")
        self.log_path = self._resolve_log_path(log_location)
        self.server: Optional[asyncio.AbstractServer] = None
        self.filesystem = kwargs.get("filesystem")

    def resolve_path(self, candidate: str) -> Path:
        base = self.config_path.parent
        return (base / candidate).resolve()

    def _resolve_log_path(self, location: str) -> Path:
        candidate = self.resolve_path(location)
        ensure_parent_dir(candidate)
        if self._test_writable(candidate):
            return candidate
        fallback = candidate.with_name(f"{candidate.stem}_user{candidate.suffix}")
        ensure_parent_dir(fallback)
        if self._test_writable(fallback):
            print(f"[!] Cannot write to {candidate}. Using fallback log path {fallback}.")
            return fallback
        raise PermissionError(f"Unable to write to log file {candidate} or fallback {fallback}")

    @staticmethod
    def _test_writable(path: Path) -> bool:
        try:
            path.touch(exist_ok=True)
            with path.open("a", encoding="utf-8"):
                return True
        except PermissionError:
            return False

    def log_event(self, event: str, **details: Any) -> None:
        payload = {
            "ts": timestamp(),
            "service": self.name,
            "event": event,
            **details,
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def serve(self) -> None:
        if self.server is None:
            await self.start()
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def start(self) -> None:
        raise NotImplementedError

    async def shutdown(self) -> None:
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()
