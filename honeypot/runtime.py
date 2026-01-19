from __future__ import annotations

import asyncio
import signal
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Type

from .base import BaseService
from .filesystem import FakeFilesystem
from .services import FtpService, HttpService, HttpsService, MysqlService, SshService, TelnetService


class HoneypotRuntime:
    """Coordinates loading service configs and running selected listeners."""

    SERVICE_MAP: dict[str, Type[BaseService]] = {
        "ssh": SshService,
        "telnet": TelnetService,
        "ftp": FtpService,
        "http": HttpService,
        "https": HttpsService,
        "mysql": MysqlService,
    }
    FILESYSTEM_SERVICES = {"ssh", "telnet", "ftp"}

    def __init__(self, config_dir: Path, services: Optional[Sequence[str]] = None):
        self.config_dir = config_dir
        self.requested_services = services
        self.services: List[BaseService] = []
        self.shutdown_event = asyncio.Event()
        self.filesystem: Optional[FakeFilesystem] = None

    def load_services(self) -> None:
        names = self.determine_service_names()
        if any(name in self.FILESYSTEM_SERVICES for name in names):
            fs_path = self.config_dir / "filesystem.json"
            if not fs_path.exists():
                raise FileNotFoundError(
                    f"filesystem.json required for services {self.FILESYSTEM_SERVICES}. Missing at {fs_path}"
                )
            self.filesystem = FakeFilesystem(fs_path)
        for name in names:
            config_path = self.config_dir / f"{name}_config.json"
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found for service '{name}': {config_path}")
            service_cls = self.SERVICE_MAP[name]
            kwargs = {}
            if name in self.FILESYSTEM_SERVICES and self.filesystem:
                kwargs["filesystem"] = self.filesystem
            self.services.append(service_cls(config_path, **kwargs))

    def determine_service_names(self) -> List[str]:
        if self.requested_services:
            normalized = [name.lower() for name in self.requested_services]
            invalid = [name for name in normalized if name not in self.SERVICE_MAP]
            if invalid:
                valid = ", ".join(sorted(self.SERVICE_MAP))
                raise ValueError(f"Unsupported service(s): {invalid}. Allowed values: {valid}")
            return normalized
        # Auto-detect available configs
        discovered = []
        for name in self.SERVICE_MAP:
            if (self.config_dir / f"{name}_config.json").exists():
                discovered.append(name)
        return discovered

    async def start(self) -> None:
        if not self.services:
            raise RuntimeError("No service configurations loaded. Did you call load_services()?")
        for service in self.services:
            await service.start()
            print(f"[+] {service.name.upper()} listening on {service.host}:{service.port}")
        print("[+] Honeypot running. Press Ctrl+C to stop.")
        await self.wait_for_shutdown()

    async def wait_for_shutdown(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.shutdown_event.set)
            except NotImplementedError:
                # Windows event loop does not support signal handlers out of the box.
                pass
        await self.shutdown_event.wait()
        await self.stop()

    async def stop(self) -> None:
        await asyncio.gather(*(service.shutdown() for service in self.services))
        print("[+] Honeypot stopped.")
