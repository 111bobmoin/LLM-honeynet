from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Tuple

from ..base import BaseService


class HttpService(BaseService):
    name = "http"

    STATUS_TEXT = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }

    def __init__(self, config_path, ssl_context: Optional[ssl.SSLContext] = None, **kwargs):
        super().__init__(config_path, **kwargs)
        self.ssl_context = ssl_context
        self.server_header = self.config.get("server_header", "Apache/2.4.52 (Ubuntu)")
        self.default_status = int(self.config.get("default_status", 404))
        self.default_headers = self.config.get("default_headers", {})
        self.routes = self.config.get("routes", [])

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
            ssl=self.ssl_context,
        )
        self.log_event("startup", host=self.host, port=self.port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                await writer.wait_closed()
                return
            try:
                method, path, version = request_line.decode("utf-8", "ignore").strip().split()
            except ValueError:
                await self.send_error(writer, 400, version="HTTP/1.0")
                return

            headers = await self.read_headers(reader)
            body = await self.read_body(reader, headers)

            route = self.match_route(method, path)
            response = await self.build_response(route, method, path, version)
            writer.write(response)
            await writer.drain()

            self.log_event(
                "request",
                client=str(peer),
                method=method,
                path=path,
                version=version,
                headers=headers,
                body_preview=(body[:200] if body else ""),
                route=route,
            )
        except Exception as exc:  # noqa: BLE001
            self.log_event("error", error=str(exc), client=str(peer))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def read_headers(self, reader: asyncio.StreamReader) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", "ignore")
            if ":" in decoded:
                key, value = decoded.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    async def read_body(self, reader: asyncio.StreamReader, headers: Dict[str, str]) -> str:
        length = headers.get("Content-Length") or headers.get("content-length")
        if not length:
            return ""
        try:
            size = int(length)
        except ValueError:
            return ""
        try:
            data = await reader.readexactly(size)
        except asyncio.IncompleteReadError as exc:
            data = exc.partial
        return data.decode("utf-8", "ignore")

    def match_route(self, method: str, path: str) -> Optional[Dict[str, Any]]:
        for route in self.routes:
            if route.get("method", "GET").upper() != method.upper():
                continue
            if route.get("path") == path:
                return route
        return None

    async def build_response(
        self,
        route: Optional[Dict[str, Any]],
        method: str,
        path: str,
        version: str,
    ) -> bytes:
        if route:
            status = int(route.get("status", self.default_status))
            body_content, length = await self.resolve_body(route)
            headers = {**self.default_headers, **route.get("response_headers", {})}
        else:
            status = self.default_status
            not_found_route = self.config.get("not_found", {})
            if not not_found_route:
                body_content = f"{status} {self.STATUS_TEXT.get(status, 'Unknown')}\n"
                length = len(body_content.encode("utf-8"))
                headers = dict(self.default_headers)
            else:
                body_content, length = await self.resolve_body(not_found_route)
                headers = {**self.default_headers, **not_found_route.get("response_headers", {})}

        headers.setdefault("Content-Type", "text/html; charset=utf-8")
        headers.setdefault("Connection", "close")
        headers["Server"] = self.server_header
        headers["Date"] = self.http_date()
        headers["Content-Length"] = str(length)

        status_line = f"{version} {status} {self.STATUS_TEXT.get(status, 'Unknown')}\r\n"
        header_blob = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        return (status_line + header_blob + "\r\n" + body_content).encode("utf-8")

    async def resolve_body(self, route: Dict[str, Any]) -> Tuple[str, int]:
        if "body" in route:
            body_content = str(route["body"])
            return body_content, len(body_content.encode("utf-8"))
        if "body_file" in route:
            file_path = self.resolve_path(route["body_file"])
            with file_path.open("r", encoding=route.get("encoding", "utf-8")) as handle:
                content = handle.read()
                return content, len(content.encode("utf-8"))
        return "", 0

    @staticmethod
    def http_date() -> str:
        now = datetime.utcnow()
        weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][now.weekday()]
        month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][now.month - 1]
        return f"{weekday}, {now.day:02d} {month} {now.year} {now:%H:%M:%S} GMT"

    async def send_error(self, writer: asyncio.StreamWriter, status: int, version: str = "HTTP/1.0") -> None:
        body = f"{status} {self.STATUS_TEXT.get(status, 'Unknown')}\r\n"
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
            "Server": self.server_header,
            "Date": self.http_date(),
        }
        response = f"{version} {status} {self.STATUS_TEXT.get(status, 'Unknown')}\r\n"
        response += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        response += "\r\n" + body
        writer.write(response.encode("utf-8"))
        await writer.drain()


class HttpsService(HttpService):
    name = "https"

    def __init__(self, config_path, **kwargs):
        super().__init__(config_path, **kwargs)
        self.ssl_context = self.build_ssl_context()

    def build_ssl_context(self) -> ssl.SSLContext:
        cert_file = self.resolve_path(self.config["certificate"])
        key_file = self.resolve_path(self.config["private_key"])
        if not cert_file.exists() or not key_file.exists():
            raise FileNotFoundError(f"HTTPS certificate or key not found: {cert_file}, {key_file}")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(str(cert_file), str(key_file))
        ciphers = self.config.get("ciphers")
        if ciphers:
            ssl_ctx.set_ciphers(ciphers)
        tls_versions: Iterable[str] = self.config.get("tls_versions", ["TLSv1.2", "TLSv1.3"])
        if hasattr(ssl_ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
            version_map = {
                "TLSv1.0": ssl.TLSVersion.TLSv1,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            }
            allowed = [version_map[v] for v in tls_versions if v in version_map]
            if allowed:
                ssl_ctx.minimum_version = min(allowed)
                ssl_ctx.maximum_version = max(allowed)
        return ssl_ctx
