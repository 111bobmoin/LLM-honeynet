from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ISO_TS = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> str:
    return datetime.utcnow().strftime(ISO_TS)


# -------------------------- short-term memory -------------------------- #


@dataclass
class VulnerabilityNode:
    type: str
    target_port: Optional[int] = None
    target_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"type": self.type}
        if self.target_port is not None:
            payload["target_port"] = self.target_port
        if self.target_file:
            payload["target_file"] = self.target_file
        return payload


@dataclass
class FileNode:
    path: str
    lure_type: str = ""
    summary: str = ""
    vulnerabilities: List[VulnerabilityNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"path": self.path}
        if self.lure_type:
            payload["lure_type"] = self.lure_type
        if self.summary:
            payload["summary"] = self.summary
        if self.vulnerabilities:
            payload["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return payload


@dataclass
class PortNode:
    port: int
    service: str
    banner: Optional[str] = None
    note: Optional[str] = None
    files: List[FileNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "port": self.port,
            "service": self.service,
            "files": [f.to_dict() for f in self.files],
        }
        if self.banner:
            payload["banner"] = self.banner
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass
class TrapAttachment:
    host_loops: List[Dict[str, Any]] = field(default_factory=list)
    credential_chains: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_loops": self.host_loops,
            "credential_chains": self.credential_chains,
        }


@dataclass
class HostNode:
    name: str
    role: Optional[str] = None
    ports: List[PortNode] = field(default_factory=list)
    traps: Optional[TrapAttachment] = None
    vulnerabilities: List[VulnerabilityNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "name": self.name,
            "ports": [p.to_dict() for p in self.ports],
        }
        if self.role:
            payload["role"] = self.role
        if self.traps:
            payload["traps"] = self.traps.to_dict()
        if self.vulnerabilities:
            payload["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return payload


class ShortTermMemory:
    """Tree-form short term memory: host -> ports -> files -> vulnerabilities."""

    def __init__(self, path: Path):
        self.path = path
        self.metadata: Dict[str, Any] = {}
        self.hosts: List[HostNode] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        self.metadata = payload.get("metadata", {})
        self.hosts = [self._host_from_dict(item) for item in payload.get("hosts", []) if isinstance(item, dict)]

    def save(self, mode: str = "update") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if "generated_at" not in self.metadata:
            self.metadata["generated_at"] = utc_now()
        if "mode" not in self.metadata:
            self.metadata["mode"] = mode
        payload = {
            "metadata": self.metadata,
            "hosts": [host.to_dict() for host in self.hosts],
        }
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def replace_hosts(self, hosts: Iterable[HostNode], mode: str) -> None:
        self.hosts = list(hosts)
        self.metadata = {"generated_at": utc_now(), "mode": mode}
        self.save(mode=mode)

    def upsert_traps(self, host_name: str, trap_data: TrapAttachment) -> None:
        for host in self.hosts:
            if host.name == host_name:
                host.traps = trap_data
                break
        else:
            self.hosts.append(HostNode(name=host_name, traps=trap_data))
        self.save(mode=self.metadata.get("mode", "update"))

    @staticmethod
    def _host_from_dict(payload: Dict[str, Any]) -> HostNode:
        ports = []
        host_level_vulns: List[VulnerabilityNode] = []
        for vuln in payload.get("vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            vtype = vuln.get("type") or vuln.get("id") or vuln.get("vector")
            if not vtype:
                continue
            host_level_vulns.append(
                VulnerabilityNode(
                    type=str(vtype),
                    target_port=vuln.get("target_port"),
                    target_file=vuln.get("target_file"),
                )
            )
        for port_data in payload.get("ports", []):
            files = []
            for file_data in port_data.get("files", []):
                for item in file_data.get("vulnerabilities", []) or []:
                    if not isinstance(item, dict):
                        continue
                    vid = item.get("id") or item.get("vector")
                    if not vid:
                        continue
                    host_level_vulns.append(
                        VulnerabilityNode(
                            id=str(vid),
                            target_port=port_data.get("port"),
                            target_file=file_data.get("path"),
                        )
                    )
                files.append(
                    FileNode(
                        path=file_data.get("path", ""),
                        lure_type=file_data.get("lure_type", ""),
                        summary=file_data.get("summary", ""),
                    )
                )
            ports.append(
                PortNode(
                    port=int(port_data.get("port", 0)),
                    service=port_data.get("service", ""),
                    banner=port_data.get("banner"),
                    note=port_data.get("note"),
                    files=files,
                )
            )

        trap_payload = payload.get("traps")
        traps = None
        if isinstance(trap_payload, dict):
            traps = TrapAttachment(
                host_loops=trap_payload.get("host_loops", []) or [],
                credential_chains=trap_payload.get("credential_chains", []) or [],
            )

        return HostNode(
            name=payload.get("name", ""),
            role=payload.get("role"),
            ports=ports,
            traps=traps,
            vulnerabilities=host_level_vulns,
        )


# -------------------------- long-term memory --------------------------- #


class LongTermMemory:
    """Supplemental factual memory keyed by node identity (e.g., port/protocol)."""

    def __init__(self, path: Path, builtin: Optional[Dict[str, Any]] = None) -> None:
        self.path = path
        self.data: Dict[str, Any] = {}
        self._load(builtin or {})

    def _load(self, builtin: Dict[str, Any]) -> None:
        payload = {}
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = {}
        merged = dict(builtin)
        merged.update(payload)
        self.data = merged

    def port_facts(self, port: int) -> Dict[str, Any]:
        key = f"{port}/tcp"
        return self.data.get("ports", {}).get(key, {})

    def relevant_port_facts(self, ports: Iterable[int]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for port in ports:
            facts = self.port_facts(port)
            if facts:
                result[f"{port}/tcp"] = facts
        return result


def default_long_term() -> Dict[str, Any]:
    """Built-in fallback facts to avoid empty prompts when user has no file."""
    return {
        "ports": {
            "22/tcp": {
                "service": "ssh",
                "protocol": "tcp",
                "version": "OpenSSH-like",
                "notes": ["Common for remote admin", "Banner should look realistic but slightly outdated"],
            },
            "80/tcp": {
                "service": "http",
                "protocol": "tcp",
                "version": "nginx/apache style",
                "notes": ["Static lure pages", "Expose admin-looking paths sparingly"],
            },
            "443/tcp": {
                "service": "https",
                "protocol": "tcp",
                "version": "TLS 1.2 allowed",
                "notes": ["Self-signed acceptable", "Keep cipher list plausible"],
            },
        }
    }
