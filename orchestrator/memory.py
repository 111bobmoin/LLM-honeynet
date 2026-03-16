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
    """Supplemental factual memory for persistent honeynet knowledge."""

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

    def save(self) -> None:
        """Persist long term memory to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data["last_updated"] = utc_now()
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

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

    def add_port_facts(self, port: int, facts: Dict[str, Any]) -> None:
        """Add or update port facts."""
        if "ports" not in self.data:
            self.data["ports"] = {}
        key = f"{port}/tcp"
        self.data["ports"][key] = {
            **self.data["ports"].get(key, {}),
            **facts,
            "port": port,
            "protocol": "tcp",
            "last_seen": utc_now()
        }
        self.save()

    def record_config_generation(self, host: str, config_summary: Dict[str, Any]) -> None:
        """Record a configuration generation event for learning."""
        if "config_history" not in self.data:
            self.data["config_history"] = []

        entry = {
            "timestamp": utc_now(),
            "host": host,
            "summary": config_summary,
        }
        self.data["config_history"].append(entry)

        # Keep only last 100 entries
        if len(self.data["config_history"]) > 100:
            self.data["config_history"] = self.data["config_history"][-100:]

        self.save()

    def get_successful_patterns(self) -> List[Dict[str, Any]]:
        """Get historically successful configuration patterns."""
        return self.data.get("successful_patterns", [])

    def add_successful_pattern(self, pattern: Dict[str, Any]) -> None:
        """Add a successful configuration pattern."""
        if "successful_patterns" not in self.data:
            self.data["successful_patterns"] = []

        pattern["timestamp"] = utc_now()
        self.data["successful_patterns"].append(pattern)

        # Keep only last 50 patterns
        if len(self.data["successful_patterns"]) > 50:
            self.data["successful_patterns"] = self.data["successful_patterns"][-50:]

        self.save()

    def get_attacker_behaviors(self) -> List[Dict[str, Any]]:
        """Get learned attacker behavior patterns."""
        return self.data.get("attacker_behaviors", [])

    def record_attacker_behavior(self, behavior: Dict[str, Any]) -> None:
        """Record observed attacker behavior."""
        if "attacker_behaviors" not in self.data:
            self.data["attacker_behaviors"] = []

        behavior["timestamp"] = utc_now()
        self.data["attacker_behaviors"].append(behavior)

        # Keep only last 100 behaviors
        if len(self.data["attacker_behaviors"]) > 100:
            self.data["attacker_behaviors"] = self.data["attacker_behaviors"][-100:]

        self.save()

    def get_effective_decoys(self) -> Dict[str, Any]:
        """Get decoy configurations that have been effective."""
        return self.data.get("effective_decoys", {})

    def record_effective_decoy(self, decoy_type: str, config: Dict[str, Any]) -> None:
        """Record an effective decoy configuration."""
        if "effective_decoys" not in self.data:
            self.data["effective_decoys"] = {}

        if decoy_type not in self.data["effective_decoys"]:
            self.data["effective_decoys"][decoy_type] = []

        self.data["effective_decoys"][decoy_type].append({
            "config": config,
            "timestamp": utc_now()
        })

        # Keep only last 20 per type
        if len(self.data["effective_decoys"][decoy_type]) > 20:
            self.data["effective_decoys"][decoy_type] = self.data["effective_decoys"][decoy_type][-20:]

        self.save()

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of long term memory contents."""
        return {
            "last_updated": self.data.get("last_updated"),
            "ports_count": len(self.data.get("ports", {})),
            "config_history_count": len(self.data.get("config_history", [])),
            "successful_patterns_count": len(self.data.get("successful_patterns", [])),
            "attacker_behaviors_count": len(self.data.get("attacker_behaviors", [])),
            "effective_decoys_types": list(self.data.get("effective_decoys", {}).keys()),
        }


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
