from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .memory import (
    FileNode,
    HostNode,
    LongTermMemory,
    PortNode,
    ShortTermMemory,
    VulnerabilityNode,
    default_long_term,
)

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment]


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


@dataclass
class HoneyAgentConfig:
    short_memory_path: Path = Path("shadow/honey_agent.json")
    long_memory_path: Path = Path("shadow/long_memory.json")
    topology_path: Path = Path("shadow/shadow_topology.json")
    fallback_topology_path: Path = Path("enterprise/enterprise_topology.json")
    preferences_path: Path = Path("shadow/attacker_preferences.json")
    openai_key_path: Path = Path("secrets/openai_api_key.txt")
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.1
    openai_top_p: float = 0.9


class HoneyAgent:
    """Generates compact short-term memory trees using an LLM and long-term facts."""

    def __init__(self, config: Optional[HoneyAgentConfig] = None) -> None:
        self.config = config or HoneyAgentConfig()
        self._openai_client: Optional[Any] = None
        self.short_memory = ShortTermMemory(self.config.short_memory_path)
        self.long_memory = LongTermMemory(self.config.long_memory_path, builtin=default_long_term())

    # ------------------------------------------------------------------ public API

    def run_initialization(self) -> Dict[str, Any]:
        topology = self._load_topology()
        preferences = self._load_preferences()
        hosts = self._generate_short_term(topology, preferences, baseline=None, mode="initialization")
        self.short_memory.replace_hosts(hosts, mode="initialization")
        return {
            "topology": topology,
            "preferences": preferences,
            "short_memory": [host.to_dict() for host in hosts],
        }

    def run_finetune(self) -> Dict[str, Any]:
        topology = self._load_topology()
        preferences = self._load_preferences()
        baseline_hosts = list(self.short_memory.hosts)
        hosts = self._generate_short_term(
            topology,
            preferences,
            baseline=baseline_hosts,
            mode="finetune",
            finetune_only=True,
        )
        # In finetune, only replace if we have deltas; otherwise keep baseline.
        if hosts:
            self.short_memory.replace_hosts(hosts, mode="finetune")
        return {
            "topology": topology,
            "preferences": preferences,
            "short_memory": [host.to_dict() for host in (hosts or baseline_hosts)],
        }

    # --------------------------------------------------------------- generation

    def _generate_short_term(
        self,
        topology: Dict[str, Any],
        preferences: Sequence[str],
        baseline: Optional[List[HostNode]],
        mode: str,
        finetune_only: bool = False,
    ) -> List[HostNode]:
        print("[HoneyAgent] step 1/3: generating ports per host")
        ports_payload = self._generate_ports(topology, preferences, baseline, mode)

        print("[HoneyAgent] step 2/3: generating files per host/port")
        files_payload = self._generate_files(topology, preferences, ports_payload, baseline, mode)

        print("[HoneyAgent] step 3/3: generating vulns per host/port/file")
        vulns_payload = self._generate_vulns(topology, preferences, ports_payload, files_payload, baseline, mode)

        merged = self._merge_ports_files_vulns(ports_payload, files_payload, vulns_payload)
        if finetune_only and baseline:
            # Only apply minimal changes: keep structure and edit where LLM provided updates.
            return self._apply_finetune_deltas(baseline, merged)
        return merged

    def _generate_ports(
        self,
        topology: Dict[str, Any],
        preferences: Sequence[str],
        baseline: Optional[List[HostNode]],
        mode: str,
    ) -> Dict[str, Any]:
        baseline_ports = self._extract_baseline_ports(baseline)
        context = {
            "mode": mode,
            "topology": topology,
            "attacker_preferences": list(preferences),
            "baseline_ports": baseline_ports,
        }
        instructions = (
            "You are a deception planner producing only host and port layers. "
            "Return strict JSON {hosts:[{name, ports}]} with no prose. "
            "Use every host from topology; for each host choose 1-3 plausible ports. "
            "Each port item is {port(int), service}. "
            "Keep output tiny and avoid any extra keys. If baseline_ports is present, prefer minor edits."
        )
        return self._invoke_generation(instructions, context, stage="ports-layer")

    def _generate_files(
        self,
        topology: Dict[str, Any],
        preferences: Sequence[str],
        ports_payload: Dict[str, Any],
        baseline: Optional[List[HostNode]],
        mode: str,
    ) -> Dict[str, Any]:
        baseline_files = self._extract_baseline_files(baseline)
        context = {
            "mode": mode,
            "topology": topology,
            "attacker_preferences": list(preferences),
            "ports": ports_payload,
            "baseline_files": baseline_files,
        }
        instructions = (
            "You are a deception planner adding honey files for each port. "
            "Return strict JSON {hosts:[{name, ports:[{port, service, files:[{path}]}]}]} with no prose. "
            "For each port, include 1-2 enticing file paths (passwords, backups, keys, finance) as {path}. "
            "Do not add hosts beyond those provided in ports. "
            "If baseline_files exists, prefer minimal changes."
        )
        return self._invoke_generation(instructions, context, stage="files-layer")

    def _generate_vulns(
        self,
        topology: Dict[str, Any],
        preferences: Sequence[str],
        ports_payload: Dict[str, Any],
        files_payload: Dict[str, Any],
        baseline: Optional[List[HostNode]],
        mode: str,
    ) -> Dict[str, Any]:
        baseline_vulns = self._extract_baseline_vulns(baseline)
        context = {
            "mode": mode,
            "topology": topology,
            "attacker_preferences": list(preferences),
            "ports": ports_payload,
            "files": files_payload,
            "baseline_vulns": baseline_vulns,
        }
        instructions = (
            "You are a deception planner adding vulnerabilities *separately* from ports/files. "
            "Use the provided hosts/ports/files, and for each host optionally output 0-2 vulnerabilities that reference them. "
            "Return strict JSON {hosts:[{name, vulnerabilities:[{type, target_port?, target_file?}]}]} with no prose. "
            "type should be a short vulnerability category (e.g., weak creds, outdated ssh, config leak, path traversal, RCE, file upload). "
            "Avoid repeating the same type for a given host; prefer variety tied to the underlying port/file. "
            "target_port is the integer port the vuln is tied to; target_file is the path it references; "
            "at least one of target_port/target_file must be present. Do not invent hosts or ports beyond input."
        )
        return self._invoke_generation(instructions, context, stage="vulns-layer")

    def _build_generation_context(
        self,
        topology: Dict[str, Any],
        preferences: Sequence[str],
        baseline: Optional[List[HostNode]],
        mode: str,
    ) -> Dict[str, Any]:
        baseline_payload = [host.to_dict() for host in baseline] if baseline else None
        # Collect a small set of port facts to keep prompt minimal.
        candidate_ports = {22, 80, 443}
        if baseline:
            for host in baseline:
                for port in host.ports:
                    candidate_ports.add(int(port.port))
        long_term = self.long_memory.relevant_port_facts(candidate_ports)
        return {
            "mode": mode,
            "topology": topology,
            "attacker_preferences": list(preferences),
            "long_term_port_facts": long_term,
            "baseline": baseline_payload,
        }

    # --------------------------------------------------------------- utilities

    def _parse_hosts(self, payload: Dict[str, Any]) -> List[HostNode]:
        hosts: List[HostNode] = []
        for host_entry in payload.get("hosts", []):
            ports: List[PortNode] = []
            for port_entry in host_entry.get("ports", []):
                files: List[FileNode] = []
                for file_entry in port_entry.get("files", []):
                    files.append(
                        FileNode(
                            path=file_entry.get("path", ""),
                            lure_type=file_entry.get("lure_type", ""),
                            summary=file_entry.get("summary", ""),
                        )
                    )
                ports.append(
                    PortNode(
                        port=int(port_entry.get("port", 0)),
                        service=port_entry.get("service", ""),
                        banner=None,
                        note=None,
                        files=files,
                    )
                )
            host_vulns = []
            for vuln in host_entry.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                vtype = vuln.get("type")
                if not vtype:
                    continue
                host_vulns.append(
                    VulnerabilityNode(
                        type=vtype,
                        target_port=vuln.get("target_port"),
                        target_file=vuln.get("target_file"),
                    )
                )
            hosts.append(
                HostNode(
                    name=host_entry.get("name", ""),
                    role=host_entry.get("role"),
                    ports=ports,
                    vulnerabilities=host_vulns,
                )
            )
        return hosts

    def _merge_ports_files_vulns(
        self,
        ports_payload: Dict[str, Any],
        files_payload: Dict[str, Any],
        vulns_payload: Dict[str, Any],
    ) -> List[HostNode]:
        host_map: Dict[str, Dict[str, Any]] = {}
        for entry in ports_payload.get("hosts", []):
            name = entry.get("name")
            if not name:
                continue
            host_map[name] = {"name": name, "ports": entry.get("ports", [])}

        for entry in files_payload.get("hosts", []):
            name = entry.get("name")
            if not name or name not in host_map:
                continue
            # Overwrite ports with those carrying files if provided.
            host_map[name]["ports"] = entry.get("ports", host_map[name].get("ports", []))

        for entry in vulns_payload.get("hosts", []):
            name = entry.get("name")
            if not name or name not in host_map:
                continue
            host_map[name]["vulnerabilities"] = entry.get("vulnerabilities", [])

        merged_hosts = {"hosts": list(host_map.values())}
        return self._parse_hosts(merged_hosts)

    def _apply_finetune_deltas(self, baseline: List[HostNode], updates: List[HostNode]) -> List[HostNode]:
        base_map = {h.name: h for h in baseline}
        update_map = {h.name: h for h in updates}
        result: List[HostNode] = []
        for name, base_host in base_map.items():
            updated = update_map.get(name)
            if not updated:
                result.append(base_host)
                continue
            # Replace ports only if updated provides ports; else keep baseline.
            ports = updated.ports or base_host.ports
            vulnerabilities = updated.vulnerabilities or base_host.vulnerabilities
            result.append(
                HostNode(
                    name=base_host.name,
                    role=base_host.role or updated.role,
                    ports=ports,
                    traps=base_host.traps,
                    vulnerabilities=vulnerabilities,
                )
            )
        # Include any new hosts not in baseline.
        for name, updated in update_map.items():
            if name not in base_map:
                result.append(updated)
        return result

    def _extract_baseline_ports(self, baseline: Optional[List[HostNode]]) -> List[Dict[str, Any]]:
        if not baseline:
            return []
        result = []
        for host in baseline:
            result.append(
                {
                    "name": host.name,
                    "ports": [{"port": p.port, "service": p.service} for p in host.ports],
                }
            )
        return result

    def _extract_baseline_files(self, baseline: Optional[List[HostNode]]) -> List[Dict[str, Any]]:
        if not baseline:
            return []
        result = []
        for host in baseline:
            host_entry: Dict[str, Any] = {"name": host.name, "ports": []}
            for port in host.ports:
                host_entry["ports"].append(
                    {
                        "port": port.port,
                        "service": port.service,
                        "files": [{"path": f.path} for f in port.files],
                    }
                )
            result.append(host_entry)
        return result

    def _extract_baseline_vulns(self, baseline: Optional[List[HostNode]]) -> List[Dict[str, Any]]:
        if not baseline:
            return []
        result = []
        for host in baseline:
            host_entry: Dict[str, Any] = {"name": host.name, "ports": []}
            if host.vulnerabilities:
                host_entry["vulnerabilities"] = [v.to_dict() for v in host.vulnerabilities]
            result.append(host_entry)
        return result

    def _load_topology(self) -> Dict[str, Any]:
        topo = _read_json(self.config.topology_path)
        if topo:
            return topo
        fallback = _read_json(self.config.fallback_topology_path)
        return fallback or {}

    def _load_preferences(self) -> List[str]:
        data = _read_json(self.config.preferences_path)
        if isinstance(data, list):
            return [str(item) for item in data if isinstance(item, (str, int, float))]
        return ["credential theft", "ssh brute force", "data exfiltration"]

    # ----------------------------------------------------------- openai client

    def _invoke_generation(self, instructions: str, context: Dict[str, Any], stage: str) -> Dict[str, Any]:
        client = self._lazy_openai_client()
        if not client:
            raise RuntimeError(
                f"OpenAI client unavailable. Provide a valid API key and install the openai package to generate {stage}."
            )
        messages = [
            {"role": "system", "content": instructions},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
        ]
        try:
            response = client.chat.completions.create(
                model=self.config.openai_model,
                messages=messages,
                temperature=self.config.openai_temperature,
                top_p=self.config.openai_top_p,
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to generate {stage} via OpenAI: {exc}") from exc

        raw = ""
        if getattr(response, "choices", None):
            raw = (response.choices[0].message.content or "").strip()
        if not raw:
            raise RuntimeError(f"OpenAI returned empty content for {stage}.")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:  # pragma: no cover
            snippet = raw[:200]
            raise RuntimeError(f"OpenAI response for {stage} is not valid JSON (preview: {snippet})") from exc

    def _lazy_openai_client(self) -> Optional[Any]:
        if self._openai_client is False:
            return None
        if self._openai_client is not None:
            return self._openai_client
        if OpenAI is None:
            self._openai_client = False
            return None
        try:
            api_key = self.config.openai_key_path.read_text(encoding="utf-8").strip()
        except OSError:
            api_key = ""
        if not api_key:
            self._openai_client = False
            return None
        self._openai_client = OpenAI(api_key=api_key)
        return self._openai_client


__all__ = ["HoneyAgent", "HoneyAgentConfig"]
