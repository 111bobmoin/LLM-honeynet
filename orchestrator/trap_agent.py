from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .memory import HostNode, ShortTermMemory, TrapAttachment

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
class TrapAgentConfig:
    short_memory_path: Path = Path("shadow/honey_agent.json")
    trap_memory_path: Path = Path("shadow/trap_agent.json")
    topology_path: Path = Path("shadow/shadow_topology.json")
    fallback_topology_path: Path = Path("enterprise/enterprise_topology.json")
    preferences_path: Path = Path("shadow/attacker_preferences.json")
    openai_key_path: Path = Path("secrets/openai_api_key.txt")
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.15
    openai_top_p: float = 0.85


class TrapAgent:
    """Generates trap loops and credential chains and attaches them to short-term memory."""

    def __init__(self, config: Optional[TrapAgentConfig] = None) -> None:
        self.config = config or TrapAgentConfig()
        self._openai_client: Optional[Any] = None
        self.short_memory = ShortTermMemory(self.config.short_memory_path)

    # ------------------------------------------------------------------ public API

    def run_host_trap_chain(self) -> Dict[str, Any]:
        hosts = self._require_hosts()
        preferences = self._load_preferences()
        context = self._build_host_context(hosts, preferences)
        instructions = (
            "Design minimal host-level trap loops. "
            "Use only the provided file paths for each host. "
            "For each host, output 0-3 loops; each loop is an ordered list of paths that forms a cycle back to the first path. "
            "Respond strictly as JSON {hosts:[{name, loops:[[path1,path2,...]]}]} with no extra fields or prose."
        )
        data = self._invoke_generation(instructions, context, stage="host trap loop")
        self._apply_host_loops(data)
        self._persist_traps()
        return {"hosts": [host.to_dict() for host in self.short_memory.hosts]}

    def run_interhost_trap_chain(self) -> Dict[str, Any]:
        hosts = self._require_hosts()
        preferences = self._load_preferences()
        context = self._build_interhost_context(hosts, preferences)
        instructions = (
            "Design inter-host trap chains with minimal text. "
            "Use provided hosts (and optional host-level loops) to produce 1-3 chains that move attackers between hosts then loop back. "
            "Each chain is an ordered list of hosts with a tier label (low/mid/high), e.g., host1(low)->host2(mid)->host3(high)->host1(low). "
            "Respond strictly as JSON {chains:[{name, steps:[{host, tier}]}]} and keep steps <=5. "
            "Do not add extra fields or prose."
        )
        data = self._invoke_generation(instructions, context, stage="inter-host trap")
        self._apply_credential_chains(data)
        self._persist_traps()
        return {"hosts": [host.to_dict() for host in self.short_memory.hosts]}

    def run_full_pipeline(self) -> Dict[str, Any]:
        self.run_host_trap_chain()
        return self.run_interhost_trap_chain()

    # -------------------------------------------------------------- context build

    def _build_host_context(self, hosts: List[HostNode], preferences: List[str]) -> Dict[str, Any]:
        return {
            "hosts": [
                {
                    "name": host.name,
                    "role": host.role,
                    "files": [
                        file.to_dict() for port in host.ports for file in port.files  # type: ignore[attr-defined]
                    ],
                }
                for host in hosts
            ],
            "preferences": preferences,
        }

    def _build_interhost_context(self, hosts: List[HostNode], preferences: List[str]) -> Dict[str, Any]:
        host_summaries = []
        for host in hosts:
            host_summaries.append(
                {
                    "name": host.name,
                    "role": host.role,
                    "ports": [{"port": port.port, "service": port.service} for port in host.ports],
                    "traps": (host.traps.to_dict() if host.traps else {}),
                }
            )
        return {"hosts": host_summaries, "preferences": preferences}

    # -------------------------------------------------------------- apply results

    def _apply_host_loops(self, payload: Dict[str, Any]) -> None:
        host_map = {host.name: host for host in self.short_memory.hosts}
        for entry in payload.get("hosts", []):
            name = entry.get("name")
            if not name or name not in host_map:
                continue
            loops = entry.get("loops", []) or []
            existing = host_map[name].traps or TrapAttachment()
            existing.host_loops = loops
            host_map[name].traps = existing

    def _apply_credential_chains(self, payload: Dict[str, Any]) -> None:
        chains = payload.get("chains", []) or []
        for host in self.short_memory.hosts:
            attachment = host.traps or TrapAttachment()
            attachment.credential_chains = chains
            host.traps = attachment

    def _persist_traps(self) -> None:
        """Persist traps to a standalone trap memory file for downstream use."""
        payload = {
            "hosts": [
                {
                    "name": host.name,
                    "host_loops": (host.traps.host_loops if host.traps else []),  # type: ignore[union-attr]
                }
                for host in self.short_memory.hosts
            ],
            "chains": self._collect_chains(),
        }
        path = self.config.trap_memory_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _collect_chains(self) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        for host in self.short_memory.hosts:
            if host.traps and host.traps.credential_chains:
                chains = host.traps.credential_chains
                break
        return chains

    # -------------------------------------------------------------- helpers

    def _require_hosts(self) -> List[HostNode]:
        if not self.short_memory.hosts:
            raise RuntimeError(
                f"No hosts found in short-term memory at {self.config.short_memory_path}. "
                "Run Honey Agent first to populate the tree."
            )
        return list(self.short_memory.hosts)

    def _load_preferences(self) -> List[str]:
        data = _read_json(self.config.preferences_path)
        if isinstance(data, list):
            return [str(item) for item in data if isinstance(item, (str, int, float))]
        return ["credential reuse", "pivot to crown jewels", "escape detection"]

    # -------------------------------------------------------------- openai client

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


__all__ = ["TrapAgent", "TrapAgentConfig"]
