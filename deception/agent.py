from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment]

from orchestrator import LongTermMemory, ShortTermMemory, default_long_term


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_topology(shadow_root: Path, enterprise_root: Path) -> Dict[str, Any]:
    shadow_path = shadow_root / "shadow_topology.json"
    if shadow_path.exists():
        topo = _read_json(shadow_path)
        if topo:
            return topo
    enterprise_path = enterprise_root / "enterprise_topology.json"
    if enterprise_path.exists():
        topo = _read_json(enterprise_path)
        if topo:
            return topo
    return {}


@dataclass
class DeceptionAgentConfig:
    rag_root: Path = Path("shadow")
    enterprise_root: Path = Path("enterprise")
    short_memory_path: Path = Path("shadow/honey_agent.json")
    long_memory_path: Path = Path("shadow/long_memory.json")
    trap_memory_path: Path = Path("shadow/trap_agent.json")
    preferences_path: Path = Path("shadow/attacker_preferences.json")
    consistency_report_path: Path = Path("shadow/deception_consistency_report.json")
    deployments_root: Path = Path("deployments")
    base_config_dir: Path = Path("config")
    openai_key_path: Path = Path("secrets/openai_api_key.txt")
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.1
    openai_top_p: float = 0.9
    extra_context: Dict[str, Any] = field(default_factory=dict)


class DeceptionAgent:
    def __init__(self, config: Optional[DeceptionAgentConfig] = None) -> None:
        self.config = config or DeceptionAgentConfig()
        self._openai_client: Optional[Any] = None
        self.short_memory = ShortTermMemory(self.config.short_memory_path)
        self.long_memory = LongTermMemory(self.config.long_memory_path, builtin=default_long_term())
        self.trap_memory = self._load_trap_memory(self.config.trap_memory_path)
        self.preferences = self._load_preferences(self.config.preferences_path)

    # ------------------------------------------------------------------ public API

    def run_consistency_check(self, save: bool = True) -> Dict[str, Any]:
        payload = self._build_consistency_payload()
        report = self._invoke_llm(
            stage="consistency",
            instructions=CONSISTENCY_PROMPT,
            context=payload,
        )
        if save:
            _ensure_dir(self.config.consistency_report_path)
            self.config.consistency_report_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        return report

    def generate_host_configs(self, hosts: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
        target_hosts = set(h.lower() for h in hosts) if hosts else None
        outputs: Dict[str, Dict[str, Any]] = {}
        for host_dir in sorted(self.config.deployments_root.iterdir()):
            if not host_dir.is_dir():
                continue
            host_name = host_dir.name
            if target_hosts is not None and host_name.lower() not in target_hosts:
                continue
            context = self._build_host_context(host_name, host_dir)
            if not context:
                continue
            response = self._invoke_llm(
                stage="host-config",
                instructions=HOST_CONFIG_PROMPT,
                context=context,
            )
            self._apply_host_config(host_name, host_dir, response)
            outputs[host_name] = response
        return outputs

    # ------------------------------------------------------------------ helpers

    def _build_consistency_payload(self) -> Dict[str, Any]:
        port_numbers = {port.port for host in self.short_memory.hosts for port in host.ports}
        return {
            "short_memory": [host.to_dict() for host in self.short_memory.hosts],
            "long_term_port_facts": self.long_memory.relevant_port_facts(port_numbers),
            "attacker_preferences": self.preferences,
            "traps": self.trap_memory,
            "topology": _load_topology(self.config.rag_root, self.config.enterprise_root),
            "extra_context": self.config.extra_context,
        }

    def _build_host_context(self, host: str, host_dir: Path) -> Optional[Dict[str, Any]]:
        host_node = next((h for h in self.short_memory.hosts if h.name == host), None)
        if not host_node:
            return None
        trap_loops = self._lookup_host_loops(host)
        trap_chains = self.trap_memory.get("chains", [])

        base_configs = self._load_base_configs(host_dir)
        raw_service_templates = {
            name: cfg for name, cfg in base_configs.items() if name.endswith("_config.json")
        }
        service_templates = {
            name.replace("_config.json", ""): cfg for name, cfg in raw_service_templates.items()
        }
        filesystem_template = base_configs.get("filesystem.json")
        filesystem = self._load_filesystem(host_dir)
        service_fields = {name: list(cfg.keys()) for name, cfg in service_templates.items()}
        port_numbers = {port.port for port in host_node.ports}
        return {
            "host": host,
            "memory": host_node.to_dict(),
            "trap_loops": trap_loops,
            "trap_chains": trap_chains,
            "attacker_preferences": self.preferences,
            "long_term_port_facts": self.long_memory.relevant_port_facts(port_numbers),
            "service_templates": service_templates,
            "service_fields": service_fields,
            "filesystem_template": filesystem_template,
            "existing_filesystem": filesystem,
            "consistency_report": _read_json(self.config.consistency_report_path),
        }

    def _load_base_configs(self, host_dir: Path) -> Dict[str, Any]:
        config_dir = host_dir / "config"
        if not config_dir.exists():
            config_dir = self.config.base_config_dir
        result: Dict[str, Any] = {}
        for file in sorted(config_dir.glob("*_config.json")):
            try:
                result[file.name] = json.loads(file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
        filesystem_path = config_dir / "filesystem.json"
        if filesystem_path.exists():
            fs = _read_json(filesystem_path)
            if fs:
                result["filesystem.json"] = fs
        return result

    def _load_filesystem(self, host_dir: Path) -> Optional[Dict[str, Any]]:
        path = host_dir / "config" / "filesystem.json"
        if not path.exists():
            path = self.config.base_config_dir / "filesystem.json"
        return _read_json(path)

    def _load_trap_memory(self, path: Path) -> Dict[str, Any]:
        data = _read_json(path)
        if isinstance(data, dict):
            return data
        return {"hosts": [], "chains": []}

    def _load_preferences(self, path: Path) -> List[str]:
        data = _read_json(path)
        if isinstance(data, list):
            return [str(item) for item in data if isinstance(item, (str, int, float))]
        return []

    def _lookup_host_loops(self, host: str) -> List[List[str]]:
        for entry in self.trap_memory.get("hosts", []):
            if isinstance(entry, dict) and entry.get("name") == host:
                return entry.get("host_loops", []) or []
        return []

    def _apply_host_config(self, host: str, host_dir: Path, data: Dict[str, Any]) -> None:
        config_dir = host_dir / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        base_configs = self._load_base_configs(host_dir)
        raw_service_templates = {
            name: cfg for name, cfg in base_configs.items() if name.endswith("_config.json")
        }
        base_filesystem = base_configs.get("filesystem.json")

        services: Dict[str, Any] = data.get("services") or {}
        for service_name, cfg in services.items():
            path = config_dir / f"{service_name}_config.json"
            _ensure_dir(path)
            base_cfg = raw_service_templates.get(f"{service_name}_config.json")
            final_cfg = self._merge_dicts(base_cfg, cfg) if base_cfg else cfg
            path.write_text(json.dumps(final_cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        filesystem = data.get("filesystem")
        if filesystem:
            fs_path = config_dir / "filesystem.json"
            _ensure_dir(fs_path)
            final_fs = self._merge_dicts(base_filesystem, filesystem) if base_filesystem else filesystem
            fs_path.write_text(json.dumps(final_fs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        notes = data.get("notes")
        if notes:
            note_path = host_dir / "deception_notes.json"
            note_path.write_text(json.dumps(notes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # ------------------------------------------------------------------ OpenAI helpers

    def _invoke_llm(self, *, stage: str, instructions: str, context: Dict[str, Any]) -> Dict[str, Any]:
        client = self._lazy_openai_client()
        if client is None:
            raise RuntimeError(
                f"OpenAI client unavailable. Provide a valid API key and install the openai package to run {stage}."
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
            raise RuntimeError(f"Failed to run deception {stage} via OpenAI: {exc}") from exc

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

    def _merge_dicts(self, base: Optional[Dict[str, Any]], override: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(base, dict):
            base = {}
        merged = json.loads(json.dumps(base))
        for key, value in override.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._merge_dicts(merged[key], value)
            else:
                merged[key] = value
        return merged


CONSISTENCY_PROMPT = (
    "You are a deception auditor reviewing a compact short-term memory tree for a honeynet. "
    "Evaluate the hosts, ports, files, vulnerabilities, and attached traps for internal conflicts, missing references, "
    "or signals that would reveal the deception. Use long_term_port_facts for plausibility checks only when relevant. "
    "Check: ports with impossible banners, files that do not fit the parent port/service, vulnerabilities that do not "
    "reference their file, trap loops pointing to non-existent files, and credential chains that do not loop attackers back. "
    "Respond as JSON {summary, issues[], confidence} where issues are brief strings."
)

HOST_CONFIG_PROMPT = (
    "You are a deception orchestrator generating host-specific honeypot configurations. "
    "Use the provided short-term memory for this host (memory) plus long_term_port_facts and service_templates to craft "
    "updated configurations. When modifying a service, return a JSON object containing every required field defined in "
    "service_fields; reuse defaults from the template where unchanged. You may omit services that do not need updates. "
    "For filesystem updates, output only the nodes that should be added or edited, following the template structure "
    "(root directory with nested children objects). Avoid inventing unsupported keys. "
    "Return valid JSON with shape {host, services, filesystem, notes}, where services is a dictionary keyed by service name "
    "(ssh, telnet, ftp, http, https, mysql). Notes should be a short list summarising important decisions. "
    "Preserve declared ports unless there is a justified reason to change them."
)
