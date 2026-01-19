from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

STAGES = ["stage1", "stage2", "stage3", "stage4", "stage5"]
RECON_COMMANDS = {
    "uname",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
    "route",
    "nmap",
    "ping",
    "traceroute",
    "whoami",
    "id",
}
PRIVILEGED_COMMANDS = {
    "systemctl",
    "service",
    "docker",
    "kubectl",
    "mysql",
    "psql",
    "redis-cli",
    "mongosh",
    "gradlew",
    "npm",
    "yarn",
}
SENSITIVE_PATH_KEYWORDS = {
    "internal",
    "collect",
    "metrics",
    "billing",
    "payment",
    "customer",
    "orders",
    "admin",
    "bastion",
    "secure",
    "portal",
}
HONEYFILE_KEYWORDS = {
    "runbook",
    "backup",
    "snapshot",
    "secret",
    "credential",
    "password",
    "readme",
    "notes",
    ".tar",
    ".gz",
    ".zip",
    "financial",
    "invoice",
}
DEFAULT_HONEYFILES = {
    "/root/readme.md",
    "/var/service/runbook.txt",
    "/srv/ftp/backups/snapshot-2024-04-10.tar.gz",
}


@dataclass
class StageIndicator:
    events: Set[str] = field(default_factory=set)
    keywords: Set[str] = field(default_factory=set)
    success_required: Optional[bool] = None
    commands: Set[str] = field(default_factory=set)
    http_paths: Set[str] = field(default_factory=set)
    honeyfile: bool = False

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "StageIndicator":
        return cls(
            events=set(payload.get("events", [])),
            keywords=set(k.lower() for k in payload.get("keywords", [])),
            success_required=payload.get("success_required"),
            commands=set(c.lower() for c in payload.get("commands", [])),
            http_paths=set(payload.get("http_paths", [])),
            honeyfile=payload.get("honeyfile", False),
        )

    def merge(self, other: "StageIndicator") -> None:
        self.events |= other.events
        self.keywords |= other.keywords
        self.commands |= other.commands
        self.http_paths |= other.http_paths
        self.honeyfile = self.honeyfile or other.honeyfile
        if other.success_required is not None:
            self.success_required = other.success_required


@dataclass
class Rules:
    honeyfiles: Set[str]
    stage_indicators: Dict[str, StageIndicator]

    def stage(self, name: str) -> StageIndicator:
        return self.stage_indicators.get(name, StageIndicator())


def load_rules(config_dir: Path, external_rules: Optional[Path] = None) -> Rules:
    config_dir = config_dir.resolve()
    dynamic_rules = build_dynamic_rules(config_dir)
    stage_indicators = dynamic_rules.stage_indicators
    honeyfiles = set(dynamic_rules.honeyfiles)

    override_paths = []
    if external_rules and external_rules.exists():
        override_paths.append(external_rules)
    host_override = config_dir / "perception_rules.json"
    if host_override.exists():
        override_paths.append(host_override)

    for override_path in override_paths:
        data = json.loads(Path(override_path).read_text(encoding="utf-8"))
        if "honeyfiles" in data:
            honeyfiles |= {normalize_path(path) for path in data["honeyfiles"]}
        for name, payload in data.get("stage_indicators", {}).items():
            indicator = StageIndicator.from_dict(payload)
            stage_indicators.setdefault(name.lower(), StageIndicator()).merge(indicator)

    for stage in STAGES:
        stage_indicators.setdefault(stage, StageIndicator())

    return Rules(honeyfiles=honeyfiles, stage_indicators=stage_indicators)


def build_dynamic_rules(config_dir: Path) -> Rules:
    http_paths, sensitive_paths = parse_http_configs(config_dir)
    privileged_users, all_users = parse_auth_configs(config_dir)
    recon_commands, privileged_commands = parse_command_surfaces(config_dir)
    honeyfiles = infer_honeyfiles(config_dir)

    stage_indicators: Dict[str, StageIndicator] = {stage: StageIndicator() for stage in STAGES}

    # Stage 1: Exploitation / initial access
    stage_indicators["stage1"].events |= {"request", "login_attempt"}
    stage_indicators["stage1"].http_paths |= http_paths

    # Stage 2: Privilege escalation
    stage_indicators["stage2"].events.add("login_attempt")
    stage_indicators["stage2"].success_required = True
    stage_indicators["stage2"].keywords |= privileged_users

    # Stage 3: Lateral movement / reconnaissance
    stage_indicators["stage3"].events.add("command")
    stage_indicators["stage3"].commands |= recon_commands

    # Stage 4: Honeyfile theft
    stage_indicators["stage4"].honeyfile = True

    # Stage 5: Business system intrusion
    stage_indicators["stage5"].events |= {"command", "request"}
    stage_indicators["stage5"].commands |= privileged_commands
    stage_indicators["stage5"].http_paths |= sensitive_paths
    stage_indicators["stage5"].keywords |= set(SENSITIVE_PATH_KEYWORDS)
    stage_indicators["stage5"].keywords |= set(HONEYFILE_KEYWORDS)

    return Rules(honeyfiles=honeyfiles, stage_indicators=stage_indicators)


def parse_http_configs(config_dir: Path) -> Tuple[Set[str], Set[str]]:
    http_paths: Set[str] = set()
    sensitive_paths: Set[str] = set()
    for filename in ("http_config.json", "https_config.json"):
        path = config_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for route in data.get("routes", []):
            route_path = normalize_path(route.get("path", "/"))
            http_paths.add(route_path)
            if any(keyword in route_path for keyword in SENSITIVE_PATH_KEYWORDS):
                sensitive_paths.add(route_path)
        if data.get("not_found", {}).get("path"):
            http_paths.add(normalize_path(data["not_found"]["path"]))
    return http_paths, sensitive_paths


def parse_auth_configs(config_dir: Path) -> Tuple[Set[str], Set[str]]:
    privileged_users: Set[str] = set()
    all_users: Set[str] = set()
    auth_files = {
        "ssh_config.json": {"privileged": {"root", "admin", "deploy", "operator", "service"}},
        "telnet_config.json": {"privileged": {"service", "root", "admin"}},
        "ftp_config.json": {"privileged": {"deploy", "admin"}},
    }
    for filename, config in auth_files.items():
        path = config_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        users = data.get("users", {})
        for username, details in users.items():
            normalized = username.lower()
            all_users.add(normalized)
            if normalized in config["privileged"]:
                privileged_users.add(normalized)
            home = normalize_path(details.get("home", ""))
            if home.startswith("/root") or "/backups" in home or "/var" in home:
                privileged_users.add(normalized)
    return privileged_users, all_users


def parse_command_surfaces(config_dir: Path) -> Tuple[Set[str], Set[str]]:
    recon: Set[str] = set()
    privileged: Set[str] = set()
    for filename in ("ssh_config.json", "telnet_config.json"):
        path = config_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        fake_commands = data.get("fake_commands", {})
        for command in fake_commands:
            cmd = command.split()[0].lower()
            if cmd in RECON_COMMANDS:
                recon.add(cmd)
            if cmd in PRIVILEGED_COMMANDS:
                privileged.add(cmd)
    return recon, privileged


def infer_honeyfiles(config_dir: Path) -> Set[str]:
    filesystem_path = config_dir / "filesystem.json"
    honeyfiles: Set[str] = set()
    if filesystem_path.exists():
        try:
            data = json.loads(filesystem_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        root = data.get("root")
        if root:
            for path, node in walk_filesystem(root):
                if node.get("type", "file") == "file":
                    normalized = normalize_path(path)
                    if any(keyword in normalized for keyword in HONEYFILE_KEYWORDS):
                        honeyfiles.add(normalized)
    if not honeyfiles:
        honeyfiles = {normalize_path(path) for path in DEFAULT_HONEYFILES}
    return honeyfiles


def walk_filesystem(node: Dict[str, Any], current_path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    name = node.get("name") or ""
    node_path = current_path
    if name:
        node_path = f"{current_path}/{name}".replace("//", "/")
    node_type = node.get("type", "file")
    if node_type == "file":
        yield node_path or "/", node
    elif node_type == "directory":
        children = node.get("children", {}) or {}
        for child_name, child_spec in children.items():
            child_spec = dict(child_spec)
            child_spec["name"] = child_name
            yield from walk_filesystem(child_spec, node_path or "/")


def normalize_path(value: str) -> str:
    return value.strip().lower()
