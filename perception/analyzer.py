from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .rules import Rules, normalize_path


@dataclass
class HostEvent:
    timestamp: datetime
    raw: Dict
    stage: Optional[str] = None
    source: Optional[Path] = None

    def summary(self) -> str:
        pieces = [self.raw.get("event", "")]
        if "service" in self.raw:
            pieces.append(f"svc={self.raw['service']}")
        if "client" in self.raw:
            pieces.append(f"client={self.raw['client']}")
        if "command" in self.raw:
            pieces.append(f"cmd={self.raw['command']}")
        if "path" in self.raw:
            pieces.append(f"path={self.raw['path']}")
        if "success" in self.raw:
            pieces.append(f"success={self.raw['success']}")
        return " ".join(filter(None, pieces))


@dataclass
class HostAnalysis:
    host: str
    max_stage: int
    events: List[HostEvent] = field(default_factory=list)

    def stage_label(self) -> str:
        return f"stage{self.max_stage}" if self.max_stage else "none"


STAGE_ORDER = ["stage1", "stage2", "stage3", "stage4", "stage5"]


def analyze_host(host: str, logs_dir: Path, rules: Rules) -> HostAnalysis:
    events = []
    for log_path in sorted(logs_dir.glob("*.log")):
        events.extend(read_log(log_path))

    events.sort(key=lambda ev: ev.timestamp)
    max_stage = 0
    for event in events:
        stage = infer_stage(event, rules, max_stage)
        if stage:
            stage_num = stage_number(stage)
            if stage_num > max_stage:
                max_stage = stage_num
        event.stage = stage

    return HostAnalysis(host=host, max_stage=max_stage, events=events)


def read_log(path: Path) -> List[HostEvent]:
    events: List[HostEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(payload.get("ts"))
            events.append(HostEvent(timestamp=ts, raw=payload, source=path))
    return events


def parse_ts(value: Optional[str]) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.utcnow()


def infer_stage(event: HostEvent, rules: Rules, current_stage: int) -> Optional[str]:
    stages_to_check = list(reversed(STAGE_ORDER))
    for stage in stages_to_check:
        if evaluate_stage(stage, event, rules, current_stage):
            return stage
    return None


def evaluate_stage(stage: str, event: HostEvent, rules: Rules, current_stage: int) -> bool:
    indicator = rules.stage(stage)
    raw = event.raw
    event_name = raw.get("event", "").lower()
    text_blob = stringify_event(raw)
    command = raw.get("command", "").lower()
    http_path = raw.get("path", "").lower()
    success = raw.get("success")

    if stage == "stage5" and current_stage < 3:
        return False
    if stage == "stage4" and current_stage < 2:
        # allow stage4 if honeyfile accessed even without stage2 but prevents noise
        pass

    matched = False
    if indicator.honeyfile:
        if touches_honeyfile(raw, rules.honeyfiles):
            return True

    if indicator.events and event_name not in indicator.events:
        # allow commands to pass if command indicator present
        if not (indicator.commands and event_name == "command"):
            return False
    elif indicator.events:
        matched = True

    if indicator.success_required is not None:
        if success is not indicator.success_required:
            return False
        matched = True

    if indicator.commands and event_name == "command":
        if not any(command.startswith(cmd) for cmd in indicator.commands):
            return False
        matched = True

    if indicator.http_paths and raw.get("path"):
        if not any(http_path.startswith(prefix) for prefix in indicator.http_paths):
            return False
        matched = True

    if indicator.keywords:
        if not any(keyword in text_blob for keyword in indicator.keywords):
            return False
        matched = True

    return matched


def stringify_event(raw: Dict) -> str:
    parts = []
    for key, value in raw.items():
        if isinstance(value, (str, int, float, bool)):
            parts.append(str(value).lower())
    return " ".join(parts)


def touches_honeyfile(raw: Dict, honeyfiles: Iterable[str]) -> bool:
    paths = extract_paths(raw)
    for path in paths:
        if normalize_path(path) in honeyfiles:
            return True
        for honeyfile in honeyfiles:
            if honeyfile.endswith("*"):
                prefix = honeyfile.rstrip("*")
                if normalize_path(path).startswith(prefix.rstrip("/")):
                    return True
    return False


def extract_paths(raw: Dict) -> List[str]:
    paths = []
    if "path" in raw:
        paths.append(str(raw["path"]))
    if "command" in raw:
        paths.extend(token for token in raw["command"].split() if token.startswith("/"))
    if raw.get("event") == "request":
        paths.append(raw.get("path", ""))
    if raw.get("event") == "command" and raw.get("response"):
        # no additional paths
        pass
    return paths


def stage_number(stage: str) -> int:
    try:
        return int(stage.replace("stage", ""))
    except ValueError:
        return 0
