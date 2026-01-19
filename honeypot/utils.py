from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def timestamp() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"
