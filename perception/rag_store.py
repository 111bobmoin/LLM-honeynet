from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


class ShadowRAGStore:
    """Lightweight JSON-based RAG cache for short-term topology memory."""

    def __init__(self, store_path: Path | None = None) -> None:
        self.store_path = store_path or Path("shadow/rag_memory.json")
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.store_path.exists():
            self._write({"entries": []})

    def add_topology(self, topology: Dict[str, Any], source: str) -> None:
        payload = self._read()
        payload.setdefault("entries", []).append(
            {
                "type": "topology",
                "source": source,
                "topology": topology,
            }
        )
        self._write(payload)

    def _read(self) -> Dict[str, Any]:
        with self.store_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, data: Dict[str, Any]) -> None:
        with self.store_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
