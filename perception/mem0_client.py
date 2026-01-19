from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .analyzer import HostAnalysis

DEFAULT_KEY_PATH = Path("secrets/mem0_api_key.txt")


class Mem0Client:
    """Wrapper around mem0 MemoryClient for storing attacker summaries."""

    def __init__(
        self,
        api_key_path: Optional[Path] = None,
        user_id: str = "honeypot",
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key_path = api_key_path or DEFAULT_KEY_PATH
        self.user_id = user_id
        self.base_url = base_url
        self._client = None

    def is_configured(self) -> bool:
        try:
            return self.api_key_path.exists() and self.api_key_path.read_text(encoding="utf-8").strip() != ""
        except OSError:
            return False

    def store_summary(self, analyses: Iterable[HostAnalysis], summary: str) -> str:
        payload = self._build_payload(analyses, summary)
        if not payload:
            return "No host analyses to store."
        if not self.is_configured():
            return "Mem0 API key not configured. Populate secrets/mem0_api_key.txt to enable persistence."

        client = self._lazy_client()
        message = json.dumps(payload, ensure_ascii=False)

        try:
            response = client.add(message, user_id=self.user_id)
        except Exception as exc:  # noqa: BLE001
            return f"Failed to persist summary via mem0: {exc}"

        if isinstance(response, dict) and "results" in response:
            count = len(response["results"])
            return f"Mem0 stored {count} item(s)."
        return "Mem0 request submitted."

    def _build_payload(self, analyses: Iterable[HostAnalysis], summary: str) -> Optional[dict[str, object]]:
        analyses = list(analyses)
        if not analyses:
            return None
        return {
            "summary": summary,
            "hosts": [
                {
                    "host": analysis.host,
                    "max_stage": analysis.max_stage,
                    "events": [
                        {
                            "ts": event.timestamp.isoformat(),
                            "stage": event.stage,
                            "summary": event.summary(),
                        }
                        for event in analysis.events
                        if event.stage
                    ],
                }
                for analysis in analyses
            ],
        }

    def _lazy_client(self):
        if self._client is not None:
            return self._client

        try:
            from mem0 import MemoryClient
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("mem0ai package is required for mem0 integration.") from exc

        api_key = self.api_key_path.read_text(encoding="utf-8").strip()
        if not api_key:
            raise RuntimeError("Mem0 API key file is empty.")

        kwargs = {"api_key": api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client = MemoryClient(**kwargs)
        return self._client
