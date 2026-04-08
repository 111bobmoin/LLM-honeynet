from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .analyzer import HostAnalysis
from llm.openai_client import normalize_usage

DEFAULT_KEY_PATH = Path("secrets/openai_api_key.txt")
DEFAULT_MODEL = "gpt-5.4-mini"


class OpenAISummarizer:
    def __init__(self, api_key_path: Path = DEFAULT_KEY_PATH, model: str = DEFAULT_MODEL):
        self.api_key_path = api_key_path
        self.model = model
        self._client = None

    def is_configured(self) -> bool:
        return self.api_key_path.exists() and self.api_key_path.read_text(encoding="utf-8").strip() != ""

    def summarize(self, analyses: Iterable[HostAnalysis]) -> str:
        return self.summarize_with_usage(analyses)["summary"]

    def summarize_with_usage(self, analyses: Iterable[HostAnalysis]) -> dict:
        analyses = list(analyses)
        if not analyses:
            return {"summary": "No host analyses provided.", "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        if not self.is_configured():
            return {
                "summary": "OpenAI API key not configured. Populate secrets/openai_api_key.txt to enable preference summaries.",
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }

        client = self._lazy_client()
        prompt = self._build_prompt(analyses)
        try:
            response = client.responses.create(
                model=self.model,
                input=prompt,
            )
            return {
                "summary": response.output_text.strip(),
                "usage": normalize_usage(getattr(response, "usage", None)),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "summary": f"Failed to contact OpenAI API: {exc}",
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }

    def _lazy_client(self):
        if self._client is not None:
            return self._client

        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("openai package is required for OpenAI summaries.") from exc

        api_key = self.api_key_path.read_text(encoding="utf-8").strip()
        if not api_key:
            raise RuntimeError("OpenAI API key file is empty.")
        self._client = OpenAI(api_key=api_key)
        return self._client

    def _build_prompt(self, analyses: Iterable[HostAnalysis]) -> list[dict[str, str]]:
        hosts_payload = []
        for analysis in analyses:
            hosts_payload.append(
                {
                    "host": analysis.host,
                    "max_stage": analysis.max_stage,
                    "events": [
                        {
                            "timestamp": event.timestamp.isoformat(),
                            "stage": event.stage,
                            "summary": event.summary(),
                        }
                        for event in analysis.events
                        if event.stage
                    ],
                }
            )
        instructions = (
            "You are part of a defensive honeynet.\n"
            "Each host lists the observed intrusion stages (1-5) and sample events. "
            "Infer the attacker's objectives and capability maturity. "
            "Highlight preferred protocols, exploited services, and whether lateral movement or data theft was successful. "
            "Respond in concise bullet points per host followed by an overall assessment."
        )
        return [
            {"role": "system", "content": instructions},
            {"role": "user", "content": json.dumps({"hosts": hosts_payload}, ensure_ascii=False)},
        ]
