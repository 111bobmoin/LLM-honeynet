"""
GLM (Zhipu AI) Summary Module for Perception Analysis
Replaces OpenAI-based summarization with GLM models
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .analyzer import HostAnalysis
from llm import GLMClient, GLMClientConfig

DEFAULT_KEY_PATH = Path("secrets/glm_api_key.txt")
DEFAULT_MODEL = "glm-4-flash"


class GLMSummarizer:
    """Summarize honeynet analysis using GLM (Zhipu AI) models."""

    def __init__(self, api_key_path: Path = DEFAULT_KEY_PATH, model: str = DEFAULT_MODEL):
        self.api_key_path = api_key_path
        self.model = model
        self._client = None

    def is_configured(self) -> bool:
        """Check if the API key is configured."""
        return self.api_key_path.exists() and self.api_key_path.read_text(encoding="utf-8").strip() != ""

    def summarize(self, analyses: Iterable[HostAnalysis]) -> str:
        """
        Generate a summary of host analyses.

        Args:
            analyses: Iterable of HostAnalysis objects

        Returns:
            Summary text as a string
        """
        analyses = list(analyses)
        if not analyses:
            return "No host analyses provided."

        if not self.is_configured():
            return (
                "GLM API key not configured. Populate secrets/glm_api_key.txt to enable preference summaries."
            )

        client = self._lazy_client()
        messages = self._build_prompt(analyses)

        try:
            response = client.chat_completion(
                messages=messages,
                model=self.model,
                temperature=0.3,  # Slightly higher for summaries
            )
            return response.get("content", "").strip()
        except Exception as exc:  # noqa: BLE001
            return f"Failed to contact GLM API: {exc}"

    def _lazy_client(self) -> Optional[GLMClient]:
        """Lazy initialization of the GLM client."""
        if self._client is not None:
            return self._client

        config = GLMClientConfig(
            api_key_path=self.api_key_path,
            model=self.model,
        )
        self._client = GLMClient(config)

        if not self._client.is_available():
            raise RuntimeError("GLM client is not available. Please install zhipuai package and configure API key.")

        return self._client

    def _build_prompt(self, analyses: list[HostAnalysis]) -> list[dict[str, str]]:
        """Build the prompt for summarization."""
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


__all__ = ["GLMSummarizer"]
