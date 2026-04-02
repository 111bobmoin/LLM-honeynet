"""
OpenAI LLM Client Module.
Provides a shared interface for OpenAI chat completions across the project.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment]


@dataclass
class OpenAIClientConfig:
    """Configuration for the OpenAI client."""

    api_key_path: Path = Path("secrets/openai_api_key.txt")
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    top_p: float = 0.9
    max_tokens: Optional[int] = None
    base_url: Optional[str] = None
    mock_mode: bool = False


class OpenAIClient:
    """Thin wrapper around the OpenAI chat completions API."""

    def __init__(self, config: Optional[OpenAIClientConfig] = None) -> None:
        self.config = config or OpenAIClientConfig()
        self._client: Optional[Any] = None

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Create a chat completion through the OpenAI API."""
        if self.config.mock_mode:
            return self._mock_completion(messages, response_format)

        client = self._lazy_client()
        if client is None:
            raise RuntimeError(
                "OpenAI client is unavailable. Install the openai package and configure secrets/openai_api_key.txt."
            )

        resolved_model = model or self.config.model
        params: Dict[str, Any] = {
            "model": resolved_model,
            "messages": messages,
        }

        if temperature is not None:
            params["temperature"] = temperature
        elif self.config.temperature is not None:
            params["temperature"] = self.config.temperature

        if top_p is not None:
            params["top_p"] = top_p
        elif self.config.top_p is not None:
            params["top_p"] = self.config.top_p

        if max_tokens is not None:
            params["max_tokens"] = max_tokens
        elif self.config.max_tokens is not None:
            params["max_tokens"] = self.config.max_tokens

        if response_format is not None:
            params["response_format"] = response_format

        params.update(kwargs)

        try:
            response = client.chat.completions.create(**params)
        except Exception as exc:
            raise RuntimeError(f"Failed to call OpenAI API: {exc}") from exc

        if not response or not getattr(response, "choices", None):
            raise RuntimeError("OpenAI API returned an empty response.")

        content = response.choices[0].message.content or ""
        if response_format and response_format.get("type") == "json_object":
            content = self._clean_markdown_json(content)

        return {
            "content": content.strip(),
            "model": resolved_model,
            "usage": getattr(response, "usage", None),
            "raw_response": response,
        }

    def is_available(self) -> bool:
        """Check whether the client can make real API calls."""
        if self.config.mock_mode:
            return True
        return self._lazy_client() is not None

    def _lazy_client(self) -> Optional[Any]:
        if self._client is False:
            return None
        if self._client is not None:
            return self._client

        if OpenAI is None:
            self._client = False
            return None

        api_key = self._load_api_key()
        if not api_key:
            self._client = False
            return None

        kwargs: Dict[str, Any] = {"api_key": api_key}
        if self.config.base_url:
            kwargs["base_url"] = self.config.base_url

        try:
            self._client = OpenAI(**kwargs)
            return self._client
        except Exception:
            self._client = False
            return None

    def _load_api_key(self) -> str:
        try:
            if self.config.api_key_path.exists():
                return self.config.api_key_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _clean_markdown_json(content: str) -> str:
        content = re.sub(r"```json\s*", "", content)
        content = re.sub(r"^```\s*", "", content, flags=re.MULTILINE)
        content = re.sub(r"```\s*$", "", content)
        content = content.strip()

        start_idx = content.find("{")
        end_idx = content.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            content = content[start_idx : end_idx + 1]

        return content

    def _mock_completion(
        self,
        messages: List[Dict[str, str]],
        response_format: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Generate deterministic mock output when explicitly enabled."""
        prompt = " ".join(message.get("content", "") for message in messages).lower()
        if response_format and response_format.get("type") == "json_object":
            if "consistency" in prompt:
                content = json.dumps(
                    {"summary": "Mock audit", "issues": [], "confidence": "low"},
                    ensure_ascii=False,
                )
            else:
                content = json.dumps(
                    {"status": "mock", "note": "Enable a real OpenAI API key for production output."},
                    ensure_ascii=False,
                )
        else:
            content = "Mock response. Configure secrets/openai_api_key.txt for real OpenAI output."

        return {
            "content": content,
            "model": "mock-openai",
            "usage": {"total_tokens": 0},
            "raw_response": None,
            "mock": True,
        }


def create_openai_client(
    api_key_path: Optional[Path] = None,
    model: str = "gpt-4o-mini",
    temperature: float = 0.1,
    top_p: float = 0.9,
) -> OpenAIClient:
    """Create a configured OpenAI client."""
    config = OpenAIClientConfig(
        api_key_path=api_key_path or Path("secrets/openai_api_key.txt"),
        model=model,
        temperature=temperature,
        top_p=top_p,
    )
    return OpenAIClient(config)


def chat_completion_simple(
    prompt: str,
    system_message: Optional[str] = None,
    model: str = "gpt-4o-mini",
    temperature: float = 0.1,
    api_key_path: Optional[Path] = None,
) -> str:
    """Simple helper for one-shot chat completions."""
    client = create_openai_client(
        api_key_path=api_key_path,
        model=model,
        temperature=temperature,
    )

    messages: List[Dict[str, str]] = []
    if system_message:
        messages.append({"role": "system", "content": system_message})
    messages.append({"role": "user", "content": prompt})

    response = client.chat_completion(messages)
    return response["content"]


__all__ = [
    "OpenAIClient",
    "OpenAIClientConfig",
    "create_openai_client",
    "chat_completion_simple",
]
