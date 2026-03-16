"""
GLM (Zhipu AI) LLM Client Module
Provides unified interface for GLM API calls to replace OpenAI
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - optional dependency
    from zhipuai import ZhipuAI
except Exception:  # noqa: BLE001
    ZhipuAI = None  # type: ignore[assignment]


@dataclass
class GLMClientConfig:
    """Configuration for GLM client"""
    api_key_path: Path = Path("secrets/glm_api_key.txt")
    model: str = "glm-4-flash"  # Default fast model, alternatives: glm-4, glm-4-plus
    temperature: float = 0.1
    top_p: float = 0.9
    max_tokens: Optional[int] = None
    base_url: Optional[str] = None  # For custom endpoints
    mock_mode: bool = False  # Enable mock mode for testing without API


class GLMClient:
    """
    Unified GLM (Zhipu AI) client for LLM API calls.

    This client provides a similar interface to OpenAI's Python SDK
    but uses Zhipu AI's GLM models instead.
    """

    # Default model mappings
    MODEL_MAP = {
        "gpt-4o-mini": "glm-4-flash",      # Fast, cost-effective
        "gpt-4o": "glm-4",                 # Standard model
        "gpt-4o-plus": "glm-4-plus",       # Advanced model
        "gpt-3.5-turbo": "glm-4-flash",    # Legacy compatibility
    }

    def __init__(self, config: Optional[GLMClientConfig] = None) -> None:
        self.config = config or GLMClientConfig()
        self._client: Optional[Any] = None

    # ==================== Public API ====================

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a chat completion using GLM API.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name (will be mapped to GLM equivalent if needed)
            temperature: Sampling temperature
            top_p: Nucleus sampling parameter
            max_tokens: Maximum tokens to generate
            response_format: Response format (e.g., {"type": "json_object"})
            **kwargs: Additional parameters

        Returns:
            Response dict with 'content' key containing the generated text

        Raises:
            RuntimeError: If client is not available or API call fails
        """
        # Check for mock mode first
        if self.config.mock_mode or not self._is_zhipuai_available():
            return self._mock_completion(messages, response_format)

        client = self._lazy_client()
        if not client:
            # Fall back to mock mode if client unavailable
            return self._mock_completion(messages, response_format)

        # Map model name to GLM equivalent
        glm_model = self._map_model(model or self.config.model)

        # Prepare parameters
        params = {
            "model": glm_model,
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

        # Handle JSON mode for GLM
        if response_format and response_format.get("type") == "json_object":
            # GLM uses a different parameter for JSON mode
            params["tools"] = [{
                "type": "web_search",
                "web_search": {"enable": False}
            }]
            # Add instruction for JSON response
            if messages and messages[0].get("role") == "system":
                messages[0]["content"] += " Respond strictly as JSON with no extra prose."
            else:
                messages.insert(0, {
                    "role": "system",
                    "content": "Respond strictly as JSON with no extra prose."
                })

        params.update(kwargs)

        try:
            response = client.chat.completions.create(**params)
        except Exception as exc:
            raise RuntimeError(f"Failed to call GLM API: {exc}") from exc

        # Extract content from response
        if not response or not hasattr(response, "choices") or not response.choices:
            raise RuntimeError("GLM API returned empty response")

        content = response.choices[0].message.content or ""

        # Clean up markdown code blocks that GLM sometimes returns
        content = self._clean_markdown_json(content)

        return {
            "content": content,
            "model": glm_model,
            "usage": getattr(response, "usage", None),
            "raw_response": response
        }

    def _clean_markdown_json(self, content: str) -> str:
        """Clean markdown code blocks from JSON responses"""
        import re

        # Remove markdown code blocks (```json ... ```)
        content = re.sub(r'```json\s*', '', content)
        content = re.sub(r'```\s*$', '', content)
        content = re.sub(r'^```\s*', '', content, flags=re.MULTILINE)

        # Remove any leading/trailing whitespace
        content = content.strip()

        # Extract JSON if there's text before/after
        # Find first { and last }
        start_idx = content.find('{')
        end_idx = content.rfind('}')

        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            content = content[start_idx:end_idx + 1]

        return content

    def is_available(self) -> bool:
        """Check if the client is properly configured and available"""
        # In mock mode, always available
        if self.config.mock_mode:
            return True
        # If zhipuai is not installed, still return True (will use mock)
        if not self._is_zhipuai_available():
            return True
        # Otherwise check if real client is available
        try:
            return self._lazy_client() is not None
        except Exception:
            return False

    # ==================== Private Methods ====================

    def _lazy_client(self) -> Optional[Any]:
        """Lazy initialization of the GLM client"""
        if self._client is False:
            return None
        if self._client is not None:
            return self._client

        if ZhipuAI is None:
            self._client = False
            return None

        try:
            api_key = self._load_api_key()
            if not api_key:
                self._client = False
                return None

            self._client = ZhipuAI(api_key=api_key)
            return self._client
        except Exception:
            self._client = False
            return None

    def _load_api_key(self) -> str:
        """Load API key from file"""
        try:
            if self.config.api_key_path.exists():
                return self.config.api_key_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        return ""

    def _map_model(self, model: str) -> str:
        """Map OpenAI model names to GLM equivalents"""
        # Direct mapping
        if model in self.MODEL_MAP:
            return self.MODEL_MAP[model]

        # If it's already a GLM model, return as-is
        if model.startswith("glm-"):
            return model

        # Default to fast model
        return "glm-4-flash"

    def _is_zhipuai_available(self) -> bool:
        """Check if zhipuai package is available"""
        return ZhipuAI is not None

    def _mock_completion(self, messages: List[Dict[str, str]], response_format: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Generate mock completion for testing without API.

        This provides realistic mock responses based on the system prompt context.
        """
        system_prompt = ""
        user_content = ""

        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            elif msg.get("role") == "user":
                user_content = msg.get("content", "")

        # Generate mock response based on context
        mock_content = self._generate_mock_response(system_prompt, user_content, response_format)

        return {
            "content": mock_content,
            "model": "mock-glm-4-flash",
            "usage": {"total_tokens": 100},
            "raw_response": None,
            "mock": True
        }

    def _generate_mock_response(self, system_prompt: str, user_content: str, response_format: Optional[Dict[str, str]] = None) -> str:
        """Generate contextually appropriate mock responses"""
        import json as json_lib

        # Check if this is a JSON request
        is_json = response_format and response_format.get("type") == "json_object"
        is_json = is_json or "JSON" in system_prompt or "json" in system_prompt

        # Detect context from prompts
        prompt_lower = (system_prompt + " " + user_content).lower()

        # Helper: Extract host names from user content
        def extract_hosts():
            try:
                user_data = json_lib.loads(user_content)
                if "hosts" in user_data:
                    hosts = [h.get("name", "") for h in user_data["hosts"] if h.get("name")]
                    if hosts:
                        return hosts
            except:
                pass
            return ["honeypot-01", "honeypot-02"]

        # Trap Agent detection (most specific first)
        if is_json and ("trap" in prompt_lower or "tier" in prompt_lower or "credential" in prompt_lower):
            # This is likely a Trap Agent request
            hosts = extract_hosts()

            # Host loops request
            if "loop" in prompt_lower and "inter-host" not in prompt_lower:
                h1, h2 = hosts[0], hosts[1] if len(hosts) > 1 else hosts[0]
                return json_lib.dumps({
                    "hosts": [
                        {"name": h1, "loops": [
                            ["/home/user/.ssh/id_rsa", "/tmp/backup", "/home/user/.ssh/id_rsa"]
                        ]},
                        {"name": h2, "loops": [
                            ["/etc/mysql/my.cnf", "/var/backups/mysql", "/etc/mysql/my.cnf"]
                        ]}
                    ]
                }, ensure_ascii=False)

            # Inter-host chains request
            if "inter-host" in prompt_lower or "interhost" in prompt_lower or "tier" in prompt_lower:
                h1, h2 = hosts[0], hosts[1] if len(hosts) > 1 else hosts[0]
                return json_lib.dumps({
                    "chains": [
                        {"name": "lateral-chain-1", "steps": [
                            {"host": h1, "tier": "low"},
                            {"host": h2, "tier": "mid"},
                            {"host": h1, "tier": "low"}
                        ]}
                    ]
                }, ensure_ascii=False)

        # Honey Agent - Ports generation
        if "port" in prompt_lower and "host" in prompt_lower and "vulnern" not in prompt_lower:
            if is_json:
                return json_lib.dumps({
                    "hosts": [
                        {"name": "honeypot-01", "ports": [
                            {"port": 22, "service": "ssh"},
                            {"port": 80, "service": "http"}
                        ]},
                        {"name": "honeypot-02", "ports": [
                            {"port": 22, "service": "ssh"},
                            {"port": 3306, "service": "mysql"}
                        ]}
                    ]
                }, ensure_ascii=False)

        # Honey Agent - Files generation
        if "file" in prompt_lower and "path" in prompt_lower and "vulnern" not in prompt_lower:
            if is_json:
                return json_lib.dumps({
                    "hosts": [
                        {"name": "honeypot-01", "ports": [
                            {"port": 22, "service": "ssh", "files": [{"path": "/home/user/.ssh/id_rsa"}]},
                            {"port": 80, "service": "http", "files": [{"path": "/var/www/config.php"}]}
                        ]},
                        {"name": "honeypot-02", "ports": [
                            {"port": 22, "service": "ssh", "files": [{"path": "/etc/mysql/my.cnf"}]},
                            {"port": 3306, "service": "mysql", "files": [{"path": "/var/lib/mysql/mysql.conf"}]}
                        ]}
                    ]
                }, ensure_ascii=False)

        # Honey Agent - Vulnerabilities generation
        if "vulnern" in prompt_lower or "vuln" in prompt_lower:
            if is_json:
                return json_lib.dumps({
                    "hosts": [
                        {"name": "honeypot-01", "vulnerabilities": [
                            {"type": "weak credentials", "target_port": 22},
                            {"type": "config leak", "target_file": "/var/www/config.php"}
                        ]},
                        {"name": "honeypot-02", "vulnerabilities": [
                            {"type": "outdated ssh", "target_port": 22}
                        ]}
                    ]
                }, ensure_ascii=False)

        # Trap Agent - Host loops (more precise detection)
        if ("host-level trap loops" in prompt_lower or "host trap loop" in prompt_lower) and "inter-host" not in prompt_lower:
            if is_json:
                # Try to extract actual host names from user content
                host_list = []
                try:
                    import json as json_parse
                    user_data = json_parse.loads(user_content)
                    if "hosts" in user_data:
                        host_list = [h.get("name", "") for h in user_data["hosts"] if h.get("name")]
                except:
                    pass

                if not host_list:
                    host_list = ["honeypot-01", "honeypot-02"]

                h1, h2 = host_list[0], host_list[1] if len(host_list) > 1 else "honeypot-02"

                return json_lib.dumps({
                    "hosts": [
                        {"name": h1, "loops": [
                            ["/home/user/.ssh/id_rsa", "/tmp/backup", "/home/user/.ssh/id_rsa"]
                        ]},
                        {"name": h2, "loops": [
                            ["/etc/mysql/my.cnf", "/var/backups/mysql", "/etc/mysql/my.cnf"]
                        ]}
                    ]
                }, ensure_ascii=False)

        # Fallback trap loop detection
        if "trap" in prompt_lower and "loop" in prompt_lower and "inter-host" not in prompt_lower:
            if is_json:
                return json_lib.dumps({
                    "hosts": [
                        {"name": "honeypot-01", "loops": [
                            ["/home/user/.ssh/id_rsa", "/tmp/backup", "/home/user/.ssh/id_rsa"]
                        ]},
                        {"name": "honeypot-02", "loops": [
                            ["/etc/mysql/my.cnf", "/var/backups/mysql", "/etc/mysql/my.cnf"]
                        ]}
                    ]
                }, ensure_ascii=False)

        # Trap Agent - Inter-host chains
        if "inter-host" in prompt_lower or "interhost" in prompt_lower or ("trap chains" in prompt_lower and "tier" in prompt_lower):
            if is_json:
                # Try to extract actual host names from user content
                host_list = []
                try:
                    import json as json_parse
                    user_data = json_parse.loads(user_content)
                    if "hosts" in user_data:
                        host_list = [h.get("name", "") for h in user_data["hosts"] if h.get("name")]
                except:
                    pass

                if not host_list:
                    host_list = ["honeypot-01", "honeypot-02"]

                h1, h2 = host_list[0], host_list[1] if len(host_list) > 1 else "honeypot-02"

                return json_lib.dumps({
                    "chains": [
                        {"name": "lateral-chain-1", "steps": [
                            {"host": h1, "tier": "low"},
                            {"host": h2, "tier": "mid"},
                            {"host": h1, "tier": "low"}
                        ]}
                    ]
                }, ensure_ascii=False)

        # Deception Agent - Consistency check
        if "consistency" in prompt_lower:
            if is_json:
                return json_lib.dumps({
                    "issues": [],
                    "warnings": ["Mock mode: No actual consistency check performed"],
                    "status": "passed"
                }, ensure_ascii=False)

        # Perception summary
        if "honeynet" in prompt_lower and "analysis" in prompt_lower:
            return """## 攻击行为分析

### 主机概况
- 共检测到 2 个主机的活动
- 最大攻击阶段：Stage 3

### 攻击者行为模式
- 偏好协议：SSH, HTTP
- 攻击目的：凭证窃取、横向移动
- 能力评估：中等

### 建议
- 加强 SSH 认证配置
- 监控异常文件访问
- 设置陷阱文件追踪"""

        # Default JSON response for JSON requests
        if is_json:
            return json_lib.dumps({
                "status": "success",
                "message": "Mock response - zhipuai not available",
                "note": "Please install zhipuai package and configure API key for real LLM responses"
            }, ensure_ascii=False)

        # Default text response
        return "Mock response: GLM API is not available. Please install zhipuai package (pip install zhipuai) and configure your API key in secrets/glm_api_key.txt"


# ==================== Convenience Functions ====================

def create_glm_client(
    api_key_path: Optional[Path] = None,
    model: str = "glm-4-flash",
    temperature: float = 0.1,
    top_p: float = 0.9
) -> GLMClient:
    """
    Create a configured GLM client.

    Args:
        api_key_path: Path to API key file (defaults to secrets/glm_api_key.txt)
        model: Model name to use
        temperature: Sampling temperature
        top_p: Nucleus sampling parameter

    Returns:
        Configured GLMClient instance
    """
    config = GLMClientConfig(
        api_key_path=api_key_path or Path("secrets/glm_api_key.txt"),
        model=model,
        temperature=temperature,
        top_p=top_p
    )
    return GLMClient(config)


def chat_completion_simple(
    prompt: str,
    system_message: Optional[str] = None,
    model: str = "glm-4-flash",
    temperature: float = 0.1,
    api_key_path: Optional[Path] = None
) -> str:
    """
    Simple chat completion helper.

    Args:
        prompt: User prompt
        system_message: Optional system message
        model: Model to use
        temperature: Sampling temperature
        api_key_path: Path to API key file

    Returns:
        Generated text response
    """
    client = create_glm_client(
        api_key_path=api_key_path,
        model=model,
        temperature=temperature
    )

    messages = []
    if system_message:
        messages.append({"role": "system", "content": system_message})
    messages.append({"role": "user", "content": prompt})

    response = client.chat_completion(messages)
    return response["content"]


__all__ = [
    "GLMClient",
    "GLMClientConfig",
    "create_glm_client",
    "chat_completion_simple",
]
