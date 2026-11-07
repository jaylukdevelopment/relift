"""Local providers: Ollama, and anything speaking OpenAI-compatible HTTP.

Every endpoint here is loopback by default. Nothing leaves the machine.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import AIError, AIProvider


def post_json(
    url: str,
    payload: dict,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:200]
        except (OSError, ValueError):
            pass
        raise AIError(f"HTTP {exc.code} from {url}: {detail}") from None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise AIError(f"cannot reach {url}: {reason}") from None
    except (TimeoutError, OSError) as exc:
        raise AIError(f"request to {url} failed: {exc}") from None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AIError(f"{url} returned something that is not JSON") from None


def reachable(url: str, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _normalise(url: str, fallback: str) -> str:
    text = (url or fallback).rstrip("/")
    if not text.startswith(("http://", "https://")):
        text = "http://" + text
    return text


class OllamaProvider(AIProvider):
    id = "ollama"
    kind = "local"
    model = "qwen2.5-coder:7b"
    endpoint = "http://127.0.0.1:11434"

    def __init__(self, model="", base_url="", timeout=60.0, api_key=""):
        super().__init__(model, base_url, timeout, api_key)
        self.base_url = _normalise(
            self.base_url or os.environ.get("OLLAMA_HOST", ""), self.endpoint
        )

    def available(self) -> bool:
        return reachable(self.base_url + "/api/tags")

    def complete(self, system, prompt, max_tokens=900, temperature=0.2) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        data = post_json(self.base_url + "/api/chat", payload, self.timeout)
        message = data.get("message") or {}
        text = str(message.get("content") or "").strip()
        if not text:
            raise AIError("ollama returned an empty completion")
        return text


class OpenAICompatibleProvider(AIProvider):
    """LM Studio, llama.cpp server, vLLM, LiteLLM, any /chat/completions gateway."""

    id = "openai-compatible"
    kind = "local"
    endpoint = "http://127.0.0.1:1234/v1"
    key_env = ""

    def __init__(self, model="", base_url="", timeout=60.0, api_key=""):
        super().__init__(model, base_url, timeout, api_key)
        self.base_url = _normalise(self.base_url, self.endpoint)
        if not self.api_key and self.key_env:
            self.api_key = os.environ.get(self.key_env, "")

    def available(self) -> bool:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else None
        request = urllib.request.Request(self.base_url + "/models")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=3.0) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def complete(self, system, prompt, max_tokens=900, temperature=0.2) -> str:
        payload = {
            "model": self.model or "local-model",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = post_json(
            self.base_url + "/chat/completions", payload, self.timeout, headers
        )
        choices = data.get("choices") or []
        if not choices:
            raise AIError("completion contained no choices")
        message = choices[0].get("message") or {}
        text = str(message.get("content") or "").strip()
        if not text:
            raise AIError("provider returned an empty completion")
        return text


class LMStudioProvider(OpenAICompatibleProvider):
    id = "lmstudio"
    kind = "local"
    endpoint = "http://127.0.0.1:1234/v1"


class LlamaCppProvider(OpenAICompatibleProvider):
    id = "llamacpp"
    kind = "local"
    endpoint = "http://127.0.0.1:8080/v1"


class CustomProvider(OpenAICompatibleProvider):
    """Any OpenAI-compatible gateway; set RELIFT_AI_BASE_URL."""

    id = "custom"
    kind = "local"
    endpoint = "http://127.0.0.1:8000/v1"
    key_env = "RELIFT_AI_API_KEY"
