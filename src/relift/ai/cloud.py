"""Cloud providers. Keys come from the environment, never from disk."""

from __future__ import annotations

import os

from .base import AIError, AIProvider
from .local import OpenAICompatibleProvider, post_json


class OpenAIProvider(OpenAICompatibleProvider):
    id = "openai"
    kind = "cloud"
    endpoint = "https://api.openai.com/v1"
    model = "gpt-4o-mini"
    key_env = "OPENAI_API_KEY"

    def available(self) -> bool:
        return bool(self.api_key)


class OpenRouterProvider(OpenAICompatibleProvider):
    id = "openrouter"
    kind = "cloud"
    endpoint = "https://openrouter.ai/api/v1"
    model = "anthropic/claude-3.5-haiku"
    key_env = "OPENROUTER_API_KEY"

    def available(self) -> bool:
        return bool(self.api_key)


class GroqProvider(OpenAICompatibleProvider):
    id = "groq"
    kind = "cloud"
    endpoint = "https://api.groq.com/openai/v1"
    model = "llama-3.3-70b-versatile"
    key_env = "GROQ_API_KEY"

    def available(self) -> bool:
        return bool(self.api_key)


class AnthropicProvider(AIProvider):
    id = "anthropic"
    kind = "cloud"
    endpoint = "https://api.anthropic.com/v1"
    model = "claude-3-5-haiku-latest"
    key_env = "ANTHROPIC_API_KEY"

    def __init__(self, model="", base_url="", timeout=60.0, api_key=""):
        super().__init__(model, base_url, timeout, api_key)
        if not self.api_key:
            self.api_key = os.environ.get(self.key_env, "")

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system, prompt, max_tokens=900, temperature=0.2) -> str:
        if not self.api_key:
            raise AIError("ANTHROPIC_API_KEY is not set")
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        data = post_json(self.base_url + "/messages", payload, self.timeout, headers)
        blocks = data.get("content") or []
        text = "".join(
            str(block.get("text") or "")
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ).strip()
        if not text:
            raise AIError("anthropic returned an empty completion")
        return text
