"""Provider registry and selection.

Order: explicit flag, environment, config file, auto-detect (local daemons first,
then any cloud key), then the rule engine.
"""

from __future__ import annotations

from typing import Any

from ..config import ai_settings
from .base import (
    SYSTEM_PROMPT,
    AIError,
    AIProvider,
    Analyst,
    ProviderInfo,
    sanitize,
)
from .cloud import AnthropicProvider, GroqProvider, OpenAIProvider, OpenRouterProvider
from .local import CustomProvider, LlamaCppProvider, LMStudioProvider, OllamaProvider
from .offline import OfflineProvider, rule_narrative

PROVIDER_CLASSES: dict[str, type[AIProvider]] = {
    "ollama": OllamaProvider,
    "lmstudio": LMStudioProvider,
    "llamacpp": LlamaCppProvider,
    "custom": CustomProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "openrouter": OpenRouterProvider,
    "groq": GroqProvider,
    "offline": OfflineProvider,
}

LOCAL_ORDER = ("ollama", "lmstudio", "llamacpp", "custom")
CLOUD_ORDER = ("openai", "anthropic", "openrouter", "groq")
OFFLINE_NAMES = {"none", "no-ai", "off", "offline", "rule-engine"}


def _instantiate(provider_id: str, settings: dict[str, Any]) -> AIProvider:
    cls = PROVIDER_CLASSES[provider_id]
    if cls is OfflineProvider:
        return OfflineProvider()
    return cls(
        model=str(settings.get("model") or ""),
        base_url=str(settings.get("base_url") or ""),
        timeout=float(settings.get("timeout") or 60),
    )


def auto_provider(settings: dict[str, Any] | None = None) -> AIProvider:
    cfg = settings or ai_settings()
    for provider_id in LOCAL_ORDER + CLOUD_ORDER:
        try:
            candidate = _instantiate(provider_id, cfg)
        except (ValueError, OSError):
            continue
        if candidate.available():
            return candidate
    return OfflineProvider(detail="no local daemon reachable and no cloud key set")


def build_provider(
    name: str | None = None,
    settings: dict[str, Any] | None = None,
) -> AIProvider:
    cfg = settings if settings is not None else ai_settings()
    choice = str(name if name is not None else cfg.get("provider") or "").strip().lower()
    if choice in OFFLINE_NAMES:
        return OfflineProvider()
    if not choice:
        return auto_provider(cfg)
    if choice not in PROVIDER_CLASSES:
        raise ValueError(
            f"unknown AI provider {choice!r}; try one of: "
            + ", ".join(sorted(PROVIDER_CLASSES))
        )
    return _instantiate(choice, cfg)


def provider_report(settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every known provider with a live readiness check. Never raises."""
    cfg = settings or ai_settings()
    rows: list[dict[str, Any]] = []
    for provider_id in LOCAL_ORDER + CLOUD_ORDER + ("offline",):
        try:
            info = _instantiate(provider_id, cfg).info()
        except Exception as exc:  # noqa: BLE001 - a probe must never kill the command
            rows.append(
                {
                    "id": provider_id,
                    "kind": "?",
                    "endpoint": "",
                    "model": "",
                    "ready": False,
                    "detail": str(exc),
                }
            )
            continue
        rows.append(info.to_dict())
    return rows


def selected_provider_label(settings: dict[str, Any] | None = None) -> str:
    try:
        return build_provider(None, settings).label
    except (ValueError, OSError):
        return "offline"


__all__ = [
    "AIError",
    "AIProvider",
    "Analyst",
    "ProviderInfo",
    "PROVIDER_CLASSES",
    "SYSTEM_PROMPT",
    "auto_provider",
    "build_provider",
    "provider_report",
    "rule_narrative",
    "sanitize",
    "selected_provider_label",
]
