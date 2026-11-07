"""Optional local configuration (``relift.config.json``).

Precedence, lowest to highest: built-in defaults, config file, environment.
Secrets never live here — only names of providers and models.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_FILENAME = "relift.config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "",  # empty means auto-detect
        "model": "",
        "base_url": "",
        "timeout": 60,
    },
    "scan": {
        "profile": "safe",
        "timeout": 6.0,
    },
}


def config_candidates(explicit: str | None = None) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    from_env = os.environ.get("RELIFT_CONFIG")
    if from_env:
        paths.append(Path(from_env).expanduser())
    paths.append(Path.cwd() / CONFIG_FILENAME)
    paths.append(Path.home() / ".relift" / "config.json")
    return paths


def load_config(explicit: str | None = None) -> dict[str, Any]:
    """Merge every config file that exists, later files winning."""
    merged: dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
    for path in config_candidates(explicit):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for section, values in data.items():
            if isinstance(values, dict) and isinstance(merged.get(section), dict):
                merged[section].update(values)
            else:
                merged[section] = values
        merged.setdefault("_source", str(path))
    return merged


def ai_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """AI settings with environment overrides applied."""
    cfg = ((config if config is not None else load_config()).get("ai") or {})
    return {
        "provider": (
            os.environ.get("RELIFT_AI_PROVIDER") or cfg.get("provider") or ""
        ).strip(),
        "model": (os.environ.get("RELIFT_AI_MODEL") or cfg.get("model") or "").strip(),
        "base_url": (
            os.environ.get("RELIFT_AI_BASE_URL") or cfg.get("base_url") or ""
        ).strip(),
        "timeout": float(
            os.environ.get("RELIFT_AI_TIMEOUT") or cfg.get("timeout") or 60
        ),
    }


def scan_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = ((config if config is not None else load_config()).get("scan") or {})
    return {
        "profile": str(cfg.get("profile") or "safe"),
        "timeout": float(cfg.get("timeout") or 6.0),
    }
