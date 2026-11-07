"""Audit trail and run artefacts.

The audit log is the answer to "was this scan in scope?" — so it is append-only,
JSONL, and deliberately boring. Credentials are never written to it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUNS_DIRNAME = ".relift-runs"
AUDIT_DIRNAME = ".relift"
AUDIT_FILENAME = "audit.jsonl"

_SENSITIVE = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "cookie",
    "credential",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_audit_path() -> Path:
    override = os.environ.get("RELIFT_AUDIT_FILE")
    if override:
        return Path(override).expanduser()
    return Path.home() / AUDIT_DIRNAME / AUDIT_FILENAME


def runs_root(base: str | Path | None = None) -> Path:
    if base:
        return Path(base).expanduser()
    override = os.environ.get("RELIFT_RUNS_DIR")
    if override:
        return Path(override).expanduser()
    return Path.cwd() / RUNS_DIRNAME


def redact(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop anything that smells like a credential before it reaches disk."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if any(hint in str(key).lower() for hint in _SENSITIVE):
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = redact(value)
        else:
            clean[key] = value
    return clean


class AuditLog:
    """Append-only JSONL writer.

    A write failure is recorded on the object but never aborts a run: losing the
    log is bad, losing the scan is worse.
    """

    def __init__(self, path: str | Path | None = None, enabled: bool = True):
        self.path = Path(path).expanduser() if path else default_audit_path()
        self.enabled = enabled
        self.error = ""

    def event(self, event: str, **fields: Any) -> None:
        if not self.enabled:
            return
        payload: dict[str, Any] = {"ts": _now(), "event": event}
        payload.update(redact(fields))
        line = json.dumps(payload, ensure_ascii=False, default=str)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            if not self.error:
                self.error = f"{self.path}: {exc}"


def write_run(record: Any, base: str | Path | None = None) -> Path:
    """Persist a RunRecord under <runs_root>/<run_id>/run.json."""
    payload = record.to_dict()
    outdir = runs_root(base) / record.run_id
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / "run.json"
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path


def find_run(ref: str | None = None, base: str | Path | None = None) -> Path:
    """Resolve a run reference: an id, a path to run.json, or None for the latest."""
    root = runs_root(base)
    if str(ref or "").strip().lower() in ("", "latest", "last"):
        ref = None
    if ref:
        candidate = Path(ref).expanduser()
        if candidate.is_file():
            return candidate
        by_id = root / ref / "run.json"
        if by_id.is_file():
            return by_id
        raise FileNotFoundError(f"no run {ref!r} under {root}")
    if not root.is_dir():
        raise FileNotFoundError(f"no runs yet: {root} does not exist")
    runs = sorted(
        (p for p in root.iterdir() if (p / "run.json").is_file()),
        key=lambda p: p.name,
    )
    if not runs:
        raise FileNotFoundError(f"no runs yet under {root}")
    return runs[-1] / "run.json"


def load_run(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
