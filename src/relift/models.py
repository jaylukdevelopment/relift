"""Core data model: techniques, targets, findings, executions, run records."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


def utcnow() -> str:
    """Timestamp string used everywhere a time is recorded."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Risk(str, Enum):
    """How much the technique can disturb the target."""

    PASSIVE = "passive"
    SAFE = "safe"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


RISK_RANK = {
    Risk.PASSIVE: 0,
    Risk.SAFE: 1,
    Risk.INTRUSIVE: 2,
    Risk.DESTRUCTIVE: 3,
}


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class AttackSpec:
    """One catalogue entry. If it is not one of these, the tool cannot run it."""

    id: str
    name: str
    category: str
    risk: Risk
    summary: str
    implemented: bool = True
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    ai_hint: str = ""
    mitre: str = ""
    notes: str = ""

    @property
    def external(self) -> bool:
        """True when the technique shells out to an installed third-party tool."""
        return bool(self.requires)

    @property
    def status(self) -> str:
        if not self.implemented:
            return "design-only"
        if self.requires:
            return "ext: " + ", ".join(self.requires)
        return "ready"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "risk": self.risk.value,
            "summary": self.summary,
            "implemented": self.implemented,
            "requires": list(self.requires),
            "produces": list(self.produces),
            "ai_hint": self.ai_hint,
            "mitre": self.mitre,
            "notes": self.notes,
            "status": self.status,
        }


@dataclass(frozen=True)
class Target:
    """A parsed target. Port and scheme are always explicit after parsing."""

    raw: str
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def parse(cls, raw: str) -> "Target":
        text = (raw or "").strip()
        if not text:
            raise ValueError("empty target")
        if "://" not in text:
            text = "https://" + text
        parts = urlsplit(text)
        scheme = (parts.scheme or "https").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme {scheme!r} (use http or https)")
        host = parts.hostname or ""
        if not host:
            raise ValueError(f"could not find a host in {raw!r}")
        try:
            explicit_port = parts.port
        except ValueError as exc:  # malformed port in the URL
            raise ValueError(f"bad port in {raw!r}: {exc}") from exc
        port = explicit_port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return cls(raw=raw, scheme=scheme, host=host, port=port, path=path)

    def url(self, path: str | None = None) -> str:
        target_path = path if path is not None else self.path
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        default = 443 if self.scheme == "https" else 80
        authority = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{authority}{target_path}"

    @property
    def origin(self) -> str:
        return self.url("/")

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
        }


@dataclass
class Finding:
    """A single observation. Evidence, not opinion."""

    attack_id: str
    target: str
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    confidence: str = "high"

    def key(self) -> tuple[str, str, str]:
        return (self.attack_id, self.target, self.title)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "target": self.target,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "references": list(self.references),
            "confidence": self.confidence,
        }


@dataclass
class Execution:
    """What happened when one catalogue entry was run (or not)."""

    attack_id: str
    status: str = "ok"          # ok | error | skipped
    started: str = ""
    finished: str = ""
    duration_ms: int = 0
    error: str = ""
    reason: str = ""            # why it was skipped
    command: list[str] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "reason": self.reason,
            "command": list(self.command),
            "finding_count": self.finding_count,
        }


@dataclass
class RunRecord:
    """The unit of truth. A report is just a view of one of these."""

    run_id: str = field(default_factory=lambda: _new_run_id())
    target: Target | None = None
    profile: str = "safe"
    provider: str = "offline"
    engagement: str = ""
    scope_sha256: str = ""
    authorized_by: str = ""
    started: str = field(default_factory=utcnow)
    finished: str = ""
    executions: list[Execution] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    narrative: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "relift",
            "version": _version(),
            "run_id": self.run_id,
            "target": self.target.to_dict() if self.target else None,
            "profile": self.profile,
            "provider": self.provider,
            "engagement": self.engagement,
            "scope_sha256": self.scope_sha256,
            "authorized_by": self.authorized_by,
            "started": self.started,
            "finished": self.finished,
            "executions": [e.to_dict() for e in self.executions],
            "findings": [f.to_dict() for f in self.findings],
            "narrative": self.narrative,
            "error": self.error,
        }


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:4]}"


def _version() -> str:
    from . import __version__

    return __version__
