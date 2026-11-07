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
    # Which target families the technique is meaningful for. A target exposes
    # the families it belongs to (a plain https origin is just ``http``; an
    # Elasticsearch endpoint is both ``http`` and ``db``).
    families: tuple[str, ...] = ("http",)
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
            "families": list(self.families),
            "requires": list(self.requires),
            "produces": list(self.produces),
            "ai_hint": self.ai_hint,
            "mitre": self.mitre,
            "notes": self.notes,
            "status": self.status,
        }


# Scheme → default port. Anything not listed is refused at parse time.
SCHEME_PORTS = {
    "http": 80,
    "https": 443,
    "local": 0,
    "ssh": 22,
    "postgres": 5432,
    "postgresql": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "redis": 6379,
    "rediss": 6379,
    "mongodb": 27017,
    "mssql": 1433,
    "sqlserver": 1433,
    "tds": 1433,
    "elasticsearch": 9200,
    "opensearch": 9200,
    "es": 9200,
    "couchdb": 5984,
}

# Several spellings describe the same engine. Normalised once, here.
ENGINE_ALIASES = {
    "postgresql": "postgres",
    "mariadb": "mysql",
    "rediss": "redis",
    "sqlserver": "mssql",
    "tds": "mssql",
    "es": "elasticsearch",
    "opensearch": "elasticsearch",
    "sqlite": "sqlite",
}

# Engines that speak HTTP and therefore also deserve the web.* techniques.
HTTP_DATABASES = ("elasticsearch", "couchdb")

DATABASE_ENGINES = (
    "postgres",
    "mysql",
    "redis",
    "mongodb",
    "mssql",
    "elasticsearch",
    "couchdb",
)


def database_engine(scheme: str) -> str:
    """Normalise a scheme to a known engine, or return ''."""
    text = (scheme or "").strip().lower()
    engine = ENGINE_ALIASES.get(text, text)
    return engine if engine in DATABASE_ENGINES else ""


@dataclass(frozen=True)
class Target:
    """A parsed target. Port and scheme are always explicit after parsing.

    Three kinds exist: an HTTP origin (``http``/``https``), a database endpoint
    (``postgres://``, ``mysql://``, ``redis://``, ...) and the local host
    (``local://``) that the host audit reads. ``engine`` is empty for plain HTTP.
    """

    raw: str
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def parse(cls, raw: str) -> Target:
        text = (raw or "").strip()
        if not text:
            raise ValueError("empty target")
        if text.lower() in ("local", "local://", "host://"):
            return cls(raw=raw, scheme="local", host="127.0.0.1", port=0, path="/")
        if "://" not in text:
            text = "https://" + text
        parts = urlsplit(text)
        scheme = (parts.scheme or "https").lower()
        if scheme not in SCHEME_PORTS:
            raise ValueError(
                f"unsupported scheme {scheme!r}; use http, https, local or one "
                f"of: {', '.join(sorted(set(SCHEME_PORTS) - {'http', 'https', 'local'}))}"
            )
        host = parts.hostname or ""
        if not host:
            raise ValueError(f"could not find a host in {raw!r}")
        try:
            explicit_port = parts.port
        except ValueError as exc:  # malformed port in the URL
            raise ValueError(f"bad port in {raw!r}: {exc}") from exc
        port = explicit_port or SCHEME_PORTS[scheme]
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return cls(raw=raw, scheme=scheme, host=host, port=port, path=path)

    @property
    def engine(self) -> str:
        """Normalised database engine, or '' when the target is not a database."""
        return database_engine(self.scheme)

    @property
    def kind(self) -> str:
        if self.scheme == "local":
            return "host"
        if self.scheme == "ssh":
            return "ssh"
        if self.engine and self.engine not in HTTP_DATABASES:
            return "db"
        return "http"

    @property
    def families(self) -> tuple[str, ...]:
        """Target families a technique may target."""
        if self.kind == "host":
            return ("host",)
        if self.kind == "ssh":
            return ("ssh",)
        if self.engine in HTTP_DATABASES:
            return ("http", "db")
        if self.kind == "db":
            return ("db",)
        return ("http",)

    @property
    def database_name(self) -> str:
        """Path segment used as the database name, if one was given."""
        name = (self.path or "").strip("/")
        return name if self.kind == "db" else ""

    def url(self, path: str | None = None) -> str:
        target_path = path if path is not None else self.path
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        default = 443 if self.scheme == "https" else 80
        authority = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{authority}{target_path}"

    @property
    def origin(self) -> str:
        if self.kind == "host":
            return "local://" + self.host
        if self.kind in ("db", "ssh"):
            suffix = self.database_name
            return f"{self.scheme}://{self.host}:{self.port}" + (f"/{suffix}" if suffix else "")
        return self.url("/")

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "engine": self.engine,
            "kind": self.kind,
            "families": list(self.families),
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
    chains: list[AttackChain] = field(default_factory=list)

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
            "chains": [c.to_dict() for c in self.chains],
            "narrative": self.narrative,
            "error": self.error,
        }


@dataclass
class ChainStep:
    """One stage of a correlated attack thread."""

    stage: str
    attack_id: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "attack_id": self.attack_id,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass
class AttackChain:
    """A multi-stage path assembled from findings that exist in this run.

    A chain is an argument, not a capability: it names the stages an attacker
    would walk and the single control that breaks the path.
    """

    id: str
    title: str
    severity: Severity
    summary: str
    stages: list[ChainStep] = field(default_factory=list)
    break_at: str = ""
    confidence: str = "medium"

    @property
    def attack_ids(self) -> list[str]:
        return [step.attack_id for step in self.stages]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "summary": self.summary,
            "stages": [step.to_dict() for step in self.stages],
            "break_at": self.break_at,
            "confidence": self.confidence,
        }


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:4]}"


def _version() -> str:
    from . import __version__

    return __version__
