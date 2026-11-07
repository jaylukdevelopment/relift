"""Database techniques: protocol fingerprint and security configuration.

Both techniques are ``safe`` tier. They speak the engine's real wire protocol
and read only what the protocol hands out before authentication: version
strings, capability flags, the requested auth mechanism, TLS support and
metadata parameters. No login is attempted here (see ``dbauth`` for the
intrusive credential-verification module), no write command is ever sent, and
no application table is read.

Why the protocol and not a driver: a driver hides exactly the facts that matter
for an audit — whether the listener negotiates TLS at all, which auth method it
asks for, and whether it answers unauthenticated in the first place.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import Severity
from . import dbproto
from .base import Module, ScanContext, finding

# Supported line, per engine. A build below this no longer receives security
# fixes from its vendor, so every future advisory is a permanent window.
EOL_BELOW: dict[str, tuple[int, int, int]] = {
    "postgres": (13, 0, 0),
    "mysql": (8, 0, 0),
    "mariadb": (10, 6, 0),
    "redis": (6, 2, 0),
    "mongodb": (5, 0, 0),
    "elasticsearch": (7, 17, 0),
    "couchdb": (3, 0, 0),
}

AUTH_LABELS = {
    0: "trust",
    3: "cleartext",
    5: "md5",
    10: "scram-sha-256",
    11: "scram-sha-256",
    12: "scram-sha-256",
}

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def version_tuple(text: str) -> tuple[int, int, int] | None:
    """First numeric triple in a version string, suffix-tolerant.

    Handles ``8.0.36-0ubuntu0.22.04.1``, ``16.2``, ``7.0.14`` and
    ``5.15.0-91-generic``. Returns None when there is nothing to compare.
    """
    match = _VERSION_RE.search(str(text or ""))
    if not match:
        return None
    parts = [int(group or 0) for group in match.groups()]
    return (parts[0], parts[1], parts[2])


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


@dataclass
class Facts:
    """Everything both modules need, collected by exactly one probe."""

    engine: str
    answered: bool = False
    version: str = ""
    build: str = ""
    port: int = 0
    tls_capable: bool = False
    auth_required: bool = True
    auth_method: str = ""
    cleartext_auth: bool = False
    eol: bool = False
    detail: str = ""
    error: str = ""
    extras: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def auth_methods(self) -> list[str]:
        listed = self.facts.get("auth_methods")
        if isinstance(listed, list) and listed:
            return [str(item) for item in listed]
        return [self.auth_method] if self.auth_method else []

    def evidence(self) -> dict[str, Any]:
        """The exact keys chains.py reads. Do not rename these."""
        return {
            "engine": self.engine,
            "version": self.version,
            "build": self.build,
            "port": self.port,
            "auth_required": self.auth_required,
            "auth_method": self.auth_method,
            "cleartext_auth": self.cleartext_auth,
            "tls_capable": self.tls_capable,
            "eol": self.eol,
        }


def _apply_eol(facts: Facts) -> None:
    line = EOL_BELOW.get(facts.engine)
    parsed = version_tuple(facts.version)
    if line is None or parsed is None:
        return
    facts.eol = parsed < line


# -- per-engine probes -------------------------------------------------------
def _probe_postgres(ctx: ScanContext, facts: Facts) -> None:
    with ctx.db_connect() as conn:
        greeting = dbproto.pg_greeting(
            conn, "relift_probe", ctx.target.database_name or "postgres"
        )
        facts.tls_capable = bool(greeting.tls_capable)
        facts.auth_method = AUTH_LABELS.get(greeting.auth_type, f"type-{greeting.auth_type}")
        facts.auth_required = greeting.auth_type != 0
        facts.cleartext_auth = facts.auth_method in ("cleartext", "md5")
        params = dict(greeting.params or {})
        facts.version = _text(params.get("server_version"))
        facts.facts.update(params)
        mechanisms = list(greeting.auth_mechanisms or [])
        if mechanisms:
            facts.facts["auth_methods"] = mechanisms
            facts.auth_method = "/".join(mechanisms).lower()
            facts.cleartext_auth = False
        if greeting.error:
            facts.detail = _text(greeting.error)[:200]
        try:
            dbproto.pg_terminate(conn)
        except OSError:
            pass
    facts.answered = True


def _probe_mysql(ctx: ScanContext, facts: Facts) -> None:
    with ctx.db_connect() as conn:
        greeting = dbproto.mysql_greeting(conn)
        facts.version = _text(greeting.version)
        facts.tls_capable = bool(greeting.tls_capable)
        plugin = _text(greeting.auth_plugin) or "unknown"
        facts.auth_method = plugin
        facts.auth_required = True
        facts.cleartext_auth = plugin == "mysql_native_password"
        facts.facts.update(
            {
                "protocol": greeting.protocol,
                "auth_methods": [plugin],
                "capability_flags": greeting.capability,
                "secure_connection": bool(greeting.secure_connection),
                "plugin_auth": bool(greeting.plugin_auth),
                "connection_id": _text(getattr(greeting, "connection_id", "")),
            }
        )
        facts.detail = f"auth plugin {plugin}"
        try:
            dbproto.mysql_quit(conn)
        except OSError:
            pass
    facts.answered = True


def _probe_mssql(ctx: ScanContext, facts: Facts) -> None:
    with ctx.db_connect() as conn:
        prelogin = dbproto.tds_prelogin(conn)
        facts.version = _text(getattr(prelogin, "version", ""))
        label = _text(getattr(prelogin, "encryption_label", "")) or "unknown"
        facts.tls_capable = label == "on"
        facts.auth_method = "sql"
        facts.auth_required = True
        facts.cleartext_auth = label in ("off", "not-supported")
        facts.facts.update(
            {
                "encryption": label,
                "instance": _text(getattr(prelogin, "instance", "")),
                "auth_methods": ["sql"],
            }
        )
        facts.detail = f"TDS pre-login, encryption {label}"
    facts.answered = True


def _probe_redis(ctx: ScanContext, facts: Facts) -> None:
    with ctx.db_connect() as conn:
        reply = dbproto.redis_command(conn, "PING")
        kind = _text(getattr(reply, "kind", ""))
        value = _text(getattr(reply, "value", ""))
        if kind == "-" or value.upper().startswith(("NOAUTH", "WRONGPASS")):
            facts.auth_required = True
            facts.auth_method = "requirepass/acl"
            facts.detail = value[:160]
            facts.facts["auth_methods"] = ["password"]
        else:
            facts.auth_required = False
            facts.auth_method = "none"
            facts.facts["auth_methods"] = ["none"]
            info = dbproto.redis_command(conn, "INFO", "server")
            payload = _text(getattr(info, "value", ""))
            for line in payload.splitlines():
                if ":" not in line or line.startswith("#"):
                    continue
                key, item = line.split(":", 1)
                facts.facts[key.strip()] = item.strip()
            facts.version = _text(facts.facts.get("redis_version"))
            facts.build = _text(facts.facts.get("redis_git_sha1"))
            facts.detail = f"os {facts.facts.get('os', '?')}, mode {facts.facts.get('mode', '?')}"
        facts.tls_capable = ctx.target.scheme == "rediss"
    facts.answered = True


def _probe_mongodb(ctx: ScanContext, facts: Facts) -> None:
    with ctx.db_connect() as conn:
        hello = dbproto.mongo_hello(conn)
        facts.version = _text(getattr(hello, "version", ""))
        mechanisms = [_text(item) for item in (getattr(hello, "mechanisms", None) or [])]
        facts.facts["auth_methods"] = mechanisms or ["unknown"]
        facts.facts["max_wire_version"] = getattr(hello, "max_wire_version", 0)
        facts.auth_method = ",".join(mechanisms) or "unknown"
        facts.auth_required = True
        facts.facts["hello_ok"] = bool(getattr(hello, "ok", False))
        if getattr(hello, "error", ""):
            facts.detail = _text(hello.error)[:200]
    facts.answered = True


def _probe_http_db(ctx: ScanContext, facts: Facts) -> None:
    response = ctx.http_get("/", scheme="http")
    if response.error:
        facts.error = response.error
        return
    facts.answered = True
    facts.port = ctx.target.port
    if response.status in (401, 403):
        facts.auth_required = True
        facts.auth_method = "http-basic-or-key"
        facts.facts["http_status"] = response.status
        facts.tls_capable = False
        return
    try:
        document = json.loads(response.text or "{}")
    except ValueError:
        facts.error = f"root returned {response.status} and no JSON"
        return
    facts.auth_required = False
    facts.auth_method = "none"
    facts.cleartext_auth = False
    if facts.engine == "elasticsearch":
        version = document.get("version") or {}
        facts.version = _text(version.get("number"))
        facts.build = _text(version.get("build_flavor") or version.get("build_hash"))
        facts.facts.update(
            {
                "cluster_name": _text(document.get("cluster_name")),
                "tagline": _text(document.get("tagline")),
                "distribution": _text(version.get("distribution")),
            }
        )
    else:
        facts.version = _text(document.get("version"))
        vendor = document.get("vendor") or {}
        facts.facts.update(
            {
                "product": _text(document.get("couchdb")),
                "vendor": _text(vendor.get("name")),
                "features": document.get("features") or [],
            }
        )
    facts.detail = f"root answered {response.status} without credentials"


_PROBES = {
    "postgres": _probe_postgres,
    "mysql": _probe_mysql,
    "mssql": _probe_mssql,
    "redis": _probe_redis,
    "mongodb": _probe_mongodb,
    "elasticsearch": _probe_http_db,
    "couchdb": _probe_http_db,
}


def collect(ctx: ScanContext) -> Facts:
    """One probe, shared by both modules. Never raises."""
    engine = ctx.target.engine
    facts = Facts(engine=engine, port=ctx.target.port)
    if not engine:
        facts.error = f"{ctx.target.scheme!r} is not a database scheme"
        return facts
    probe = _PROBES.get(engine)
    if probe is None:
        facts.error = f"no protocol probe for engine {engine!r}"
        return facts
    try:
        probe(ctx, facts)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        facts.answered = False
        facts.error = f"{type(exc).__name__}: {exc}"[:220]
    except Exception as exc:  # noqa: BLE001 - a malformed reply must not kill the run
        facts.answered = False
        facts.error = f"{type(exc).__name__}: {exc}"[:220]
    _apply_eol(facts)
    return facts


class DatabaseFingerprintModule(Module):
    """``db.fingerprint`` — safe tier: no authentication, no writes."""

    attack_id = "db.fingerprint"

    def run(self, ctx: ScanContext):
        facts = collect(ctx)
        engine = facts.engine or ctx.target.scheme
        if not facts.answered:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"{engine} did not answer the protocol probe",
                    Severity.INFO,
                    detail=facts.error or "connection failed",
                    evidence={
                        "engine": facts.engine,
                        "port": ctx.target.port,
                        "error": facts.error,
                    },
                    confidence="low",
                )
            ]

        evidence = facts.evidence()
        evidence["auth_methods"] = facts.auth_methods
        evidence["facts"] = facts.facts
        version = facts.version or "listener"
        bits = [f"{engine} {version}"]
        if facts.build:
            bits.append(f"build {facts.build}")
        if facts.facts.get("max_wire_version"):
            bits.append(f"wire {facts.facts['max_wire_version']}")
        bits.append("TLS available" if facts.tls_capable else "no TLS")
        bits.append(f"auth {facts.auth_method or 'unknown'}")
        if facts.detail:
            bits.append(facts.detail)

        return [
            finding(
                ctx,
                self.attack_id,
                f"{engine} {version} fingerprinted",
                Severity.INFO,
                detail=" · ".join(str(bit) for bit in bits if bit),
                evidence=evidence,
                confidence="high",
            )
        ]


class DatabaseSecurityModule(Module):
    """``db.security_config`` — safe tier: reads configuration facts only.

    It reports whether a listener demands authentication at all, which auth
    method it negotiates, whether the transport can be encrypted and whether the
    build is still supported. It does not log in, list databases or read rows.
    """

    attack_id = "db.security_config"

    def run(self, ctx: ScanContext):
        facts = collect(ctx)
        engine = facts.engine or ctx.target.scheme
        evidence = facts.evidence()
        evidence["facts"] = facts.facts

        if not facts.answered:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"{engine} security configuration not readable",
                    Severity.INFO,
                    detail=facts.error or "connection failed",
                    evidence=evidence,
                    confidence="low",
                )
            ]

        findings = []

        def add(title, severity, detail="", confidence="high", **extra):
            bag = dict(evidence)
            bag.update(extra)
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    title,
                    severity,
                    detail=detail,
                    evidence=bag,
                    confidence=confidence,
                )
            )

        # -- authentication -------------------------------------------------
        if not facts.auth_required:
            if engine == "redis":
                add(
                    "Redis answers commands without authentication",
                    Severity.CRITICAL,
                    "PING was answered without AUTH. Every key in this "
                    "instance, and on many builds the configuration endpoint "
                    "that leads to command execution, is reachable by anyone "
                    "who can route to this port.",
                )
            elif engine in ("elasticsearch", "couchdb"):
                add(
                    f"{engine} answers unauthenticated",
                    Severity.HIGH,
                    f"the root endpoint returned {facts.facts.get('http_status', 200)} "
                    "with no credential; index/data and admin APIs sit behind the "
                    "same gate",
                )
            elif engine == "mongodb":
                # `hello` succeeds before authentication by design, so it proves
                # reachability and nothing more. The honest finding is a medium
                # one that says so; open data needs db.credential_verify.
                wire = int(facts.facts.get("max_wire_version") or 0)
                add(
                    "MongoDB hello is reachable without credentials",
                    Severity.MEDIUM,
                    f"wire version {wire or '?'}. hello is unauthenticated by "
                    "design, so this shows the listener is reachable, not that "
                    "data is readable. Confirm with db.credential_verify before "
                    "calling it an exposure.",
                    confidence="medium",
                )
            else:
                add(
                    f"{engine} accepts connections without authentication",
                    Severity.CRITICAL,
                    f"negotiated auth method: {facts.auth_method}. The listener "
                    "handed out a usable session without a credential.",
                )
        else:
            add(
                f"{engine} requires authentication ({facts.auth_method})",
                Severity.INFO,
                "the listener refused to proceed without a credential",
            )

        # -- credential exposure on the wire --------------------------------
        if facts.cleartext_auth and facts.auth_required:
            add(
                f"{engine} negotiates a replayable credential exchange",
                Severity.MEDIUM,
                f"auth method {facts.auth_method} puts a reusable secret on the "
                "wire; the login becomes replayable with a tap on the path",
                cleartext_auth=True,
            )

        # -- transport ------------------------------------------------------
        if not facts.tls_capable and engine not in ("elasticsearch", "couchdb"):
            if facts.auth_required and facts.cleartext_auth:
                add(
                    f"{engine} listener offers no TLS",
                    Severity.HIGH,
                    "a replayable credential exchange over a plaintext socket "
                    "is the credential-interception path in one hop",
                    tls_capable=False,
                )
            else:
                add(
                    f"{engine} listener offers no TLS",
                    Severity.MEDIUM if engine in ("postgres", "mysql", "mssql") else Severity.LOW,
                    "traffic and metadata cross the wire in the clear",
                    tls_capable=False,
                )
        if engine == "mssql" and facts.facts.get("encryption") in ("off", "not-supported"):
            add(
                "TDS traffic is not encrypted",
                Severity.MEDIUM if facts.facts.get("encryption") == "off" else Severity.HIGH,
                f"pre-login encryption: {facts.facts.get('encryption')}",
            )

        # -- support window -------------------------------------------------
        if facts.eol:
            add(
                f"{engine} {facts.version} is past end of life",
                Severity.HIGH,
                "this build no longer receives security fixes, so every future "
                "advisory for the engine is a permanent window on this host",
                eol=True,
            )

        findings.append(
            finding(
                ctx,
                self.attack_id,
                "security configuration recorded",
                Severity.INFO,
                detail=(
                    f"{engine} {facts.version or '?'} · "
                    f"auth {'required' if facts.auth_required else 'NOT required'} "
                    f"({facts.auth_method or '?'}) · "
                    f"TLS {'yes' if facts.tls_capable else 'no'} · "
                    f"{'EOL' if facts.eol else 'supported'}"
                ),
                evidence=evidence,
                confidence="high",
            )
        )
        return findings
