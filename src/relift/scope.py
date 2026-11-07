"""Scope handling: the gate that decides whether a target may be touched.

Nothing here sends traffic. It only decides. Every refusal raises
:class:`ScopeError`, which the CLI turns into exit code 2 before a single
packet leaves the machine.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .models import RISK_RANK, Risk

DEFAULT_PORTS = (22, 80, 443, 8000, 8080, 8443)

# A /22 is 1022 hosts. Anything broader is refused unless the scope file says
# "allow_wide_ranges": true, because 0.0.0.0/0 is one typo away.
MAX_V4_PREFIX = 22
MAX_V6_PREFIX = 120


class ScopeError(RuntimeError):
    """A refusal. Nothing is sent to the target when this is raised."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_when(value: Any) -> datetime:
    text = str(value).strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    stamp = datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def resolve_host(host: str) -> list[str]:
    """Every address a name resolves to, deduplicated and sorted."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


@dataclass(frozen=True)
class Pattern:
    """One scope entry: exact host, ``*.suffix`` wildcard, or address/CIDR."""

    raw: str
    kind: str  # "host" | "wildcard" | "network"
    value: Any

    def matches(self, candidate: str) -> bool:
        text = (candidate or "").strip().rstrip(".").casefold()
        if not text:
            return False
        if self.kind == "host":
            return text == self.value
        if self.kind == "wildcard":
            # *.example.com matches a.example.com but never the apex itself.
            return text.endswith(self.value) and len(text) > len(self.value)
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        return address.version == self.value.version and address in self.value


def compile_pattern(raw: str) -> Pattern:
    text = str(raw).strip().rstrip(".")
    if not text:
        raise ScopeError("empty entry in the scope file")
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ScopeError(f"{text!r} looks like a CIDR but is not one") from None
        return Pattern(text, "network", network)
    if text.startswith("*."):
        suffix = text[1:].casefold()
        if "." not in suffix:
            raise ScopeError(f"wildcard {text!r} needs a domain, e.g. *.example.com")
        return Pattern(text, "wildcard", suffix)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return Pattern(text, "host", text.casefold())
    return Pattern(text, "network", ipaddress.ip_network(address))


@dataclass
class Scope:
    """A loaded, validated engagement scope."""

    path: Path
    digest: str
    engagement: str
    authorized_by: str
    organization: str
    expires: datetime
    allowed_raw: list[str]
    denied_raw: list[str]
    max_risk: Risk
    allow_intrusive: bool
    allow_wide_ranges: bool
    rate_limit_rps: float
    ports: tuple[int, ...]
    notes: str = ""
    allowed: list[Pattern] = field(default_factory=list, repr=False)
    denied: list[Pattern] = field(default_factory=list, repr=False)

    # -- presentation ------------------------------------------------------
    @property
    def expires_in_days(self) -> int:
        return int((self.expires - _now()).total_seconds() // 86400)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "sha256": self.digest,
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "organization": self.organization,
            "expires": self.expires.isoformat(timespec="seconds"),
            "expires_in_days": self.expires_in_days,
            "allowed_hosts": list(self.allowed_raw),
            "denied_hosts": list(self.denied_raw),
            "max_risk": self.max_risk.value,
            "allow_intrusive": self.allow_intrusive,
            "allow_wide_ranges": self.allow_wide_ranges,
            "rate_limit_rps": self.rate_limit_rps,
            "ports": list(self.ports),
            "notes": self.notes,
        }

    # -- policy ------------------------------------------------------------
    def risk_ceiling(self, profile_max: Risk) -> Risk:
        """The stricter of the scope's ceiling and the profile's ceiling."""
        ceiling = self.max_risk
        if RISK_RANK[profile_max] < RISK_RANK[ceiling]:
            ceiling = profile_max
        if not self.allow_intrusive and RISK_RANK[ceiling] > RISK_RANK[Risk.SAFE]:
            ceiling = Risk.SAFE
        return ceiling

    def port_set(self, override: Iterable[int] | None = None) -> tuple[int, ...]:
        if override:
            return tuple(sorted({int(p) for p in override}))
        return self.ports or DEFAULT_PORTS

    def _check_expiry(self) -> None:
        if _now() > self.expires:
            raise ScopeError(
                f"scope {self.path} expired on "
                f"{self.expires.isoformat(timespec='seconds')}. "
                "Re-authorise the engagement before scanning again."
            )

    def _deny_match(self, candidate: str) -> Pattern | None:
        for pattern in self.denied:
            if pattern.matches(candidate):
                return pattern
        return None

    def authorize(self, host: str) -> str:
        """Return the matching allow pattern, or raise :class:`ScopeError`."""
        self._check_expiry()
        name = (host or "").strip().rstrip(".")
        if not name:
            raise ScopeError("no target host given")

        denied = self._deny_match(name)
        if denied is not None:
            raise ScopeError(
                f"{host!r} is explicitly denied by {denied.raw!r} in {self.path}"
            )

        matched: Pattern | None = None
        for pattern in self.allowed:
            if pattern.matches(name):
                matched = pattern
                break
        if matched is None:
            raise ScopeError(
                f"{host!r} is not in allowed_hosts of {self.path}. "
                f"Engagement {self.engagement!r} does not cover it."
            )

        try:
            literal = ipaddress.ip_address(name)
        except ValueError:
            literal = None
        if literal is not None:
            return matched.raw

        # A name is only as trustworthy as what it resolves to right now.
        addresses = resolve_host(name)
        if not addresses:
            raise ScopeError(
                f"{host!r} is allowed by name but does not resolve. "
                "Refusing to scan a name with no address."
            )
        for address in addresses:
            denied = self._deny_match(address)
            if denied is not None:
                raise ScopeError(
                    f"{host!r} resolves to {address}, which is denied by "
                    f"{denied.raw!r}"
                )
        outside = [
            address
            for address in addresses
            if not any(pattern.matches(address) for pattern in self.allowed)
        ]
        if outside:
            raise ScopeError(
                f"{host!r} (allowed as {matched.raw!r}) resolves to "
                f"{', '.join(outside)}, which is not in scope. Add the address "
                "or its CIDR to allowed_hosts if that is intended."
            )
        return matched.raw


def load_scope(path: str | Path) -> Scope:
    """Read, validate and fingerprint a scope file."""
    source = Path(path).expanduser()
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ScopeError(f"cannot read scope file {source}: {exc}") from None

    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScopeError(f"scope file {source} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ScopeError(f"scope file {source} must contain a JSON object")

    if data.get("acknowledge_authorization") is not True:
        raise ScopeError(
            f'{source} is missing "acknowledge_authorization": true. Relift '
            "will not touch anything without an explicit authorisation statement."
        )

    for key in ("engagement", "authorized_by"):
        if not str(data.get(key) or "").strip():
            raise ScopeError(f"{source} is missing required field {key!r}")

    if not data.get("expires"):
        raise ScopeError(
            f"{source} is missing 'expires'. An engagement without an end date "
            "is not a scope."
        )
    try:
        expires = _parse_when(data["expires"])
    except (ValueError, TypeError):
        raise ScopeError(
            f"{source}: 'expires' must be ISO-8601, got {data['expires']!r}"
        ) from None

    allowed_raw = [str(x) for x in (data.get("allowed_hosts") or []) if str(x).strip()]
    if not allowed_raw:
        raise ScopeError(f"{source} allows nothing: allowed_hosts is empty")
    denied_raw = [str(x) for x in (data.get("denied_hosts") or []) if str(x).strip()]

    allowed = [compile_pattern(entry) for entry in allowed_raw]
    denied = [compile_pattern(entry) for entry in denied_raw]
    allow_wide = bool(data.get("allow_wide_ranges", False))

    if not allow_wide:
        for pattern in allowed + denied:
            if pattern.kind != "network":
                continue
            limit = MAX_V4_PREFIX if pattern.value.version == 4 else MAX_V6_PREFIX
            if pattern.value.prefixlen < limit:
                raise ScopeError(
                    f"{pattern.raw!r} covers more than a /{limit}. Set "
                    '"allow_wide_ranges": true in the scope file if that is '
                    "genuinely what you mean."
                )

    try:
        max_risk = Risk(str(data.get("max_risk", "safe")).lower())
    except ValueError:
        raise ScopeError(
            f"{source}: max_risk must be passive, safe or intrusive, got "
            f"{data.get('max_risk')!r}"
        ) from None
    if max_risk is Risk.DESTRUCTIVE:
        raise ScopeError(
            "max_risk 'destructive' is not a thing here: no such module exists."
        )

    allow_intrusive = bool(data.get("allow_intrusive", False))
    if allow_intrusive and RISK_RANK[max_risk] < RISK_RANK[Risk.INTRUSIVE]:
        raise ScopeError(
            '"allow_intrusive" is true but max_risk is lower. Set '
            '"max_risk": "intrusive" as well, deliberately.'
        )

    try:
        rps = float(data.get("rate_limit_rps", 5))
    except (TypeError, ValueError):
        raise ScopeError(f"{source}: rate_limit_rps must be a number") from None
    if rps <= 0 or rps > 200:
        raise ScopeError(
            f"{source}: rate_limit_rps must be between 0 and 200, got {rps:g}"
        )

    ports: list[int] = []
    for entry in data.get("ports") or list(DEFAULT_PORTS):
        try:
            port = int(entry)
        except (TypeError, ValueError):
            raise ScopeError(f"{source}: bad port {entry!r}") from None
        if not 1 <= port <= 65535:
            raise ScopeError(f"{source}: port {port} is out of range")
        ports.append(port)

    scope = Scope(
        path=source,
        digest=sha256(raw).hexdigest(),
        engagement=str(data["engagement"]).strip(),
        authorized_by=str(data["authorized_by"]).strip(),
        organization=str(data.get("organization") or "").strip(),
        expires=expires,
        allowed_raw=allowed_raw,
        denied_raw=denied_raw,
        max_risk=max_risk,
        allow_intrusive=allow_intrusive,
        allow_wide_ranges=allow_wide,
        rate_limit_rps=rps,
        ports=tuple(sorted(set(ports))),
        notes=str(data.get("notes") or ""),
        allowed=allowed,
        denied=denied,
    )
    scope._check_expiry()
    return scope


def build_scope_document(
    engagement: str,
    hosts: Iterable[str] = (),
    denies: Iterable[str] = (),
    authorized_by: str = "Jay",
    organization: str = "Pixelcity",
    expires: datetime | None = None,
    max_risk: Risk = Risk.SAFE,
    ports: Iterable[int] = DEFAULT_PORTS,
    allow_intrusive: bool = False,
    notes: str = "",
) -> dict[str, Any]:
    """Build the JSON document written by ``relift init-scope``."""
    host_list = [str(h).strip() for h in hosts if str(h).strip()]
    if not host_list:
        host_list = ["127.0.0.1", "::1"]
    # localhost resolves to both families, so keep both literals in scope or the
    # stricter hostname check will refuse it.
    if any(h.casefold() == "localhost" for h in host_list):
        for extra in ("127.0.0.1", "::1"):
            if extra not in host_list:
                host_list.append(extra)
    when = expires or (_now() + timedelta(days=30))
    return {
        "engagement": engagement,
        "authorized_by": authorized_by,
        "organization": organization,
        "acknowledge_authorization": True,
        "expires": when.isoformat(timespec="seconds"),
        "allowed_hosts": host_list,
        "denied_hosts": [str(d).strip() for d in denies if str(d).strip()],
        "max_risk": max_risk.value,
        "allow_intrusive": allow_intrusive,
        "allow_wide_ranges": False,
        "rate_limit_rps": 5,
        "ports": sorted({int(p) for p in ports}),
        "notes": notes,
    }
