"""The module contract, the scan context, and the two shared helpers.

A module may only touch the network through ``ctx``. That is what makes the
rate limit and the dry-run switch total rather than advisory.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, Severity
from ..scope import Scope

MAX_BODY = 64 * 1024
USER_AGENT = "Relift/0.1 (+authorized-assessment; pixelcity)"


class MissingTool(RuntimeError):
    """An external binary the catalogue says we need is not installed."""


class MissingInput(RuntimeError):
    """A module needs operator input it was not given (a parameter, a credential)."""


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    # Duplicates matter: a response carries one Set-Cookie per cookie, and
    # collapsing them into a dict loses every cookie but the last.
    header_list: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: int = 0
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def headers_all(self, name: str) -> list[str]:
        """Every value for a header, in wire order."""
        wanted = name.lower()
        return [value for key, value in self.header_list if key.lower() == wanted]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects instead of following them: a Location may leave scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


@dataclass
class TCPConn:
    """A bounded TCP conversation: exact reads, hard caps, no unbounded waits.

    Every database module speaks through one of these so the rate limit, the
    timeout and the dry-run switch apply to protocol work exactly as they do to
    an HTTP request.
    """

    sock: Any
    host: str
    port: int
    limit: int = 1024 * 1024
    _read: int = field(default=0, repr=False)

    def send(self, payload: bytes) -> None:
        if len(payload) > self.limit:
            raise OSError("refusing to send an oversized probe")
        self.sock.sendall(payload)

    def recv_exact(self, count: int) -> bytes:
        """Read exactly ``count`` bytes or raise; used by length-prefixed frames."""
        chunks: list[bytes] = []
        remaining = count
        while remaining > 0:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise OSError("peer closed the connection mid-frame")
            chunks.append(chunk)
            remaining -= len(chunk)
            self._read += len(chunk)
            if self._read > self.limit:
                raise OSError("refusing to read an oversized response")
        return b"".join(chunks)

    def recv_some(self, count: int = 4096) -> bytes:
        chunk = self.sock.recv(min(count, self.limit - self._read) or 1)
        self._read += len(chunk)
        if self._read > self.limit:
            raise OSError("refusing to read an oversized response")
        return chunk

    def recv_until(self, marker: bytes, cap: int = 65536) -> bytes:
        """Read until ``marker`` appears. Used by line-oriented protocols."""
        buffer = b""
        while marker not in buffer:
            if len(buffer) > cap:
                raise OSError("marker not found within the read cap")
            chunk = self.recv_some(4096)
            if not chunk:
                break
            buffer += chunk
        return buffer

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> TCPConn:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


@dataclass
class ScanContext:
    """Everything a module is allowed to touch."""

    target: Any  # models.Target
    scope: Scope
    ports: tuple[int, ...] = ()
    timeout: float = 6.0
    insecure: bool = False
    dry_run: bool = False
    audit: Any = None
    # Operator-supplied credentials, already validated by the CLI. Each entry
    # is {"username", "password", "engine", "host", "port", "note"}.
    db_creds: list[dict[str, Any]] = field(default_factory=list)
    # Operator-named parameter attack point, shared by the parameter techniques
    # (SQL injection, traversal, open redirect). One point per run, by design.
    inject_url: str = ""
    inject_param: str = ""
    # code.dependencies asks OSV over HTTPS; --no-osv turns that one call off.
    osv: bool = True
    _last_net: float = field(default=0.0, repr=False)
    # Parallel modules (the port sweep) still share one budget: the lock is
    # what keeps the rate limit a control rather than a suggestion.
    _budget_lock: Any = field(default_factory=threading.Lock, repr=False)

    # -- budgeting ---------------------------------------------------------
    def throttle(self) -> None:
        """Enforce the engagement-wide request budget before any network call."""
        rps = self.scope.rate_limit_rps or 0
        if rps <= 0:
            return
        gap = 1.0 / rps
        with self._budget_lock:
            elapsed = time.monotonic() - self._last_net
            if elapsed < gap:
                time.sleep(gap - elapsed)
            self._last_net = time.monotonic()

    # -- HTTP --------------------------------------------------------------
    def http_get(
        self,
        path: str = "/",
        method: str = "GET",
        scheme: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Request on the target origin. ``scheme`` overrides a db:// scheme
        for HTTP-speaking datastores (Elasticsearch, CouchDB).

        ``headers`` exists for the handful of techniques that must send one
        extra request header (an Origin for CORS, a Referer for cache tests).
        It cannot change the host, the scheme or the method budget.
        """
        url = self.target.url(path)
        override = (scheme or "").strip().lower()
        if override in ("http", "https"):
            default = 443 if override == "https" else 80
            authority = (
                self.target.host
                if self.target.port == default
                else f"{self.target.host}:{self.target.port}"
            )
            url = f"{override}://{authority}" + (
                path if path.startswith("/") else "/" + path
            )
        return self._fetch(url, method, headers)

    def http_get_url(self, url: str, method: str = "GET") -> HttpResponse:
        """Fetch an absolute URL, but only on the authorised target host.

        Redirects and operator-supplied URLs are the two ways an assessment tool
        gets pointed at a stranger's server. Anything whose host is not the
        target is refused before a socket is opened.
        """
        parts = urllib.parse.urlsplit(url)
        if (parts.hostname or "").casefold() != self.target.host.casefold():
            return HttpResponse(
                url=url,
                error=f"refused: {parts.hostname!r} is not the authorised target host",
            )
        if (parts.scheme or "").lower() not in ("http", "https"):
            return HttpResponse(url=url, error=f"refused: scheme {parts.scheme!r}")
        return self._fetch(url, method)

    def _fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        if self.dry_run:
            return HttpResponse(url=url, error="dry-run: request not sent")
        self.throttle()
        request = urllib.request.Request(url, method=method)
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", "*/*")
        for key, value in (headers or {}).items():
            request.add_header(str(key), str(value))
        opener = urllib.request.build_opener(_NoRedirect)
        started = time.monotonic()
        try:
            with opener.open(request, timeout=self.timeout) as response:
                pairs = list(response.headers.items())
                return HttpResponse(
                    url=url,
                    status=response.status,
                    headers={k.lower(): v for k, v in pairs},
                    header_list=pairs,
                    body=response.read(MAX_BODY),
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
        except urllib.error.HTTPError as exc:
            # Redirects and 4xx/5xx land here; the headers are still interesting.
            body = b""
            try:
                body = exc.read(MAX_BODY)
            except (OSError, ValueError):
                pass
            pairs = list((exc.headers or {}).items())
            return HttpResponse(
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in pairs},
                header_list=pairs,
                body=body,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except urllib.error.URLError as exc:
            return HttpResponse(
                url=url,
                error=str(getattr(exc, "reason", exc)),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except (OSError, ValueError) as exc:
            return HttpResponse(
                url=url,
                error=str(exc),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    # -- raw TCP -----------------------------------------------------------
    def db_connect(self, port: int | None = None) -> TCPConn:
        """Open a bounded connection for protocol work. Never used in dry-run."""
        if self.dry_run:
            raise OSError("dry-run: connection not opened")
        target_port = int(port or self.target.port)
        self.throttle()
        sock = socket.create_connection(
            (self.target.host, target_port), timeout=self.timeout
        )
        sock.settimeout(self.timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        return TCPConn(sock=sock, host=self.target.host, port=target_port)

    def tcp_probe(self, port: int) -> tuple[bool, str]:
        """Connect and read whatever the service says first. Never writes."""
        if self.dry_run:
            return False, ""
        self.throttle()
        try:
            with socket.create_connection(
                (self.target.host, port), timeout=self.timeout
            ) as sock:
                sock.settimeout(min(2.0, self.timeout))
                try:
                    banner = sock.recv(256)
                except (socket.timeout, OSError):
                    banner = b""
        except (socket.timeout, OSError):
            return False, ""
        return True, banner.decode("utf-8", "replace").strip()


class Module:
    """One catalogue entry, one technique."""

    attack_id = ""

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - contract
        raise NotImplementedError


def finding(
    ctx: ScanContext,
    attack_id: str,
    title: str,
    severity: Severity = Severity.INFO,
    detail: str = "",
    evidence: dict[str, Any] | None = None,
    references: list[str] | None = None,
    confidence: str = "high",
) -> Finding:
    """Build a finding already tied to the target and the technique."""
    return Finding(
        attack_id=attack_id,
        target=ctx.target.origin,
        title=title,
        severity=severity,
        detail=detail,
        evidence=evidence or {},
        references=list(references or []),
        confidence=confidence,
    )


def swap_query_param(url: str, param: str, value: str) -> str:
    """Replace exactly one query parameter, preserving every other one."""
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, current in pairs:
        if not replaced and key == param:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, current))
    if not replaced:
        updated.append((param, value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(updated), parts.fragment)
    )


def query_param_value(url: str, param: str) -> str | None:
    """The current value of one query parameter, or None when it is absent."""
    pairs = urllib.parse.parse_qsl(
        urllib.parse.urlsplit(url).query, keep_blank_values=True
    )
    for key, value in pairs:
        if key == param:
            return value
    return None


def tool_path(name: str) -> str | None:
    """Where a required external binary lives, if it is installed at all."""
    return shutil.which(name)


def run_tool(argv: list[str], timeout: float) -> tuple[int, str, str]:
    """Run an external tool with an argv list. Never through a shell."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} timed out after {timeout:.0f}s"
    except OSError as exc:
        return 126, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""
