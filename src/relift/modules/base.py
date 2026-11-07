"""The module contract, the scan context, and the two shared helpers.

A module may only touch the network through ``ctx``. That is what makes the
rate limit and the dry-run switch total rather than advisory.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, Severity
from ..scope import Scope

MAX_BODY = 64 * 1024
USER_AGENT = "Relift/0.1 (+authorized-assessment; pixelcity)"


class MissingTool(RuntimeError):
    """An external binary the catalogue says we need is not installed."""


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: int = 0
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects instead of following them: a Location may leave scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


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
    _last_net: float = field(default=0.0, repr=False)

    # -- budgeting ---------------------------------------------------------
    def throttle(self) -> None:
        """Enforce the engagement-wide request budget before any network call."""
        rps = self.scope.rate_limit_rps or 0
        if rps <= 0:
            return
        gap = 1.0 / rps
        elapsed = time.monotonic() - self._last_net
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last_net = time.monotonic()

    # -- HTTP --------------------------------------------------------------
    def http_get(self, path: str = "/", method: str = "GET") -> HttpResponse:
        url = self.target.url(path)
        if self.dry_run:
            return HttpResponse(url=url, error="dry-run: request not sent")
        self.throttle()
        request = urllib.request.Request(url, method=method)
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", "*/*")
        opener = urllib.request.build_opener(_NoRedirect)
        started = time.monotonic()
        try:
            with opener.open(request, timeout=self.timeout) as response:
                return HttpResponse(
                    url=url,
                    status=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
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
            return HttpResponse(
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
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

    # -- TCP ---------------------------------------------------------------
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
