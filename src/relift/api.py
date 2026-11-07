"""Desktop backend: a loopback-only JSON API over the same engine as the CLI.

Design constraints, in order of importance:

1. It is the same engine. A desktop scan goes through ``load_scope``,
   ``scope.authorize``, ``make_plan`` and ``execute`` exactly like ``relift
   scan --execute``. There is no second path around the scope gate.
2. It binds ``127.0.0.1`` only, and every ``/api`` call needs the token that
   was generated at launch. Browser content on another origin cannot read the
   token because no CORS headers are ever sent.
3. It serves exactly three static files from a fixed list. No path joining, no
   directory listing, no template rendering of user input. The splash is read by
   the launcher, never served.
"""

from __future__ import annotations

import json
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import BANNER, __version__, catalog
from .ai import Analyst, build_provider, provider_report
from .audit import AuditLog, default_audit_path, find_run, load_run, runs_root, write_run
from .chains import analyse as analyse_chains
from .config import ai_settings, load_config, scan_settings
from .models import Risk, Target
from .modules import ScanContext
from .report import render_markdown, render_run_text
from .runner import execute, make_plan
from .scope import ScopeError, build_scope_document, load_scope

STATIC_FILES = {
    "/": ("app.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

MAX_BODY = 256 * 1024
TOKEN_HEADER = "X-Relift-Token"


def static_root() -> Path:
    """Where the bundled UI lives, including inside a PyInstaller onefile."""
    import sys

    base = getattr(sys, "_MEIPASS", None)
    if base:
        bundled = Path(base) / "relift" / "desktop"
        if bundled.is_dir():
            return bundled
    return Path(__file__).resolve().parent / "desktop"


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# -- jobs --------------------------------------------------------------------
class Job:
    """One background scan. Polled by the UI; nothing is pushed."""

    def __init__(self, target: str, scope: str, profile: str):
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.scope = scope
        self.profile = profile
        self.status = "queued"
        self.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.finished = ""
        self.lines: list[str] = []
        self.run_id = ""
        self.error = ""
        self.payload: dict[str, Any] = {}
        self._lock = threading.Lock()

    def log(self, message: str) -> None:
        with self._lock:
            self.lines.append(message)
            del self.lines[:-200]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "target": self.target,
                "scope": self.scope,
                "profile": self.profile,
                "status": self.status,
                "started": self.started,
                "finished": self.finished,
                "lines": list(self.lines),
                "run_id": self.run_id,
                "error": self.error,
                "run": self.payload,
            }


class DesktopState:
    def __init__(self, token: str):
        self.token = token
        self.jobs: dict[str, Job] = {}
        self.config = load_config(None)
        self._lock = threading.Lock()

    def add_job(self, job: Job) -> Job:
        with self._lock:
            # Keep the most recent 20 jobs; the run artefacts live on disk.
            if len(self.jobs) >= 20:
                oldest = sorted(self.jobs.values(), key=lambda j: j.started)[0]
                self.jobs.pop(oldest.id, None)
            self.jobs[job.id] = job
        return job


def _provider_matrix(state: DesktopState) -> tuple[str, list[dict[str, Any]]]:
    settings = ai_settings(state.config)
    selected = "offline"
    try:
        selected = build_provider(None, settings).id
    except (ValueError, OSError):
        pass
    return selected, provider_report(settings)


# -- request handlers --------------------------------------------------------
def _meta(_body: dict[str, Any], state: DesktopState) -> dict[str, Any]:
    selected, providers = _provider_matrix(state)
    return {
        "tool": "relift",
        "version": __version__,
        "banner": BANNER,
        "counts": catalog.counts(),
        "categories": catalog.categories(),
        "profiles": [
            {
                "name": name,
                "description": profile.description,
                "max_risk": profile.max_risk.value,
                "external": profile.include_external,
            }
            for name, profile in catalog.PROFILES.items()
        ],
        "default_profile": scan_settings(state.config)["profile"],
        "providers": providers,
        "selected_provider": selected,
        "runs_root": str(runs_root()),
        "audit_path": str(default_audit_path()),
        "cwd": str(Path.cwd()),
    }


def _catalog(_body: dict[str, Any], _state: DesktopState) -> dict[str, Any]:
    return {"techniques": [spec.to_dict() for spec in catalog.all_specs()]}


def _scope(body: dict[str, Any]) -> dict[str, Any]:
    path = str(body.get("path") or "").strip()
    if not path:
        raise ApiError("a scope file path is required")
    return load_scope(path).to_dict()


def _init_scope(body: dict[str, Any], state: DesktopState) -> dict[str, Any]:
    engagement = str(body.get("engagement") or "").strip()
    hosts = [str(h).strip() for h in body.get("hosts") or [] if str(h).strip()]
    if not engagement:
        raise ApiError("an engagement name is required")
    if not hosts:
        raise ApiError("at least one host, CIDR or wildcard is required")
    risk_name = str(body.get("max_risk") or "safe").lower()
    try:
        max_risk = Risk(risk_name)
    except ValueError:
        raise ApiError("max_risk must be passive or safe") from None
    if max_risk is Risk.INTRUSIVE:
        raise ApiError(
            "intrusive scope cannot be created from the desktop app; "
            "set it by hand in the scope file"
        )
    days = int(body.get("expires_in_days") or 30)
    if not 1 <= days <= 365:
        raise ApiError("expires_in_days must be between 1 and 365")
    target_path = Path(str(body.get("path") or f"scope-{engagement}.json")).expanduser()
    document = build_scope_document(
        engagement=engagement,
        hosts=hosts,
        denies=body.get("denied") or [],
        authorized_by=str(body.get("authorized_by") or "Jay"),
        organization=str(body.get("organization") or "Pixelcity"),
        expires=datetime.now(timezone.utc) + timedelta(days=days),
        max_risk=max_risk,
        ports=body.get("ports") or (22, 80, 443, 5432, 3306, 6379, 27017, 1433, 9200),
        allow_intrusive=False,
        notes=str(body.get("notes") or ""),
    )
    if target_path.exists():
        raise ApiError(f"{target_path} already exists; choose another path")
    try:
        target_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ApiError(f"cannot write {target_path}: {exc}") from None
    checked = load_scope(target_path)
    return {"path": str(target_path), "scope": checked.to_dict()}


def _plan(body: dict[str, Any], state: DesktopState) -> dict[str, Any]:
    target = _target(body)
    scope = _scope_for(body, target)
    profile = _profile(body, state)
    analyst = Analyst(build_provider(None, ai_settings(state.config)))
    plan = make_plan(target, scope, profile, analyst)
    return plan.to_dict()


def _target(body: dict[str, Any]) -> Target:
    raw = str(body.get("target") or "").strip()
    if not raw:
        raise ApiError("a target is required")
    try:
        return Target.parse(raw)
    except ValueError as exc:
        raise ApiError(str(exc)) from None


def _scope_for(body: dict[str, Any], target: Target):
    path = str(body.get("scope") or "").strip()
    if not path:
        raise ApiError("a scope file is required: nothing runs without one")
    scope = load_scope(path)
    scope.authorize(target.host)
    return scope


def _profile(body: dict[str, Any], state: DesktopState) -> str:
    profile = str(body.get("profile") or scan_settings(state.config)["profile"])
    if profile not in catalog.PROFILES:
        raise ApiError(f"unknown profile {profile!r}")
    return profile


def _ports(body: dict[str, Any], scope) -> tuple[int, ...]:
    raw = body.get("ports")
    if not raw:
        return scope.port_set()
    if isinstance(raw, str):
        chips = [chunk for chunk in raw.replace(" ", "").split(",") if chunk]
    else:
        chips = [str(chunk) for chunk in raw]
    ports: list[int] = []
    for chip in chips:
        try:
            port = int(chip)
        except ValueError:
            raise ApiError(f"bad port {chip!r}") from None
        if not 1 <= port <= 65535:
            raise ApiError(f"port {port} is out of range")
        ports.append(port)
    if not ports:
        raise ApiError("no ports given")
    return tuple(sorted(set(ports)))


def _start_scan(body: dict[str, Any], state: DesktopState) -> dict[str, Any]:
    target = _target(body)
    scope = _scope_for(body, target)
    profile = _profile(body, state)
    if profile == "lab" and not scope.allow_intrusive:
        raise ApiError(
            "profile lab needs a scope file with allow_intrusive and intrusive max_risk"
        )
    job = state.add_job(Job(target=target.origin, scope=str(scope.path), profile=profile))
    credentials = body.get("db_creds") or []
    timeout = float(body.get("timeout") or 6.0)
    if not 1.0 <= timeout <= 60.0:
        raise ApiError("timeout must be between 1 and 60 seconds")

    def worker() -> None:
        job.status = "running"
        job.log(f"authorized {target.origin} under {scope.engagement}")
        try:
            analyst = Analyst(build_provider(None, ai_settings(state.config)))
            plan = make_plan(target, scope, profile, analyst)
            job.log(f"plan: {len(plan.specs)} technique(s)")
            ctx = ScanContext(
                target=target,
                scope=scope,
                ports=_ports(body, scope),
                timeout=timeout,
                insecure=bool(body.get("insecure")),
                dry_run=False,
                audit=AuditLog(),
                db_creds=credentials if isinstance(credentials, list) else [],
                inject_url=str(body.get("sqli_url") or ""),
                inject_param=str(body.get("sqli_param") or ""),
            )
            for spec in plan.specs:
                job.log(f"running {spec.id}")
            record = execute(plan, ctx, ctx.audit)
            payload = record.to_dict()
            payload["narrative"] = analyst.narrate(payload)
            payload["provider"] = analyst.label
            path = write_run(record)
            job.run_id = record.run_id
            job.payload = payload
            job.log(f"run saved: {path}")
            job.status = "done"
        except ScopeError as exc:
            job.status = "refused"
            job.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - surface it to the UI, never crash the server
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished = datetime.now(timezone.utc).isoformat(timespec="seconds")

    threading.Thread(target=worker, name=f"relift-job-{job.id}", daemon=True).start()
    return {"job_id": job.id}


def _job(body: dict[str, Any], state: DesktopState, job_id: str) -> dict[str, Any]:
    job = state.jobs.get(job_id)
    if job is None:
        raise ApiError(f"no job {job_id!r}", status=404)
    return job.to_dict()


def _list_runs(_body: dict[str, Any], _state: DesktopState) -> dict[str, Any]:
    root = runs_root()
    rows: list[dict[str, Any]] = []
    if root.is_dir():
        for directory in sorted(root.iterdir(), key=lambda p: p.name, reverse=True)[:50]:
            run_file = directory / "run.json"
            if not run_file.is_file():
                continue
            try:
                payload = json.loads(run_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            findings = payload.get("findings") or []
            counts: dict[str, int] = {}
            for item in findings:
                key = str(item.get("severity") or "info")
                counts[key] = counts.get(key, 0) + 1
            rows.append(
                {
                    "run_id": payload.get("run_id") or directory.name,
                    "target": (payload.get("target") or {}).get("raw", ""),
                    "started": payload.get("started", ""),
                    "profile": payload.get("profile", ""),
                    "engagement": payload.get("engagement", ""),
                    "findings": len(findings),
                    "chains": len(payload.get("chains") or []),
                    "severities": counts,
                }
            )
    return {"runs_root": str(root), "runs": rows}


def _load_payload(run_id: str) -> dict[str, Any]:
    try:
        return load_run(find_run(run_id))
    except FileNotFoundError as exc:
        raise ApiError(str(exc), status=404) from None


def _get_run(_body: dict[str, Any], _state: DesktopState, run_id: str) -> dict[str, Any]:
    payload = _load_payload(run_id)
    if not payload.get("chains"):
        payload["chains"] = [
            chain.to_dict() for chain in analyse_chains(payload.get("findings") or [])
        ]
    return payload


def _report(body: dict[str, Any], _state: DesktopState, run_id: str) -> dict[str, Any]:
    payload = _load_payload(run_id)
    fmt = str(body.get("format") or "md")
    if fmt == "json":
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    elif fmt == "text":
        text = render_run_text(payload)
    elif fmt == "md":
        text = render_markdown(payload)
    else:
        raise ApiError(f"unknown format {fmt!r}")
    return {"format": fmt, "text": text, "run_id": payload.get("run_id")}


def _narrate(body: dict[str, Any], state: DesktopState, run_id: str) -> dict[str, Any]:
    payload = _load_payload(run_id)
    analyst = Analyst(build_provider(None, ai_settings(state.config)))
    payload["narrative"] = analyst.narrate(payload)
    return {
        "run_id": payload.get("run_id"),
        "narrative": payload["narrative"],
        "provider": analyst.label,
        "notes": analyst.notes,
    }


def _audit(_body: dict[str, Any], _state: DesktopState) -> dict[str, Any]:
    path = default_audit_path()
    lines: list[str] = []
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-120:]
        except OSError as exc:
            raise ApiError(f"cannot read audit log: {exc}") from None
    return {"path": str(path), "lines": lines}


def _providers(_body: dict[str, Any], state: DesktopState) -> dict[str, Any]:
    selected, rows = _provider_matrix(state)
    return {"selected": selected, "providers": rows}


# -- routing -----------------------------------------------------------------
ROUTES: dict[tuple[str, str], Callable[..., dict[str, Any]]] = {
    ("GET", "/api/meta"): _meta,
    ("GET", "/api/catalog"): _catalog,
    ("GET", "/api/providers"): _providers,
    ("GET", "/api/runs"): _list_runs,
    ("GET", "/api/audit"): _audit,
    ("POST", "/api/scope"): lambda body, state: _scope(body),
    ("POST", "/api/init-scope"): _init_scope,
    ("POST", "/api/plan"): _plan,
    ("POST", "/api/scan"): _start_scan,
}

# Routes whose last path segment is a run or job id.
RUN_ROUTES: dict[str, Callable[..., dict[str, Any]]] = {
    "GET /api/runs/": _get_run,
    "POST /api/runs/": _report,  # POST /api/runs/<id>/report
    "GET /api/jobs/": _job,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "relift-desktop/" + __version__
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return  # never echo request lines; a token could end up on a terminal

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, status: int, data: dict[str, Any]) -> None:
        self._send(
            status,
            json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _fail(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError("bad Content-Length") from None
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ApiError("request body too large", status=413)
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError("body must be JSON") from None
        if not isinstance(data, dict):
            raise ApiError("body must be a JSON object")
        return data

    def _authorised(self) -> bool:
        state: DesktopState = self.server.state  # type: ignore[attr-defined]
        supplied = self.headers.get(TOKEN_HEADER) or ""
        if not secrets.compare_digest(supplied, state.token):
            return False
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host") or ""
            if origin not in (f"http://{host}", f"https://{host}"):
                return False
        return True

    # -- verbs -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._fail(405, "no CORS, no preflight")

    def _handle(self, verb: str) -> None:
        state: DesktopState = self.server.state  # type: ignore[attr-defined]
        parts = urlsplit(self.path)
        path = parts.path

        if path in STATIC_FILES:
            self._static(path)
            return
        if path == "/favicon.ico":
            self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            return
        if not path.startswith("/api/"):
            self._fail(404, "not found")
            return
        if not self._authorised():
            self._fail(401, "missing or invalid X-Relift-Token")
            return

        body: dict[str, Any] = {}
        try:
            if verb == "POST":
                body = self._body()
            elif parts.query:
                body = {k: v[-1] for k, v in parse_qs(parts.query).items()}

            handler = ROUTES.get((verb, path))
            if handler is not None:
                self._json(200, handler(body, state))
                return

            for prefix, routed in RUN_ROUTES.items():
                route_verb, route_prefix = prefix.split(" ", 1)
                if route_verb != verb or not path.startswith(route_prefix):
                    continue
                remainder = path[len(route_prefix):].strip("/")
                if not remainder:
                    continue
                segments = remainder.split("/")
                run_id = segments[0]
                if len(segments) == 2 and segments[1] == "report":
                    self._json(200, _report(body, state, run_id))
                    return
                if len(segments) == 2 and segments[1] == "narrative":
                    self._json(200, _narrate(body, state, run_id))
                    return
                if len(segments) == 1:
                    self._json(200, routed(body, state, run_id))
                    return
            self._fail(404, "not found")
        except ApiError as exc:
            self._fail(exc.status, str(exc))
        except ScopeError as exc:
            self._fail(403, f"refused: {exc}")
        except (ValueError, KeyError) as exc:
            self._fail(400, str(exc))
        except OSError as exc:
            self._fail(500, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - a handler bug must not kill the app
            self._fail(500, f"{type(exc).__name__}: {exc}")

    def _static(self, path: str) -> None:
        name, content_type = STATIC_FILES[path]
        candidate = static_root() / name
        try:
            payload = candidate.read_bytes()
        except OSError:
            self._fail(500, f"UI asset missing: {name}")
            return
        if name == "app.html":
            state: DesktopState = self.server.state  # type: ignore[attr-defined]
            bootstrap = (
                "<script>window.RELIFT_BOOT={token:" + json.dumps(state.token)
                + ",version:" + json.dumps(__version__) + "};</script>"
            ).encode("utf-8")
            payload = payload.replace(b"</head>", bootstrap + b"</head>", 1)
        self._send(200, payload, content_type)


class DesktopServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], token: str):
        super().__init__(address, Handler)
        self.state = DesktopState(token)


def build_server(port: int = 0) -> tuple[DesktopServer, str]:
    """Create a loopback server and its one-time token."""
    token = secrets.token_urlsafe(24)
    server = DesktopServer(("127.0.0.1", int(port or 0)), token)
    return server, token


__all__ = [
    "DesktopServer",
    "DesktopState",
    "build_server",
    "static_root",
]
