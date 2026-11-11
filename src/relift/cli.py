"""Command line surface: list, explain, doctor, providers, scope, plan, scan,
attack, chains, report, desktop."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import BANNER, __version__, catalog
from . import chains as chain_engine
from .ai import Analyst, build_provider, provider_report, selected_provider_label
from .audit import (
    AuditLog,
    default_audit_path,
    find_run,
    load_run,
    runs_root,
    write_run,
)
from .config import ai_settings, load_config, scan_settings
from .models import Risk, Target
from .modules import MODULES, ScanContext, tool_path
from .report import (
    bold,
    chain_lines,
    configure,
    cyan,
    dim,
    green,
    red,
    render_json,
    render_markdown,
    render_plan_text,
    render_run_text,
    table,
    yellow,
)
from .runner import execute, make_plan
from .scope import (
    ScopeError,
    build_scope_document,
    load_scope,
    offline_scope,
    resolve_host,
)


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _fix_streams() -> None:
    """Make UTF-8 glyphs safe on a Windows console."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def _parse_ports(text: str) -> tuple[int, ...]:
    ports = []
    for chunk in str(text).replace(" ", "").split(","):
        if not chunk:
            continue
        try:
            port = int(chunk)
        except ValueError:
            raise ValueError(f"bad port {chunk!r}") from None
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is out of range")
        ports.append(port)
    if not ports:
        raise ValueError("no ports given")
    return tuple(sorted(set(ports)))


def _add_target_argument(parser: argparse.ArgumentParser) -> None:
    """Accept the target positionally or as --target, because both are typed.

    ``relift attack pixelcity.dev`` is what people reach for first; the flag
    stays for scripts written against 0.2 and for tab completion.
    """
    parser.add_argument(
        "target",
        nargs="?",
        metavar="TARGET",
        help="host, URL or database URI (same as --target)",
    )
    parser.add_argument(
        "--target",
        dest="target_option",
        metavar="TARGET",
        help="the target, if you prefer it as a flag",
    )


def _resolve_target(args: argparse.Namespace) -> str:
    value = str(
        getattr(args, "target_option", None) or getattr(args, "target", None) or ""
    ).strip()
    if not value:
        raise ValueError(
            "a target is required — try 'relift attack <target>' "
            "(or --target <target>)"
        )
    return value


def _load_credentials(path: str, target: Target) -> list[dict]:
    """Read the operator's own credential file.

    This is verification of credentials you already hold, not discovery: there
    is no wordlist, no default list, and no retry loop anywhere in the codebase.
    Entries for other hosts or engines are ignored rather than dialled.
    """
    source = Path(path).expanduser()
    try:
        mode = source.stat().st_mode
    except OSError as exc:
        raise ValueError(f"cannot read credential file {source}: {exc}") from None
    if os.name == "posix" and mode & 0o077:
        _err(yellow(f"credential file {source} is readable by group/other; chmod 600 it"))

    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"credential file {source} is not valid JSON: {exc}") from None

    entries = data.get("credentials") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError(
            f"{source} must contain {{\"credentials\": [...]}} or a JSON array"
        )

    selected: list[dict] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"credential #{index} in {source} is not an object")
        username = str(entry.get("username") or "").strip()
        password = str(entry.get("password") or "")
        if not username or not password:
            raise ValueError(
                f"credential #{index} in {source} needs both username and password"
            )
        engine = str(entry.get("engine") or target.engine or "").strip().lower()
        host = str(entry.get("host") or "").strip()
        if engine and engine != target.engine:
            continue
        if host and host != target.host:
            continue
        selected.append(
            {
                "username": username,
                "password": password,
                "engine": target.engine,
                "host": target.host,
                "port": int(entry.get("port") or target.port),
                "database": str(entry.get("database") or target.database_name or ""),
                "note": str(entry.get("note") or ""),
            }
        )
    if not selected:
        raise ValueError(
            f"{source} has no credential matching {target.engine}://{target.host}"
        )
    return selected


def _add_analyst_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ai", metavar="ID", help="AI provider id (none = rule engine)")
    parser.add_argument("--no-ai", action="store_true", help="force the rule engine")


# depth -> (profile, scope ceiling, allow_intrusive, include_external)
ATTACK_DEPTHS: dict[str, tuple[str, Risk, bool, bool]] = {
    "1": ("passive", Risk.PASSIVE, False, False),
    "2": ("safe", Risk.SAFE, False, False),
    "3": ("standard", Risk.SAFE, False, True),
    "4": ("lab", Risk.INTRUSIVE, True, False),
    "5": ("lab", Risk.INTRUSIVE, True, True),
}

_DEPTH_ALIASES = {
    "quiet": "1",
    "passive": "1",
    "safe": "2",
    "standard": "3",
    "intrusive": "4",
    "deep": "4",
    "full": "5",
    "max": "5",
}

DEPTH_NAMES = {
    "1": "passive",
    "2": "safe",
    "3": "standard",
    "4": "intrusive",
    "5": "full",
}


def _parse_depth(value: str) -> tuple[str, str, Risk, bool, bool]:
    """Turn ``--depth 3`` (or a name) into a profile and a scope ceiling."""
    text = str(value).strip().lower()
    text = _DEPTH_ALIASES.get(text, text)
    if text not in ATTACK_DEPTHS:
        raise ValueError(
            f"unknown depth {value!r}; use 1-5 or "
            "passive, safe, standard, intrusive, full"
        )
    profile, ceiling, intrusive, external = ATTACK_DEPTHS[text]
    return text, profile, ceiling, intrusive, external


def _attack_scope_path(host: str) -> Path:
    root = Path(
        os.environ.get("RELIFT_SCOPE_DIR")
        or (Path.home() / ".relift" / "scopes")
    ).expanduser()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)[:60]
    return root / f"attack-{safe}-{stamp}.json"


def _author_attack_scope(
    target: Target,
    ceiling: Risk,
    intrusive: bool,
    args: argparse.Namespace,
) -> Path:
    """Write the one-target engagement that ``relift attack`` runs under.

    The scope file is not a formality: it is the audit artefact that records
    which host was authorised, by whom, for how long and at what tier. The
    command removes the setup step, not the record.
    """
    addresses = resolve_host(target.host)
    if not addresses:
        raise ScopeError(
            f"{target.host!r} does not resolve. Refusing to attack a name with "
            "no address."
        )
    hosts = list(dict.fromkeys([target.host, *addresses]))

    expires = None
    if getattr(args, "expires", None):
        text = str(args.expires)
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        expires = datetime.fromisoformat(text)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    if expires is None:
        expires = datetime.now(timezone.utc) + timedelta(hours=24)

    ports = _attack_scope_ports(args, target)
    document = build_scope_document(
        engagement=f"attack {target.host}",
        # The name and every address it resolves to right now: a name is only
        # as trustworthy as what it points at during the run.
        hosts=hosts,
        authorized_by=args.authorized_by,
        organization=args.organization,
        expires=expires,
        max_risk=ceiling,
        ports=ports,
        allow_intrusive=intrusive,
        notes=f"authored by 'relift attack' for a single target on {utc_stamp()}",
    )

    path = _attack_scope_path(target.host)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _attack_scope_ports(args: argparse.Namespace, target: Target) -> tuple[int, ...]:
    """Ports an authored attack scope sweeps.

    The target's own port is always included: `attack host:8099` that never
    probes 8099 would be a scope bug, not a sensible default.
    """
    if getattr(args, "ports", None):
        return _parse_ports(args.ports)
    base = {22, 80, 443, 8000, 8080, 8443}
    if target.port:
        base.add(int(target.port))
    return tuple(sorted(base))


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relift",
        description="Pixelcity red-team orchestrator for authorized infrastructure testing.",
        epilog="examples:\n"
               "  relift attack pixelcity.dev            scope + run, safe tier\n"
               "  relift attack pixelcity.dev --dry-run  plan only, nothing sent\n"
               "  relift scan https://host --scope s.json --execute\n"
               "  relift list --search cors             find a technique\n"
               "Every technique is listed by 'relift list'. Nothing runs "
               "without a scope file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"relift {__version__} · Pixelcity · author Jay",
    )
    parser.add_argument("--config", metavar="PATH", help="path to relift.config.json")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="print the attack catalogue")
    p_list.add_argument(
        "--category", help=" | ".join(catalog.categories())
    )
    p_list.add_argument("--implemented-only", action="store_true")
    p_list.add_argument(
        "--search",
        metavar="TEXT",
        help="only entries whose id, name or summary contains TEXT",
    )
    p_list.add_argument("--json", action="store_true")

    p_explain = sub.add_parser(
        "explain", help="describe one technique in full"
    )
    p_explain.add_argument("attack_id", metavar="ID", help="e.g. web.cors_policy")
    p_explain.add_argument("--json", action="store_true")

    p_doctor = sub.add_parser(
        "doctor",
        help="check this machine's setup before the first run",
        description="Read-only environment check: paths, external tools, AI "
        "provider and — when a target is given — whether the name resolves. "
        "Sends no traffic to the target.",
    )
    p_doctor.add_argument(
        "target", nargs="?", metavar="TARGET", help="also check that this resolves"
    )
    p_doctor.add_argument("--json", action="store_true")

    p_prov = sub.add_parser("providers", help="show AI providers and readiness")
    p_prov.add_argument("--json", action="store_true")

    p_init = sub.add_parser("init-scope", help="write a scope file")
    p_init.add_argument("--engagement", required=True)
    p_init.add_argument("--host", action="append", metavar="HOST")
    p_init.add_argument("--deny", action="append", metavar="HOST")
    p_init.add_argument("--out", default="scope.json")
    p_init.add_argument("--authorized-by", default="Jay")
    p_init.add_argument("--organization", default="Pixelcity")
    p_init.add_argument("--expires", metavar="ISO8601")
    p_init.add_argument("--max-risk", default="safe", choices=["passive", "safe"])
    p_init.add_argument("--ports", metavar="LIST")
    p_init.add_argument("--allow-intrusive", action="store_true")
    p_init.add_argument("--notes", default="")
    p_init.add_argument("--force", action="store_true")

    def _execution_flags(parser: argparse.ArgumentParser, execute: bool) -> None:
        if execute:
            parser.add_argument(
                "--execute", action="store_true", help="actually send traffic"
            )
        parser.add_argument("--ports", metavar="LIST")
        parser.add_argument("--timeout", type=float, default=6.0)
        parser.add_argument("--insecure", action="store_true")
        parser.add_argument(
            "--db-creds",
            metavar="FILE",
            help="JSON file of credentials you already hold (intrusive tier)",
        )
        parser.add_argument(
            "--sqli-url",
            "--param-url",
            dest="sqli_url",
            metavar="URL",
            help="URL with the parameter to probe (injection, traversal, redirect)",
        )
        parser.add_argument(
            "--sqli-param",
            "--param",
            dest="sqli_param",
            metavar="NAME",
            help="which query parameter the parameter techniques should probe on",
        )

    for name, text in (
        ("plan", "show the ordered run plan without sending traffic"),
        ("scan", "run the plan (dry-run unless --execute)"),
    ):
        sub_parser = sub.add_parser(name, help=text)
        _add_target_argument(sub_parser)
        sub_parser.add_argument("--scope", required=True)
        sub_parser.add_argument("--profile", choices=list(catalog.PROFILES))
        _add_analyst_flags(sub_parser)
        sub_parser.add_argument("--json", action="store_true")
        if name == "scan":
            _execution_flags(sub_parser, execute=True)

    p_attack = sub.add_parser(
        "attack",
        help="one command: authorise the target, plan and run it",
        description="Author a one-target, 24-hour engagement for the target, then "
        "run it. --depth picks how far the run goes: 1 passive, 2 safe, "
        "3 standard (external tools), 4 intrusive, 5 full. Every run still "
        "writes a scope file and an audit record.",
    )
    _add_target_argument(p_attack)
    p_attack.add_argument(
        "--depth",
        default="2",
        metavar="N",
        help="1-5 or passive|safe|standard|intrusive|full (default: 2, safe)",
    )
    p_attack.add_argument(
        "--dry-run",
        action="store_true",
        help="authorise and plan, then stop without sending a request",
    )
    p_attack.add_argument(
        "--scope",
        help="use an existing scope instead of authoring one for this target",
    )
    p_attack.add_argument("--authorized-by", default="Jay")
    p_attack.add_argument("--organization", default="Pixelcity")
    p_attack.add_argument("--expires", metavar="ISO8601")
    _add_analyst_flags(p_attack)
    p_attack.add_argument("--json", action="store_true")
    _execution_flags(p_attack, execute=False)

    p_code = sub.add_parser(
        "code",
        help="audit a local codebase",
        description="Audit a directory: hardcoded secrets, dangerous sinks and "
        "dependency advisories. Reads local files only; the single outbound "
        "request is the OSV advisory lookup, disabled with --no-osv.",
    )
    p_code.add_argument("path", metavar="PATH", help="directory to audit")
    p_code.add_argument(
        "--profile",
        choices=list(catalog.PROFILES),
        default="safe",
        help="ceiling for the run (default: safe; code techniques are passive)",
    )
    p_code.add_argument(
        "--no-osv",
        action="store_true",
        help="skip the OSV advisory lookup and inventory versions only",
    )
    _add_analyst_flags(p_code)
    p_code.add_argument("--json", action="store_true")

    p_report = sub.add_parser("report", help="render a stored run")
    p_report.add_argument("--run", help="run id, or a path to run.json (default: latest)")
    p_report.add_argument("--format", default="text", choices=["text", "md", "json"])
    p_report.add_argument("--out", help="write to a file instead of stdout")
    _add_analyst_flags(p_report)

    p_chains = sub.add_parser("chains", help="show correlated attack threads for a run")
    p_chains.add_argument("--run", help="run id or path (default: latest)")
    p_chains.add_argument("--format", default="text", choices=["text", "json"])
    p_chains.add_argument("--out", help="write to a file instead of stdout")

    p_desktop = sub.add_parser("desktop", help="launch the desktop application")
    p_desktop.add_argument("--port", type=int, default=0, help="0 picks a free port")
    p_desktop.add_argument(
        "--no-window",
        action="store_true",
        help="serve only; print the URL instead of opening a window",
    )
    return parser


# -- commands ----------------------------------------------------------------
def _cmd_list(args: argparse.Namespace) -> int:
    specs = catalog.all_specs()
    if args.category:
        wanted = args.category.strip().lower()
        if wanted not in catalog.categories():
            _err(red(f"unknown category {wanted!r}; try: " + ", ".join(catalog.categories())))
            return 3
        specs = [spec for spec in specs if spec.category == wanted]
    if args.implemented_only:
        specs = [spec for spec in specs if spec.implemented]
    if getattr(args, "search", None):
        needle = str(args.search).strip().lower()
        specs = [
            spec
            for spec in specs
            if needle in spec.id.lower()
            or needle in spec.name.lower()
            or needle in spec.summary.lower()
        ]
        if not specs:
            _err(yellow(f"no technique matches {args.search!r}"))
            return 3

    if args.json:
        print(json.dumps([spec.to_dict() for spec in specs], indent=2))
        return 0

    rows = []
    for spec in specs:
        if not spec.implemented:
            status = dim(spec.status)
        elif spec.external:
            status = yellow(spec.status)
        else:
            status = green(spec.status)
        tier = spec.risk.value
        tier_text = red(tier) if tier in ("intrusive", "destructive") else tier
        rows.append([cyan(spec.id), spec.name, tier_text, status])

    print(bold(BANNER))
    print(dim(catalog.summary_line()))
    print()
    print(table(rows, ["ID", "TECHNIQUE", "TIER", "STATUS"]))
    print()
    print(dim("use --json for the raw catalogue, --implemented-only to hide design-only entries"))
    return 0


def _cmd_providers(args: argparse.Namespace) -> int:
    config = load_config(getattr(args, "config", None))
    settings = ai_settings(config)
    rows_data = provider_report(settings)
    try:
        selected = build_provider(None, settings).id
    except (ValueError, OSError):
        selected = "offline"

    if args.json:
        print(json.dumps({"selected": selected, "providers": rows_data}, indent=2))
        return 0

    rows = []
    for row in rows_data:
        ready = green("yes") if row.get("ready") else dim("no")
        marker = cyan("<- selected") if row.get("id") == selected else ""
        rows.append(
            [
                cyan(row.get("id", "")),
                dim(row.get("kind", "")),
                ready,
                row.get("endpoint") or "-",
                row.get("model") or "-",
                marker,
            ]
        )
    print(bold(BANNER))
    print()
    print(table(rows, ["ID", "KIND", "READY", "ENDPOINT", "MODEL", ""]))
    print()
    print(
        dim(
            "selection: --ai -> RELIFT_AI_PROVIDER -> config -> local daemon "
            "-> cloud key -> offline"
        )
    )
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        spec = catalog.spec(args.attack_id)
    except KeyError as exc:
        _err(red(str(exc)))
        _err(dim(f"try: relift list --search {args.attack_id}"))
        return 3

    profiles = [
        name
        for name in catalog.PROFILES
        if any(item.id == spec.id for item in catalog.select(name))
    ]
    module = MODULES.get(spec.id)
    payload = dict(spec.to_dict())
    payload["module"] = type(module).__name__ if module else ""
    payload["profiles"] = profiles

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    tier = spec.risk.value
    tier_text = red(tier) if tier in ("intrusive", "destructive") else tier
    print(bold(BANNER))
    print()
    print(f"{cyan(spec.id)}   {bold(spec.name)}")
    print()
    fields = [
        ("category", spec.category),
        ("tier", tier_text),
        ("status", spec.status),
        ("families", ", ".join(spec.families)),
        ("produces", ", ".join(spec.produces) or "-"),
        ("profiles", ", ".join(profiles) or "none"),
        ("module", type(module).__name__ if module else "-"),
        ("MITRE", spec.mitre or "-"),
    ]
    width = max(len(name) for name, _ in fields)
    for name, value in fields:
        print(f"  {dim(name.ljust(width))}  {value}")
    print()
    print(f"  {bold('what it does')}  {spec.summary}")
    if spec.ai_hint:
        print(f"  {bold('why it matters')} {spec.ai_hint}")
    if spec.notes:
        print(f"  {bold('notes')}         {spec.notes}")
    print()
    return 0


def _nearest_existing(path: Path) -> Path | None:
    """The closest ancestor that exists, so mkdir -p semantics are checked."""
    candidate = path
    while True:
        if candidate.exists():
            return candidate
        if candidate.parent == candidate:
            return None
        candidate = candidate.parent


def _dir_report(label: str, path: Path) -> tuple[str, str, str]:
    if path.exists():
        writable = os.access(path, os.W_OK)
        return (
            "ok" if writable else "fail",
            label,
            f"{path} ({'writable' if writable else 'not writable'})",
        )
    ancestor = _nearest_existing(path)
    if ancestor is not None and os.access(ancestor, os.W_OK):
        return "warn", label, f"{path} (will be created on the first run)"
    return "fail", label, f"{path} (no writable ancestor: {ancestor})"


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Environment check. Reads paths and lookups only; never touches a target."""
    config = load_config(getattr(args, "config", None))
    checks: list[tuple[str, str, str]] = []

    version_ok = sys.version_info >= (3, 9)
    checks.append(
        (
            "ok" if version_ok else "fail",
            "python",
            f"{platform.python_version()} (needs 3.9+)",
        )
    )
    checks.append(("ok", "relift", f"{__version__} on {platform.platform()}"))
    checks.append(
        ("ok", "config", str(config.get("_source") or "built-in defaults"))
    )

    scope_dir = Path(
        os.environ.get("RELIFT_SCOPE_DIR")
        or (Path.home() / ".relift" / "scopes")
    ).expanduser()
    checks.append(_dir_report("scope dir", scope_dir))
    checks.append(_dir_report("run dir", runs_root()))
    audit_path = default_audit_path()
    checks.append(_dir_report("audit log", audit_path))

    external = ("nmap", "nuclei", "nikto", "sslscan")
    found = {name: tool_path(name) for name in external}
    missing = [name for name, path in found.items() if not path]
    tools_text = ", ".join(
        name if path else f"{name} (missing)" for name, path in found.items()
    )
    checks.append(("warn" if missing else "ok", "external tools", tools_text))

    provider = selected_provider_label(ai_settings(config))
    checks.append(
        (
            "ok" if provider != "offline" else "warn",
            "ai analyst",
            provider
            + ("" if provider != "offline" else " (deterministic rule engine)"),
        )
    )

    if getattr(args, "target", None):
        host = Target.parse(args.target).host
        try:
            addresses = sorted(
                {info[4][0] for info in socket.getaddrinfo(host, None)}
            )
        except OSError as exc:
            checks.append(("fail", "target", f"{host} does not resolve: {exc}"))
        else:
            checks.append(("ok", "target", f"{host} -> {', '.join(addresses)}"))

    failures = sum(1 for level, _, _ in checks if level == "fail")
    warnings = sum(1 for level, _, _ in checks if level == "warn")

    if args.json:
        print(
            json.dumps(
                {
                    "ok": failures == 0,
                    "failures": failures,
                    "warnings": warnings,
                    "checks": [
                        {"level": level, "check": name, "detail": detail}
                        for level, name, detail in checks
                    ],
                },
                indent=2,
            )
        )
        return 1 if failures else 0

    palette = {"ok": green, "warn": yellow, "fail": red}
    rows = [
        [palette[level](level), name, detail]
        for level, name, detail in checks
    ]
    print(bold(BANNER))
    print()
    print(table(rows, ["STATUS", "CHECK", "DETAIL"]))
    print()
    verdict = (
        red(f"{failures} check(s) failed")
        if failures
        else green("ready")
        + (
            dim(f" — {warnings} warning(s), nothing blocking")
            if warnings
            else ""
        )
    )
    print(verdict)
    if not failures:
        print(dim("next: relift attack <target>   ·   relift list --search cors"))
    return 1 if failures else 0


def _cmd_init_scope(args: argparse.Namespace) -> int:
    expires = None
    if args.expires:
        text = args.expires
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            expires = datetime.fromisoformat(text)
        except ValueError:
            _err(red(f"--expires must be ISO-8601, got {args.expires!r}"))
            return 3
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

    try:
        max_risk = Risk(args.max_risk)
    except ValueError:
        _err(red("--max-risk must be passive or safe"))
        return 3
    if args.allow_intrusive:
        max_risk = Risk.INTRUSIVE

    ports = (
        _parse_ports(args.ports)
        if args.ports
        else (22, 80, 443, 8000, 8080, 8443)
    )
    document = build_scope_document(
        engagement=args.engagement,
        hosts=args.host or [],
        denies=args.deny or [],
        authorized_by=args.authorized_by,
        organization=args.organization,
        expires=expires,
        max_risk=max_risk,
        ports=ports,
        allow_intrusive=args.allow_intrusive,
        notes=args.notes,
    )

    path = Path(args.out).expanduser()
    if path.exists() and not args.force:
        _err(red(f"{path} already exists; use --force to replace it"))
        return 3
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    print(bold(BANNER))
    print()
    print(f"wrote scope {cyan(str(path))}")
    print(f"  engagement  {document['engagement']}")
    print(
        f"  authorised  {document['authorized_by']} "
        f"({document['organization']})"
    )
    print(f"  expires     {document['expires']}")
    print(f"  max risk    {document['max_risk']}")
    print(f"  allowed     {', '.join(document['allowed_hosts'])}")
    if document["denied_hosts"]:
        print(f"  denied      {', '.join(document['denied_hosts'])}")
    print()
    print(
        yellow(
            "read the file before the first run: the allow list is exactly what "
            "you are authorising."
        )
    )
    return 0


def _prepare(args: argparse.Namespace):
    config = load_config(getattr(args, "config", None))
    settings = ai_settings(config)

    target = Target.parse(args.target)
    scope = load_scope(args.scope)
    matched = scope.authorize(target.host)

    provider_name = "none" if args.no_ai else (args.ai or "")
    analyst = Analyst(build_provider(provider_name or None, settings))
    audit = AuditLog()
    profile = args.profile or scan_settings(config)["profile"]

    audit.event(
        "authorize",
        engagement=scope.engagement,
        target=target.origin,
        matched=matched,
        decision="allow",
        scope=str(scope.path),
        scope_sha256=scope.digest,
        authorized_by=scope.authorized_by,
        profile=profile,
        analyst=analyst.label,
    )
    return target, scope, matched, analyst, audit, profile, config


def _cmd_code(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    if not root.exists():
        raise ValueError(f"no such path: {root}")
    if not root.is_dir():
        raise ValueError(f"{root} is a file; point 'relift code' at a directory")
    root = root.resolve()

    config = load_config(getattr(args, "config", None))
    settings = ai_settings(config)
    target = Target(
        raw=f"code://{root}", scheme="code", host="local", port=0, path=str(root)
    )
    scope = offline_scope(root)
    provider_name = "none" if args.no_ai else (args.ai or "")
    analyst = Analyst(build_provider(provider_name or None, settings))
    audit = AuditLog()
    audit.event(
        "codebase",
        path=str(root),
        profile=args.profile,
        analyst=analyst.label,
        note="local files only; no host is authorised or contacted",
    )

    plan = make_plan(target, scope, args.profile, analyst)
    ctx = ScanContext(
        target=target,
        scope=scope,
        ports=(),
        dry_run=False,
        audit=audit,
        osv=not args.no_osv,
    )

    print(bold(BANNER))
    print()
    print(f"  codebase  {cyan(str(root))}")
    print(f"  profile   {args.profile} · {len(plan.specs)} technique(s)")
    print()

    record = execute(plan, ctx, audit)
    path = write_run(record)
    payload = record.to_dict()

    print(render_run_text(payload))
    print()
    print(dim(f"run saved to {path}   audit: {audit.path}"))
    if audit.error:
        _err(yellow(f"audit log problem: {audit.error}"))
    if args.json:
        print()
        print(render_json(payload))
    return 1 if any(entry.status == "error" for entry in record.executions) else 0


def _cmd_plan(args: argparse.Namespace) -> int:
    args.target = _resolve_target(args)
    target, scope, matched, analyst, audit, profile, _ = _prepare(args)
    plan = make_plan(target, scope, profile, analyst)

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
        return 0
    print(render_plan_text(plan, scope=scope, matched=matched))
    if audit.error:
        _err(yellow(f"audit log problem: {audit.error}"))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    args.target = _resolve_target(args)
    target, scope, matched, analyst, audit, profile, _ = _prepare(args)
    plan = make_plan(
        target,
        scope,
        profile,
        analyst,
        include_external=getattr(args, "include_external", None),
    )
    ports = _parse_ports(args.ports) if args.ports else scope.port_set()

    credentials: list[dict] = []
    if getattr(args, "db_creds", None):
        credentials = _load_credentials(args.db_creds, target)
    if args.sqli_url and not args.sqli_param:
        raise ValueError("--sqli-url also needs --sqli-param")
    if args.sqli_param and not args.sqli_url:
        raise ValueError("--sqli-param also needs --sqli-url")

    ctx = ScanContext(
        target=target,
        scope=scope,
        ports=ports,
        timeout=args.timeout,
        insecure=args.insecure,
        dry_run=not args.execute,
        audit=audit,
        db_creds=credentials,
        inject_url=getattr(args, "sqli_url", "") or "",
        inject_param=getattr(args, "sqli_param", "") or "",
    )

    if not args.execute:
        print(render_plan_text(plan, scope=scope, matched=matched))
        print()
        # 'attack' has no --execute: its hint is to drop --dry-run.
        hint = (
            "re-run the same command without " + bold("--dry-run") + "."
            if getattr(args, "command", "") == "attack"
            else "add " + bold("--execute") + " to run it."
        )
        print(yellow("dry run: nothing was sent. ") + hint)
        return 0

    print(dim(f"running {len(plan.specs)} technique(s) against {target.origin} ..."))
    record = execute(plan, ctx, audit)
    path = write_run(record)
    payload = record.to_dict()

    print()
    print(render_run_text(payload))
    print()
    print(dim(f"run saved to {path}   audit: {audit.path}"))
    if audit.error:
        _err(yellow(f"audit log problem: {audit.error}"))

    if args.json:
        print()
        print(render_json(payload))

    return 1 if any(entry.status == "error" for entry in record.executions) else 0


def _cmd_attack(args: argparse.Namespace) -> int:
    depth, profile, ceiling, intrusive, external = _parse_depth(args.depth)
    args.target = _resolve_target(args)
    target = Target.parse(args.target)

    if args.scope:
        scope_path = Path(args.scope).expanduser()
    else:
        scope_path = _author_attack_scope(target, ceiling, intrusive, args)

    scope = load_scope(scope_path)
    name = DEPTH_NAMES[depth]

    print(bold(BANNER))
    print()
    print(f"  target   {cyan(target.origin)}")
    print(
        f"  depth    {depth}/5 · {bold(name)} · ceiling {scope.max_risk.value}"
        + (" · external tools" if external else "")
    )
    expiry = scope.expires.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"  scope    {dim(str(scope_path))}  (expires {expiry})")
    if scope.risk_ceiling(ceiling) is not scope.max_risk:
        print(
            yellow(
                f"  note     scope ceiling lowers this run to "
                f"{scope.risk_ceiling(ceiling).value}"
            )
        )
    if intrusive and scope.allow_intrusive:
        print()
        print(
            yellow("  intrusive tier: only against hosts you own or are ")
            + yellow("contracted to test.")
        )
    print()

    args.scope = str(scope_path)
    args.profile = profile
    args.include_external = external
    args.execute = not getattr(args, "dry_run", False)
    return _cmd_scan(args)


def _cmd_report(args: argparse.Namespace) -> int:
    path = find_run(args.run)
    payload = load_run(path)

    if args.ai or args.no_ai or not payload.get("narrative"):
        config = load_config(getattr(args, "config", None))
        settings = ai_settings(config)
        name = "none" if args.no_ai else (args.ai or "")
        analyst = Analyst(build_provider(name or None, settings))
        payload["narrative"] = analyst.narrate(payload)
        payload["provider"] = analyst.label
        for note in analyst.notes:
            _err(yellow(f"note: {note}"))

    if args.format == "json":
        output = render_json(payload)
    elif args.format == "md":
        output = render_markdown(payload)
    else:
        output = render_run_text(payload)

    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.write_text(output + "\n", encoding="utf-8")
        print(f"wrote {out_path}")
    else:
        print(output)
    return 0


def _cmd_chains(args: argparse.Namespace) -> int:
    payload = load_run(find_run(args.run))
    chains = payload.get("chains") or [
        chain.to_dict() for chain in chain_engine.analyse(payload.get("findings") or [])
    ]
    if args.format == "json":
        worst = chains[0].get("severity") if chains else ""
        headline = (
            f"{len(chains)} attack thread(s); worst is {worst}"
            if chains
            else "no attack thread completed from these findings"
        )
        output = json.dumps(
            {
                "run_id": payload.get("run_id"),
                "target": (payload.get("target") or {}).get("raw"),
                "headline": headline,
                "chains": chains,
            },
            indent=2,
            ensure_ascii=False,
        )
    else:
        target = (payload.get("target") or {}).get("raw") or "?"
        head = [bold(BANNER), ""]
        head.append(f"{dim('target')} {cyan(str(target))}   {dim('run')} {payload.get('run_id')}")
        head.append("")
        if chains:
            head.append(bold("ATTACK THREADS"))
            head.append("")
            head.extend(chain_lines(chains))
        else:
            head.append(
                "no attack thread completed from these findings — that is a "
                "statement about the evidence, not about the target"
            )
        output = "\n".join(head)

    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.write_text(output + "\n", encoding="utf-8")
        print(f"wrote {out_path}")
    else:
        print(output)
    return 0


def _cmd_desktop(args: argparse.Namespace) -> int:
    from .desktop import launch

    return launch(open_window=not args.no_window, port=args.port)


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "explain":
        return _cmd_explain(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "providers":
        return _cmd_providers(args)
    if args.command == "init-scope":
        return _cmd_init_scope(args)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "attack":
        return _cmd_attack(args)
    if args.command == "code":
        return _cmd_code(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "chains":
        return _cmd_chains(args)
    if args.command == "desktop":
        return _cmd_desktop(args)
    parser.print_help()
    return 3


def main(argv: list[str] | None = None) -> int:
    _fix_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)
    configure(color=not getattr(args, "no_color", False))

    if not getattr(args, "command", None):
        print(bold(BANNER))
        print()
        print(bold("quick start"))
        for line in (
            ("relift doctor", "check this machine's setup"),
            ("relift list", "every technique, tier and status"),
            ("relift explain web.cors_policy", "one technique in full"),
            ("relift attack <target>", "authorise, plan and run (safe, no traffic first)"),
            ("relift attack <target> --depth 3", "add external tools when installed"),
            ("relift code .", "audit a local codebase for secrets and CVEs"),
            ("relift chains", "the attack threads from the last run"),
        ):
            print(f"  {cyan(line[0].ljust(38))} {dim(line[1])}")
        print()
        parser.print_help()
        return 0

    try:
        return _dispatch(args, parser)
    except ScopeError as exc:
        _err(red("refused: ") + str(exc))
        _err(dim("nothing was sent to the target"))
        return 2
    except KeyboardInterrupt:
        _err("")
        _err("interrupted")
        return 130
    except (ValueError, KeyError, FileNotFoundError) as exc:
        _err(red("error: ") + str(exc))
        return 3


def entry() -> None:
    """Single entry point for the console script, frozen builds and .pyz archives."""
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
