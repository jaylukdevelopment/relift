"""Command line surface: list, providers, init-scope, plan, scan, report."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import BANNER, __version__, catalog
from . import chains as chain_engine
from .ai import Analyst, build_provider, provider_report
from .audit import AuditLog, find_run, load_run, write_run
from .config import ai_settings, load_config, scan_settings
from .models import Risk, Target
from .modules import ScanContext
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
from .scope import ScopeError, build_scope_document, load_scope


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relift",
        description="Pixelcity red-team orchestrator for authorized infrastructure testing.",
        epilog="Every technique is listed by 'relift list'. Nothing runs "
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
    p_list.add_argument("--json", action="store_true")

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

    for name, text in (
        ("plan", "show the ordered run plan without sending traffic"),
        ("scan", "run the plan (dry-run unless --execute)"),
    ):
        sub_parser = sub.add_parser(name, help=text)
        sub_parser.add_argument("--target", required=True)
        sub_parser.add_argument("--scope", required=True)
        sub_parser.add_argument("--profile", choices=list(catalog.PROFILES))
        _add_analyst_flags(sub_parser)
        sub_parser.add_argument("--json", action="store_true")
        if name == "scan":
            sub_parser.add_argument(
                "--execute", action="store_true", help="actually send traffic"
            )
            sub_parser.add_argument("--ports", metavar="LIST")
            sub_parser.add_argument("--timeout", type=float, default=6.0)
            sub_parser.add_argument("--insecure", action="store_true")
            sub_parser.add_argument(
                "--db-creds",
                metavar="FILE",
                help="JSON file of credentials you already hold (intrusive tier)",
            )
            sub_parser.add_argument(
                "--sqli-url",
                metavar="URL",
                help="URL with a parameter to test for injection (intrusive tier)",
            )
            sub_parser.add_argument(
                "--sqli-param",
                metavar="NAME",
                help="which query parameter --sqli-url should be probed on",
            )

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


def _cmd_plan(args: argparse.Namespace) -> int:
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
    target, scope, matched, analyst, audit, profile, _ = _prepare(args)
    plan = make_plan(target, scope, profile, analyst)
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
        print(
            yellow("dry run: nothing was sent. ") + "add "
            + bold("--execute") + " to run it."
        )
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
    if args.command == "providers":
        return _cmd_providers(args)
    if args.command == "init-scope":
        return _cmd_init_scope(args)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "scan":
        return _cmd_scan(args)
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
