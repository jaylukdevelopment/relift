"""Rendering: tables, plans, run output, markdown, json. No network, no AI."""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Sequence

from . import BANNER

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_COLOR = True
_UNICODE = True


def configure(color: bool = True) -> None:
    """Set colour and glyph support. Call after stdout has been reconfigured."""
    global _COLOR, _UNICODE
    _COLOR = bool(color)
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "✓─·".encode(encoding)
        _UNICODE = True
    except (UnicodeEncodeError, LookupError):
        _UNICODE = False


def _c(text: Any, code: str = "") -> str:
    value = str(text)
    if not _COLOR or not code or not value:
        return value
    return f"\x1b[{code}m{value}\x1b[0m"


def bold(text: Any) -> str:
    return _c(text, "1")


def dim(text: Any) -> str:
    return _c(text, "2")


def red(text: Any) -> str:
    return _c(text, "31")


def green(text: Any) -> str:
    return _c(text, "32")


def yellow(text: Any) -> str:
    return _c(text, "33")


def cyan(text: Any) -> str:
    return _c(text, "36")


def magenta(text: Any) -> str:
    return _c(text, "1;35")


def ok_mark() -> str:
    return green("✓" if _UNICODE else "+")


def skip_mark() -> str:
    return dim("–" if _UNICODE else "-")


def fail_mark() -> str:
    return red("✗" if _UNICODE else "x")


def dot() -> str:
    return "·" if _UNICODE else "|"


def _visible(text: str) -> int:
    return len(ANSI.sub("", str(text)))


def _pad(text: str, width: int) -> str:
    padding = width - _visible(text)
    return text if padding <= 0 else text + " " * padding


def table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> str:
    """ANSI-aware fixed-width table."""
    columns = len(headers)
    widths = []
    for index in range(columns):
        width = _visible(str(headers[index]))
        for row in rows:
            if index < len(row):
                width = max(width, _visible(str(row[index])))
        widths.append(width)

    rule = "─" if _UNICODE else "-"
    lines = ["  ".join(bold(_pad(str(headers[i]), widths[i])) for i in range(columns))]
    lines.append("  ".join(rule * widths[i] for i in range(columns)))
    for row in rows:
        cells = [
            _pad(str(row[index]) if index < len(row) else "", widths[index])
            for index in range(columns)
        ]
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines)


def severity_tag(value: Any) -> str:
    key = str(value or "info").lower()
    styles = {
        "critical": ("1;35", "CRIT"),
        "high": ("1;31", "HIGH"),
        "medium": ("33", "MED "),
        "low": ("36", "LOW "),
        "info": ("2", "INFO"),
    }
    code, label = styles.get(key, ("2", "INFO"))
    return _c(label, code)


def severity_counts(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for item in findings:
        key = str(item.get("severity") or "info").lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _status_summary(executions: Sequence[dict[str, Any]]) -> str:
    executed = sum(1 for e in executions if e.get("status") == "ok")
    skipped = sum(1 for e in executions if e.get("status") == "skipped")
    errored = sum(1 for e in executions if e.get("status") == "error")
    parts = [bold(f"{executed} executed")]
    if skipped:
        parts.append(f"{skipped} skipped")
    if errored:
        parts.append(red(f"{errored} errored"))
    return f" {dot()} ".join(parts)


# -- plan --------------------------------------------------------------------
def render_plan_text(plan: Any, scope: Any = None, matched: str = "") -> str:
    target = plan.target
    lines = [bold(BANNER), ""]
    lines.append(
        f"{dim('target')}   {cyan(target.origin)}   "
        f"{dim('profile')}: {plan.profile}   {dim('ceiling')}: {plan.ceiling.value}"
    )
    if scope is not None:
        lines.append(
            f"{dim('scope')}    {scope.engagement} "
            f"({scope.digest[:12]}, {scope.expires_in_days}d left) "
            f"{dim('matched')} {matched!r}"
        )
    lines.append(
        f"{dim('analyst')}  {plan.analyst}"
        + (f"  {dim(plan.note)}" if plan.note else "")
    )
    lines.append("")

    rows = []
    for index, spec in enumerate(plan.specs, start=1):
        status = spec.status
        if not spec.implemented:
            status = dim(status)
        elif spec.external:
            status = yellow(status)
        else:
            status = green(status)
        tier = spec.risk.value
        rows.append([str(index), cyan(spec.id), tier, status])

    if rows:
        lines.append(table(rows, ["#", "TECHNIQUE", "TIER", "STATUS"]))
    else:
        lines.append(yellow("nothing is allowed: the scope ceiling excludes every technique"))
    lines.append("")
    lines.append(dim(f"{len(plan.specs)} technique(s) would run"))
    for note in plan.notes:
        lines.append(dim(f"note: {note}"))
    return "\n".join(lines)


# -- run ---------------------------------------------------------------------
def render_run_text(payload: dict[str, Any]) -> str:
    target = payload.get("target") or {}
    executions = payload.get("executions") or []
    findings = payload.get("findings") or []

    lines = [bold(BANNER), ""]
    lines.append(
        f"{dim('target')}   {cyan(target.get('raw', '?'))}   "
        f"{dim('engagement')}: {payload.get('engagement') or '-'}"
    )
    lines.append(
        f"{dim('scope')}    {str(payload.get('scope_sha256') or '')[:12]}   "
        f"{dim('profile')}: {payload.get('profile')}   "
        f"{dim('analyst')}: {payload.get('provider')}"
    )
    lines.append(
        f"{dim('run')}      {payload.get('run_id')}   {dim(payload.get('started', ''))}"
    )
    lines.append("")

    rows = []
    for entry in executions:
        status = entry.get("status")
        if status == "ok":
            mark = ok_mark()
        elif status == "skipped":
            mark = skip_mark()
        else:
            mark = fail_mark()

        note = entry.get("reason") or entry.get("error") or ""
        if status == "ok":
            count = entry.get("finding_count") or 0
            note = f"{count} finding(s)" if count else "no findings"
        rows.append(
            [
                mark,
                entry.get("attack_id", ""),
                status,
                f"{(entry.get('duration_ms') or 0) / 1000:.2f}s",
                note[:72],
            ]
        )

    if rows:
        lines.append(table(rows, ["", "TECHNIQUE", "RESULT", "TIME", "NOTE"]))
    lines.append("")

    if findings:
        lines.append(bold("FINDINGS"))
        lines.append("")
        for item in findings:
            lines.append(
                f" {severity_tag(item.get('severity'))} "
                f"{item.get('title', '')}  "
                f"{dim('[' + str(item.get('attack_id', '')) + ']')}"
            )
            detail = str(item.get("detail") or "").strip()
            if detail:
                lines.append(f"        {dim(detail[:150])}")
        lines.append("")

    counts = severity_counts(findings)
    summary = (
        f" {dot()} ".join(
            f"{counts[name]} {name}" for name in SEVERITY_ORDER if counts[name]
        )
        or "no findings"
    )
    lines.append(
        f"{_status_summary(executions)} {dot()} {len(findings)} finding(s) ({summary})"
    )

    narrative = (payload.get("narrative") or "").strip()
    if narrative:
        lines.append("")
        lines.append(bold("ANALYST"))
        lines.append("")
        lines.append(narrative)
    return "\n".join(lines)


# -- other formats -----------------------------------------------------------
def render_markdown(payload: dict[str, Any]) -> str:
    target = payload.get("target") or {}
    executions = payload.get("executions") or []
    findings = payload.get("findings") or []
    counts = severity_counts(findings)

    lines = ["# Relift report", ""]
    lines.append("| field | value |")
    lines.append("|---|---|")
    for key in (
        "run_id",
        "engagement",
        "profile",
        "provider",
        "started",
        "finished",
        "authorized_by",
    ):
        lines.append(f"| {key} | {payload.get(key) or '-'} |")
    lines.append(f"| target | {target.get('raw', '-')} |")
    lines.append(f"| scope sha256 | `{str(payload.get('scope_sha256') or '')[:16]}` |")
    lines.append("")

    lines.append("## Findings by severity")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("|---|---|")
    for name in SEVERITY_ORDER:
        lines.append(f"| {name} | {counts[name]} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("None observed.")
    else:
        lines.append("| severity | technique | finding | detail |")
        lines.append("|---|---|---|---|")
        for item in findings:
            detail = str(item.get("detail") or "").replace("|", "\\|")[:200]
            title = str(item.get("title") or "").replace("|", "\\|")
            lines.append(
                f"| {item.get('severity')} | `{item.get('attack_id')}` | "
                f"{title} | {detail} |"
            )
    lines.append("")

    lines.append("## Coverage")
    lines.append("")
    lines.append("| technique | result | time | note |")
    lines.append("|---|---|---|---|")
    for entry in executions:
        note = entry.get("reason") or entry.get("error") or ""
        lines.append(
            f"| `{entry.get('attack_id')}` | {entry.get('status')} | "
            f"{(entry.get('duration_ms') or 0) / 1000:.2f}s | {note[:120]} |"
        )
    lines.append("")

    narrative = (payload.get("narrative") or "").strip()
    if narrative:
        lines.append(narrative)
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by Relift (Pixelcity). Authorized testing only: the "
        "engagement scope is fingerprinted above."
    )
    return "\n".join(lines)


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)
