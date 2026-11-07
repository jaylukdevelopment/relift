"""Deterministic rule engine: no model, no network, no keys.

This is what runs when the analyst is unavailable, and it is what makes a
``--no-ai`` run byte-identical in findings to an AI-enabled one.
"""

from __future__ import annotations

from typing import Any

from ..models import SEVERITY_RANK
from .base import AIError, AIProvider

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

CATEGORY_ADVICE = {
    "web.headers": "set the missing response headers at the reverse proxy, once, for every vhost",
    "web.methods": "disable unused HTTP verbs at the server or proxy",
    "web.content_disclosure": "move admin and backup paths out of robots.txt; it is a map",
    "web.template_scan": "work through the template matches by family, not one by one",
    "web.server_audit": "verify each nikto line by hand; most are configuration smells",
    "tls.certificate": "fix certificate validity and hostname coverage before anything else",
    "tls.protocol_support": "require TLS 1.2 and prefer 1.3 in the listener configuration",
    "recon.port_scan": "close or firewall ports that do not need to answer from this network",
    "recon.service_scan": "pin and patch the versions that answer; banners age badly",
    "recon.http_fingerprint": "stop advertising framework and version headers",
    "recon.dns": "keep the address inventory in your asset list; unknown addresses are findings",
}


class OfflineProvider(AIProvider):
    id = "offline"
    kind = "none"
    model = "rule-engine"

    def __init__(self, model="", base_url="", timeout=60.0, api_key="", detail=""):
        super().__init__(model or self.model, base_url, timeout, api_key)
        self._detail = detail or "deterministic rule engine"

    def available(self) -> bool:
        return True

    def info(self):
        info = super().info()
        info.detail = self._detail
        return info

    def complete(self, system, prompt, max_tokens=900, temperature=0.2) -> str:
        raise AIError(
            "the offline provider has no model; the rule engine handles this instead"
        )


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for item in findings:
        severity = str(item.get("severity", "info")).lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def rule_narrative(payload: dict[str, Any]) -> str:
    """A readable report narrative with no model involved."""
    target = (payload.get("target") or {}).get("raw") or "?"
    engagement = payload.get("engagement") or "(unnamed)"
    profile = payload.get("profile") or "?"
    run_id = payload.get("run_id") or "?"
    findings = payload.get("findings") or []
    executions = payload.get("executions") or []

    ok = [e for e in executions if e.get("status") == "ok"]
    skipped = [e for e in executions if e.get("status") == "skipped"]
    errored = [e for e in executions if e.get("status") == "error"]
    counts = _counts(findings)

    lines: list[str] = []
    lines.append("## Summary")
    lines.append("")
    if not findings:
        lines.append(
            f"Nothing was found on {target} in {len(ok)} executed technique(s). "
            "That is not the same as nothing being wrong: read the coverage notes "
            "at the end before drawing conclusions."
        )
    else:
        notable = [s for s in ("critical", "high", "medium") if counts.get(s)]
        headline = ", ".join(f"{counts[s]} {s}" for s in notable) or "only informational items"
        lines.append(
            f"{len(findings)} finding(s) on {target} from {len(ok)} executed "
            f"technique(s): {headline}."
        )
    lines.append("")

    lines.append("## What to fix first")
    lines.append("")
    ranked = sorted(
        findings,
        key=lambda item: -SEVERITY_RANK.get(
            _severity(item.get("severity")), 0
        ),
    )
    actionable = [
        item for item in ranked
        if str(item.get("severity", "info")).lower() in ("critical", "high", "medium")
    ][:3]
    if not actionable:
        actionable = ranked[:2]
    if not actionable:
        lines.append("1. Nothing actionable. Re-run after the next deployment.")
    else:
        for index, item in enumerate(actionable, start=1):
            advice = CATEGORY_ADVICE.get(str(item.get("attack_id")), "")
            line = (
                f"{index}. **{item.get('title')}** ({item.get('severity')})"
                f" — {item.get('attack_id')}"
            )
            if advice:
                line += f"; {advice}"
            lines.append(line)
    lines.append("")

    lines.append("## Coverage")
    lines.append("")
    lines.append(f"Engagement: {engagement} · profile: {profile} · run: {run_id}")
    lines.append(
        f"Executed {len(ok)} technique(s)"
        + (f", {len(skipped)} skipped" if skipped else "")
        + (f", {len(errored)} errored" if errored else "")
        + "."
    )
    for entry in skipped[:8]:
        note = entry.get("reason") or "not available"
        lines.append(f"- skipped `{entry.get('attack_id')}`: {note}")
    for entry in errored[:8]:
        note = entry.get("error") or "unknown error"
        lines.append(f"- errored `{entry.get('attack_id')}`: {note}")
    lines.append("")
    lines.append(
        "This narrative was produced by the built-in rule engine. No model was "
        "consulted and no data left the machine."
    )
    return "\n".join(lines)


def _severity(value: Any):
    from ..models import Severity

    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO
