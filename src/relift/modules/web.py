"""Web techniques: header audit, method exposure, disclosure, template scan."""

from __future__ import annotations

import json
import re

from ..models import Severity
from .base import MissingTool, Module, ScanContext, finding, run_tool, tool_path

# (header, severity when missing, why it matters)
SECURITY_HEADERS = (
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "No HSTS: the first request may go out in plaintext and be downgraded.",
    ),
    (
        "content-security-policy",
        Severity.MEDIUM,
        "No CSP: any injected script runs with the page's full privileges.",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "MIME sniffing not disabled.",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "No clickjacking protection (CSP frame-ancestors also counts).",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "Referrer leakage not restricted.",
    ),
    (
        "permissions-policy",
        Severity.INFO,
        "No Permissions-Policy for browser features.",
    ),
)

RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")

SENSITIVE_HINTS = (
    "admin",
    "backup",
    "bak",
    "private",
    "secret",
    "config",
    "staging",
    "internal",
    ".git",
    ".env",
    "db",
    "sql",
    "test",
    "dev",
)


def coerce_severity(value: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


class HeadersModule(Module):
    attack_id = "web.headers"

    def run(self, ctx: ScanContext):
        response = ctx.http_get("/")
        if response.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Could not read response headers",
                    Severity.INFO,
                    detail=response.error,
                    evidence={"url": response.url},
                )
            ]

        present = {name: response.header(name) for name, _, _ in SECURITY_HEADERS}
        findings = []
        for name, severity, why in SECURITY_HEADERS:
            if present[name]:
                continue
            if name == "strict-transport-security" and ctx.target.scheme != "https":
                continue  # HSTS means nothing on a plaintext origin
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Missing security header: {name}",
                    severity,
                    detail=why,
                    evidence={"header": name, "url": response.url},
                )
            )

        if not findings:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "All audited security headers present",
                    Severity.INFO,
                    detail=", ".join(name for name, _, _ in SECURITY_HEADERS),
                    evidence={"present": present},
                )
            )

        server = response.header("server")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Server header discloses a version",
                    Severity.LOW,
                    detail=f"Server: {server}",
                    evidence={"server": server},
                )
            )
        return findings


class MethodsModule(Module):
    attack_id = "web.methods"

    def run(self, ctx: ScanContext):
        findings = []
        options = ctx.http_get("/", method="OPTIONS")
        allow = options.header("allow")
        declared = []
        if allow:
            declared = [part.strip().upper() for part in allow.split(",") if part.strip()]
        risky = [m for m in declared if m in RISKY_METHODS]

        if risky:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Risky HTTP methods declared: {', '.join(risky)}",
                    Severity.MEDIUM,
                    detail=f"Allow: {allow}",
                    evidence={"allow": allow, "methods": declared, "risky": risky},
                )
            )
        else:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No risky methods declared",
                    Severity.INFO,
                    detail=f"Allow: {allow}" if allow else "OPTIONS returned no Allow header",
                    evidence={"allow": allow, "status": options.status},
                )
            )

        trace = ctx.http_get("/", method="TRACE")
        if trace.status == 200:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "TRACE is enabled",
                    Severity.MEDIUM,
                    detail="The server echoes the request back, which enables "
                           "cross-site tracing.",
                    evidence={"status": trace.status},
                )
            )
        return findings


class ContentDisclosureModule(Module):
    attack_id = "web.content_disclosure"

    def run(self, ctx: ScanContext):
        findings = []

        robots = ctx.http_get("/robots.txt")
        if robots.status == 200 and robots.body:
            disallowed: list[str] = []
            sitemaps: list[str] = []
            for line in robots.text.splitlines():
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                if ":" not in entry:
                    continue
                key, value = entry.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "disallow" and value not in ("", "/"):
                    disallowed.append(value)
                elif key == "sitemap" and value:
                    sitemaps.append(value)

            if disallowed:
                flagged = [
                    p for p in disallowed
                    if any(hint in p.lower() for hint in SENSITIVE_HINTS)
                ]
                findings.append(
                    finding(
                        ctx,
                        self.attack_id,
                        f"robots.txt names {len(disallowed)} disallowed path(s)",
                        Severity.MEDIUM if flagged else Severity.INFO,
                        detail=", ".join(disallowed[:15]),
                        evidence={
                            "disallowed": disallowed,
                            "interesting": flagged,
                            "note": "paths are reported, not fetched",
                        },
                        confidence="high" if flagged else "medium",
                    )
                )
            if sitemaps:
                findings.append(
                    finding(
                        ctx,
                        self.attack_id,
                        f"robots.txt advertises {len(sitemaps)} sitemap(s)",
                        Severity.INFO,
                        detail=", ".join(sitemaps[:5]),
                        evidence={"sitemaps": sitemaps},
                    )
                )

        sitemap = ctx.http_get("/sitemap.xml")
        if sitemap.status == 200 and b"<loc>" in sitemap.body:
            locations = re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap.text, re.I | re.S)
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"sitemap.xml lists {len(locations)} URL(s)",
                    Severity.INFO,
                    detail=", ".join(url.strip()[:80] for url in locations[:10]),
                    evidence={"count": len(locations)},
                )
            )

        if not findings:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No robots.txt or sitemap disclosure",
                    Severity.INFO,
                    detail=f"robots.txt status {robots.status}, "
                           f"sitemap.xml status {sitemap.status}",
                    evidence={"robots_status": robots.status,
                              "sitemap_status": sitemap.status},
                )
            )
        return findings


class TemplateScanModule(Module):
    attack_id = "web.template_scan"

    def run(self, ctx: ScanContext):
        binary = tool_path("nuclei")
        if not binary:
            raise MissingTool("nuclei")
        argv = [
            binary,
            "-u",
            ctx.target.url("/"),
            "-severity",
            "info,low,medium",
            "-no-interactsh",
            "-disable-update-check",
            "-silent",
            "-jsonl",
            "-rate-limit",
            str(max(1, int(ctx.scope.rate_limit_rps))),
        ]
        code, stdout, stderr = run_tool(argv, timeout=max(300.0, ctx.timeout * 60))

        matches = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                matches.append(json.loads(line))
            except ValueError:
                continue

        findings = []
        for match in matches:
            info = match.get("info") or {}
            template = match.get("template-id") or match.get("templateID") or "unknown"
            reference = info.get("reference")
            if isinstance(reference, str):
                references = [reference]
            else:
                references = [str(r) for r in (reference or [])]
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{template}: {info.get('name') or 'match'}",
                    coerce_severity(info.get("severity", "info")),
                    detail=str(match.get("matched-at") or match.get("host") or ""),
                    evidence={
                        "template": template,
                        "name": info.get("name", ""),
                        "matched_at": match.get("matched-at", ""),
                        "matcher": match.get("matcher-name", ""),
                    },
                    references=references,
                    confidence="medium",
                )
            )

        if not findings:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No template matches",
                    Severity.INFO,
                    detail=stderr.strip()[:300],
                    evidence={"argv": argv, "exit": code},
                )
            )
        return findings


class ServerAuditModule(Module):
    attack_id = "web.server_audit"

    def run(self, ctx: ScanContext):
        binary = tool_path("nikto")
        if not binary:
            raise MissingTool("nikto")
        argv = [
            binary,
            "-h",
            ctx.target.url("/"),
            "-Tuning",
            "123b",
            "-nointeractive",
            "-ask",
            "no",
        ]
        code, stdout, stderr = run_tool(argv, timeout=max(600.0, ctx.timeout * 100))

        lines = [
            line.strip()[2:]
            for line in stdout.splitlines()
            if line.strip().startswith("+ ") and len(line.strip()) > 4
        ]
        findings = []
        for entry in lines[:25]:
            lowered = entry.lower()
            severity = Severity.MEDIUM if any(
                hint in lowered
                for hint in ("vulnerab", "outdated", "osvdb", "sql", "xss", "traversal")
            ) else Severity.LOW
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    entry[:100],
                    severity,
                    detail="nikto finding — verify before reporting",
                    evidence={"raw": entry},
                    confidence="low",
                )
            )

        if not findings:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "nikto reported nothing actionable",
                    Severity.INFO,
                    detail=stderr.strip()[:300],
                    evidence={"argv": argv, "exit": code},
                )
            )
        return findings
