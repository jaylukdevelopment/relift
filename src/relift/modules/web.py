"""Web techniques: headers, methods, disclosure, CORS, cookies, path probes,
template scans."""

from __future__ import annotations

import json
import re
import urllib.parse
import uuid

from ..models import Severity
from .base import (
    MissingInput,
    MissingTool,
    Module,
    ScanContext,
    finding,
    query_param_value,
    run_tool,
    swap_query_param,
    tool_path,
)

# An origin that can never belong to the target, used to see whether a CORS
# policy reflects arbitrary callers. .invalid is reserved by RFC 2606.
CORS_PROBE_ORIGIN = "https://relift-probe.invalid"

# Cookie names that usually carry a session. Used only to grade severity —
# an unrecognised cookie still gets audited.
SESSION_COOKIE_HINTS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "remember",
    "login",
)

# Bounded, fixed path list for web.dir_bruteforce. Each entry is
# (path, what it is, severity if it is reachable). No wordlist file, no user
# input: a fixed list is auditable and cannot be pointed at a bigger target.
PROBE_PATHS: tuple[tuple[str, str, Severity], ...] = (
    ("/.git/HEAD", "Git metadata", Severity.HIGH),
    ("/.env", "Environment file", Severity.CRITICAL),
    ("/.svn/entries", "Subversion metadata", Severity.HIGH),
    ("/.DS_Store", "macOS directory index", Severity.LOW),
    ("/backup.zip", "Backup archive", Severity.HIGH),
    ("/backup.sql", "Database dump", Severity.CRITICAL),
    ("/db.sql", "Database dump", Severity.CRITICAL),
    ("/docker-compose.yml", "Compose file", Severity.HIGH),
    ("/Dockerfile", "Build recipe", Severity.LOW),
    ("/wp-config.php.bak", "WordPress config backup", Severity.CRITICAL),
    ("/config.php.bak", "Configuration backup", Severity.CRITICAL),
    ("/phpinfo.php", "phpinfo page", Severity.MEDIUM),
    ("/server-status", "Apache status page", Severity.MEDIUM),
    ("/actuator/env", "Spring actuator environment", Severity.HIGH),
    ("/actuator/health", "Spring actuator health", Severity.LOW),
    ("/swagger.json", "API description", Severity.LOW),
    ("/openapi.json", "API description", Severity.LOW),
    ("/graphql", "GraphQL endpoint", Severity.LOW),
    ("/admin", "Admin console", Severity.MEDIUM),
    ("/admin/login", "Admin login", Severity.MEDIUM),
    ("/wp-admin/", "WordPress admin", Severity.MEDIUM),
    ("/wp-login.php", "WordPress login", Severity.MEDIUM),
    ("/phpmyadmin/", "phpMyAdmin", Severity.MEDIUM),
    ("/debug", "Debug endpoint", Severity.MEDIUM),
    ("/metrics", "Metrics endpoint", Severity.MEDIUM),
    ("/.well-known/security.txt", "Security contact", Severity.INFO),
)

# Total requests this technique may send, calibration included.
MAX_PATH_PROBES = 40
BODY_WINDOW = 20 * 1024

# Reserved, unroutable host. A redirect here cannot be a legitimate destination.
REDIRECT_TARGET = "relift-probe.invalid"
REDIRECT_PAYLOADS = (
    f"https://{REDIRECT_TARGET}/",
    f"//{REDIRECT_TARGET}/",
    f"https://{REDIRECT_TARGET}",
    f"////{REDIRECT_TARGET}",
    f"https:{'/' * 2}{REDIRECT_TARGET}/%2f..",
)

# Fixed traversal payloads. One marker line is proof; the file is never stored.
TRAVERSAL_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
)
TRAVERSAL_MARKERS = (
    ("root:x:0:0:", "Unix passwd file"),
    ("daemon:x:1:1:", "Unix passwd file"),
    ("[extensions]", "Windows win.ini"),
    ("[fonts]", "Windows win.ini"),
)

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
        report_only = response.header("content-security-policy-report-only")
        findings = []
        for name, severity, why in SECURITY_HEADERS:
            if present[name]:
                continue
            if name == "strict-transport-security" and ctx.target.scheme != "https":
                continue  # HSTS means nothing on a plaintext origin
            detail = why
            if name == "content-security-policy" and report_only:
                # Report-only is the rehearsal, not the control: violations are
                # collected and nothing is blocked.
                detail = (
                    "A Content-Security-Policy-Report-Only header is present; it "
                    "reports violations but does not block injected script. "
                    "Shipping the same policy as an enforcing CSP is the fix."
                )
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Missing security header: {name}",
                    severity,
                    detail=detail,
                    evidence={
                        "header": name,
                        "url": response.url,
                        "report_only": report_only if name == "content-security-policy" else "",
                    },
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


class CorsPolicyModule(Module):
    """Does the target hand its responses to origins it does not control?

    One extra request with an ``Origin`` header. A reflected origin *with*
    credentials is the difference between a public read API and a page that
    will hand a logged-in user's data to any site that asks.
    """

    attack_id = "web.cors_policy"

    def run(self, ctx: ScanContext):
        baseline = ctx.http_get("/")
        if baseline.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Could not read CORS headers",
                    Severity.INFO,
                    detail=baseline.error,
                    evidence={"url": baseline.url},
                )
            ]

        probe = ctx.http_get("/", headers={"Origin": CORS_PROBE_ORIGIN})
        if probe.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "CORS probe did not complete",
                    Severity.INFO,
                    detail=probe.error,
                    evidence={"url": probe.url},
                )
            ]

        acao = probe.header("access-control-allow-origin").strip()
        acac = probe.header("access-control-allow-credentials").strip().lower() == "true"
        acam = probe.header("access-control-allow-methods")
        vary = probe.header("vary")
        wildcard = acao == "*"
        reflected = acao.rstrip("/").lower() == CORS_PROBE_ORIGIN
        exploitable = bool(reflected and acac)

        evidence = {
            "url": probe.url,
            "origin_sent": CORS_PROBE_ORIGIN,
            "acao": acao,
            "acac": acac,
            "acam": acam,
            "vary": vary,
            "wildcard": wildcard,
            "reflected": reflected,
            "exploitable": exploitable,
        }

        if exploitable:
            title = "CORS reflects any origin with credentials"
            severity = Severity.HIGH
            detail = (
                f"{CORS_PROBE_ORIGIN} was echoed in Access-Control-Allow-Origin "
                "with Access-Control-Allow-Credentials: true. Any site a "
                "logged-in visitor opens can read this origin's responses."
            )
        elif reflected:
            title = "CORS reflects an arbitrary origin"
            severity = Severity.MEDIUM
            detail = (
                f"{CORS_PROBE_ORIGIN} was echoed in Access-Control-Allow-Origin. "
                "Without credentials the reach is limited to unauthenticated "
                "reads, but the policy is not an allowlist."
            )
        elif wildcard and acac:
            title = "CORS wildcard combined with credentials"
            severity = Severity.LOW
            detail = (
                "Access-Control-Allow-Origin is * while credentials are allowed. "
                "Browsers reject that pair, so this is a configuration smell "
                "rather than a live exposure."
            )
        elif wildcard:
            title = "CORS allows any origin (no credentials)"
            severity = Severity.INFO
            detail = (
                "Public read access is intentional on many sites; this is only "
                "a finding if the origin serves authenticated content."
            )
        elif acao:
            title = f"CORS allows a fixed origin ({acao})"
            severity = Severity.INFO
            detail = "The allowlist did not reflect the probe origin."
        else:
            title = "No CORS policy on the root path"
            severity = Severity.INFO
            detail = (
                "No Access-Control-Allow-Origin was returned for a cross-origin "
                "request; the browser default (deny) applies."
            )

        findings = [finding(ctx, self.attack_id, title, severity, detail, evidence)]
        if (reflected or wildcard) and "origin" not in vary.lower():
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "CORS response is not marked Vary: Origin",
                    Severity.LOW,
                    detail=(
                        "A shared cache can serve one origin's CORS response to "
                        "another. Add Vary: Origin wherever the header is dynamic."
                    ),
                    evidence={"vary": vary, "acao": acao},
                )
            )
        return findings


def parse_set_cookie(value: str) -> dict:
    """Split one Set-Cookie header into a name and its attributes."""
    parts = [part.strip() for part in str(value).split(";")]
    name, _, first = (parts[0] if parts else "").partition("=")
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip()
    return {
        "name": name.strip(),
        "value_present": bool(first),
        "secure": "secure" in attributes,
        "httponly": "httponly" in attributes,
        "samesite": attributes.get("samesite", ""),
        "domain": attributes.get("domain", ""),
        "path": attributes.get("path", ""),
        "session": not ("expires" in attributes or "max-age" in attributes),
        "attributes": sorted(attributes),
    }


def looks_like_session(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SESSION_COOKIE_HINTS)


class CookieFlagsModule(Module):
    """Audit the flags on every cookie the root path sets.

    Read-only and single-request: nothing is decoded, replayed or attacked. The
    question is only whether the cookie that carries authority is protected
    from script access, plaintext transport and cross-site sending.
    """

    attack_id = "web.cookie_flags"

    def run(self, ctx: ScanContext):
        response = ctx.http_get("/")
        if response.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Could not read cookies",
                    Severity.INFO,
                    detail=response.error,
                    evidence={"url": response.url},
                )
            ]

        raw = response.headers_all("set-cookie")
        if not raw:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "No cookies set on the root path",
                    Severity.INFO,
                    detail="Nothing to audit; authenticated areas may still set them.",
                    evidence={"cookies": [], "insecure_session": []},
                )
            ]

        cookies = [parse_set_cookie(value) for value in raw]
        https = ctx.target.scheme == "https"
        findings = []

        insecure_session = [
            cookie["name"]
            for cookie in cookies
            if looks_like_session(cookie["name"])
            and (not cookie["httponly"] or not cookie["secure"])
        ]

        findings.append(
            finding(
                ctx,
                self.attack_id,
                f"{len(cookies)} cookie(s) audited",
                Severity.INFO,
                detail=", ".join(cookie["name"] or "?" for cookie in cookies),
                evidence={
                    "cookies": cookies,
                    "insecure_session": insecure_session,
                    "url": response.url,
                },
            )
        )

        unsercured = [c["name"] for c in cookies if not c["secure"]]
        if unsercured:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Cookie sent without the Secure flag",
                    Severity.MEDIUM if https else Severity.LOW,
                    detail=(
                        "These cookies can travel over plaintext HTTP, where a "
                        "passive observer on the path can read them: "
                        + ", ".join(unsercured)
                    ),
                    evidence={"cookies": unsercured, "https": https},
                )
            )

        no_httponly = [c["name"] for c in cookies if not c["httponly"]]
        if no_httponly:
            session_hits = [name for name in no_httponly if looks_like_session(name)]
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Cookie readable from JavaScript",
                    Severity.MEDIUM if session_hits else Severity.LOW,
                    detail=(
                        "No HttpOnly flag: any XSS on this origin can read these "
                        "cookies. " + ", ".join(no_httponly)
                    ),
                    evidence={"cookies": no_httponly, "session_cookies": session_hits},
                )
            )

        no_samesite = [c["name"] for c in cookies if not c["samesite"]]
        if no_samesite:
            session_hits = [name for name in no_samesite if looks_like_session(name)]
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Cookie has no SameSite attribute",
                    Severity.LOW,
                    detail=(
                        "Without SameSite the browser's default cross-site policy "
                        "applies and varies by browser: "
                        + ", ".join(no_samesite)
                    ),
                    evidence={"cookies": no_samesite, "session_cookies": session_hits},
                )
            )

        none_insecure = [
            c["name"]
            for c in cookies
            if c["samesite"].lower() == "none" and not c["secure"]
        ]
        if none_insecure:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SameSite=None without Secure is refused by browsers",
                    Severity.MEDIUM,
                    detail="Cookie will be dropped: " + ", ".join(none_insecure),
                    evidence={"cookies": none_insecure},
                )
            )

        broad = [
            c["name"]
            for c in cookies
            if c["domain"].startswith(".") and c["domain"].count(".") == 2
        ]
        if broad:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Cookie scoped to a parent domain",
                    Severity.LOW,
                    detail=(
                        "A parent-domain cookie is sent to every sibling "
                        "subdomain, including ones this assessment never saw: "
                        + ", ".join(broad)
                    ),
                    evidence={"cookies": broad},
                )
            )
        return findings


class DirectoryProbeModule(Module):
    """Bounded, calibrated probe for well-known exposed paths.

    Design constraints, in order of importance: a fixed 26-entry list (no
    wordlist, no user input), at most ``MAX_PATH_PROBES`` requests including
    calibration, no redirect following, and an abort when the server answers
    200 to a random path — an uncalibrated soft-404 turns every miss into a
    confident false positive. Bodies are measured, never stored.
    """

    attack_id = "web.dir_bruteforce"

    def run(self, ctx: ScanContext):
        if ctx.dry_run:
            return []

        token = "relift-" + uuid.uuid4().hex[:10]
        baseline = ctx.http_get(f"/{token}")
        control = ctx.http_get(f"/{token}-control")
        if baseline.error or control.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Path probe could not calibrate",
                    Severity.INFO,
                    detail=(baseline.error or control.error)[:200],
                    evidence={"url": baseline.url},
                )
            ]

        baseline_len = len(baseline.body)
        soft_404 = (
            baseline.status in (200, 204)
            and control.status in (200, 204)
            and abs(len(control.body) - baseline_len) <= 16
        )
        if soft_404:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Path probing skipped: the server answers 200 for unknown paths",
                    Severity.INFO,
                    detail=(
                        "Two random paths both returned "
                        f"{baseline.status} with near-identical bodies, so a hit "
                        "cannot be distinguished from a miss. Not reported as a "
                        "pass on the paths themselves."
                    ),
                    evidence={
                        "baseline_status": baseline.status,
                        "baseline_length": baseline_len,
                        "soft_404": True,
                        "probed": 2,
                    },
                )
            ]

        findings = []
        probed = 2
        for path, label, severity in PROBE_PATHS:
            if probed >= MAX_PATH_PROBES:
                break
            probed += 1
            response = ctx.http_get(path)
            if response.error:
                continue
            length = len(response.body)
            location = response.header("location")

            if response.status in (200, 204) and not (
                abs(length - baseline_len) <= 16 and response.status == baseline.status
            ):
                findings.append(
                    finding(
                        ctx,
                        self.attack_id,
                        f"Reachable: {path} ({label})",
                        severity,
                        detail=(
                            f"HTTP {response.status}, {length} bytes"
                            + (f", redirects to {location[:80]}" if location else "")
                        ),
                        evidence={
                            "path": path,
                            "label": label,
                            "status": response.status,
                            "length": length,
                            "content_type": response.header("content-type")[:80],
                            "location": location[:120],
                            "calibrated": True,
                        },
                    )
                )
            elif response.status in (401, 403):
                findings.append(
                    finding(
                        ctx,
                        self.attack_id,
                        f"Exists but access-controlled: {path} ({label})",
                        Severity.LOW,
                        detail=f"HTTP {response.status}; the path is real but not readable.",
                        evidence={
                            "path": path,
                            "label": label,
                            "status": response.status,
                            "length": length,
                            "calibrated": True,
                        },
                    )
                )
            elif response.status in (301, 302, 303, 307, 308):
                # /foo -> /foo/ is the framework normalising a route, not a
                # discovered path. Reporting it would manufacture a finding.
                if location.rstrip("/") == path.rstrip("/") or not location:
                    continue
                findings.append(
                    finding(
                        ctx,
                        self.attack_id,
                        f"Redirects: {path} ({label})",
                        Severity.INFO,
                        detail=f"HTTP {response.status} to {location[:100]}",
                        evidence={
                            "path": path,
                            "label": label,
                            "status": response.status,
                            "location": location[:120],
                        },
                    )
                )

        findings.append(
            finding(
                ctx,
                self.attack_id,
                f"{len(PROBE_PATHS)} well-known paths probed",
                Severity.INFO,
                detail=(
                    f"{probed} request(s) sent, calibrated against a "
                    f"{baseline.status} baseline. A miss is not proof of absence: "
                    "this list is fixed and small by design."
                ),
                evidence={
                    "probed": probed,
                    "baseline_status": baseline.status,
                    "baseline_length": baseline_len,
                    "soft_404": False,
                    "hits": sum(
                        1 for item in findings if item.severity is not Severity.INFO
                    ),
                },
            )
        )
        return findings


class OpenRedirectModule(Module):
    """Does the named parameter send the browser off-origin?

    Only one parameter is touched, with five fixed payloads aimed at a reserved
    ``.invalid`` host. A redirect to a path on the target itself is routing, not
    a finding, so the Location host has to match exactly.
    """

    attack_id = "web.open_redirect"

    def run(self, ctx: ScanContext):
        url, param = ctx.inject_url, ctx.inject_param
        if not url or not param:
            return []  # no probe point named: silent, not a skipped technique
        original = query_param_value(url, param)
        if original is None:
            return []

        sent = 0
        for payload in REDIRECT_PAYLOADS:
            probe = ctx.http_get_url(swap_query_param(url, param, payload))
            sent += 1
            if probe.error:
                continue
            location = probe.header("location")
            if not location:
                continue
            host = (urllib.parse.urlsplit(location).hostname or "").casefold()
            if host == REDIRECT_TARGET:
                return [
                    finding(
                        ctx,
                        self.attack_id,
                        f"Open redirect in parameter {param}",
                        Severity.HIGH,
                        detail=(
                            f"The parameter sent the response to {location[:120]} "
                            f"(HTTP {probe.status}). A link on your own domain can "
                            "now land on an attacker's page, which is the shape "
                            "of a credible phishing link."
                        ),
                        evidence={
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "location": location[:200],
                            "status": probe.status,
                            "confirmed": True,
                            "requests_sent": sent,
                        },
                        references=["CWE-601", "OWASP-A01:2021"],
                        confidence="high",
                    )
                ]

        return [
            finding(
                ctx,
                self.attack_id,
                f"No open redirect in parameter {param}",
                Severity.INFO,
                detail=(
                    f"{sent} fixed payload(s) aimed at {REDIRECT_TARGET}; the target "
                    "never answered with a redirect to that host. Relative redirects "
                    "are not a finding."
                ),
                evidence={
                    "url": url,
                    "param": param,
                    "confirmed": False,
                    "requests_sent": sent,
                },
                references=["CWE-601"],
                confidence="medium",
            )
        ]


class PathTraversalModule(Module):
    """Proof that the named parameter reads files it should not.

    Six fixed payloads, one operator-named parameter, no payload supplied by
    the operator. A hit is reported as a marker line (``root:x:0:0:``), never as
    file contents: the point is to prove arbitrary read, not to exfiltrate.
    """

    attack_id = "web.path_traversal"

    def run(self, ctx: ScanContext):
        url, param = ctx.inject_url, ctx.inject_param
        if not url or not param:
            raise MissingInput("--sqli-url and --sqli-param are required")
        original = query_param_value(url, param)
        if original is None:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"Parameter {param} is not present in the supplied URL",
                    Severity.INFO,
                    detail="Nothing was probed.",
                    evidence={"url": url, "param": param, "confirmed": False},
                )
            ]

        sent = 0
        for payload in TRAVERSAL_PAYLOADS:
            probe = ctx.http_get_url(swap_query_param(url, param, payload))
            sent += 1
            if probe.error:
                continue
            body = probe.text[:BODY_WINDOW]
            for marker, label in TRAVERSAL_MARKERS:
                if marker not in body:
                    continue
                return [
                    finding(
                        ctx,
                        self.attack_id,
                        f"Path traversal in parameter {param} reads {label}",
                        Severity.CRITICAL,
                        detail=(
                            f"Payload {sent} returned the {label} marker "
                            f"'{marker}' in the response. That is arbitrary file "
                            "read: configuration, private keys and credentials "
                            "live in the same reachable set. The file itself was "
                            "not stored or returned in this report."
                        ),
                        evidence={
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "marker": marker,
                            "marker_label": label,
                            "confirmed": True,
                            "requests_sent": sent,
                            "bytes_returned": len(probe.body),
                        },
                        references=["CWE-22", "OWASP-A01:2021"],
                        confidence="high",
                    )
                ]

        return [
            finding(
                ctx,
                self.attack_id,
                f"No traversal marker in parameter {param}",
                Severity.INFO,
                detail=(
                    f"{sent} fixed payload(s). A clean result means these encodings "
                    "did not reach a readable file, not that the parameter is safe."
                ),
                evidence={
                    "url": url,
                    "param": param,
                    "confirmed": False,
                    "requests_sent": sent,
                },
                references=["CWE-22"],
                confidence="low",
            )
        ]


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
