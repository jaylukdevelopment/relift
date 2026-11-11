"""The web techniques added in 0.3: CORS, cookie flags, bounded path probe.

Each is driven against a loopback server that answers exactly the way the
technique is supposed to notice. No internet, no target, port 0.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from relift import chains as chain_engine
from relift.models import Severity
from relift.modules.web import (
    MAX_PATH_PROBES,
    PROBE_PATHS,
    CookieFlagsModule,
    CorsPolicyModule,
    DirectoryProbeModule,
    parse_set_cookie,
)


def _handler(routes: dict[str, tuple[int, list[tuple[str, str]], bytes]]):
    """Build a handler class from a small path table, 404 by default."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
            path = self.path.split("?", 1)[0]
            status, headers, body = routes.get(path, (404, [], b"not found"))
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):  # silence the test output
            return

    return Handler


def _find(findings, predicate):
    return [item for item in findings if predicate(item)]


def test_report_only_csp_is_reported_as_not_enforcing(scan_ctx, serve_http):
    handler = _handler(
        {
            "/": (
                200,
                [("Content-Security-Policy-Report-Only", "default-src 'self'")],
                b"<html></html>",
            )
        }
    )
    from relift.modules.web import HeadersModule

    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = HeadersModule().run(ctx)

    csp = [item for item in findings if item.evidence.get("header") == "content-security-policy"]
    assert csp, "report-only must still count as a missing enforcing policy"
    assert "Report-Only" in csp[0].detail
    assert csp[0].evidence["report_only"] == "default-src 'self'"


def test_parse_set_cookie_keeps_attributes():
    parsed = parse_set_cookie("sid=abc; Path=/; Domain=.example.com; HttpOnly; SameSite=Lax")
    assert parsed["name"] == "sid"
    assert parsed["httponly"] is True
    assert parsed["secure"] is False
    assert parsed["samesite"] == "Lax"
    assert parsed["domain"] == ".example.com"
    assert parsed["session"] is True


def test_cors_reflection_with_credentials_is_high(scan_ctx, serve_http):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    with serve_http(Handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = CorsPolicyModule().run(ctx)

    worst = max(findings, key=lambda item: item.severity is Severity.HIGH)
    assert worst.severity is Severity.HIGH
    assert worst.evidence["reflected"] is True
    assert worst.evidence["exploitable"] is True
    assert any("Vary" in item.title for item in findings)


def test_cors_absent_policy_is_informational(scan_ctx, serve_http):
    handler = _handler({"/": (200, [], b"<html></html>")})
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = CorsPolicyModule().run(ctx)

    assert findings
    assert all(item.severity is Severity.INFO for item in findings)
    assert "No CORS policy" in findings[0].title


def test_cookie_flags_flag_an_unprotected_session_cookie(scan_ctx, serve_http):
    handler = _handler(
        {
            "/": (
                200,
                [
                    ("Set-Cookie", "sessionid=abc; Path=/"),
                    ("Set-Cookie", "theme=dark; Secure; HttpOnly"),
                ],
                b"<html></html>",
            )
        }
    )
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = CookieFlagsModule().run(ctx)

    summary = _find(findings, lambda item: "audited" in item.title)[0]
    assert len(summary.evidence["cookies"]) == 2
    assert summary.evidence["insecure_session"] == ["sessionid"]
    flagged = _find(findings, lambda item: item.evidence.get("cookies") == ["sessionid"])
    assert flagged, "the session cookie should be named in a finding"
    assert any(item.severity in (Severity.LOW, Severity.MEDIUM) for item in flagged)


def test_cookie_flags_are_quiet_when_every_cookie_is_protected(scan_ctx, serve_http):
    handler = _handler(
        {
            "/": (
                200,
                [("Set-Cookie", "sid=x; Secure; HttpOnly; SameSite=Strict")],
                b"<html></html>",
            )
        }
    )
    with serve_http(handler) as server:
        ctx = scan_ctx(f"https://127.0.0.1:{server.server_address[1]}")
        findings = CookieFlagsModule().run(ctx)

    assert [item.severity for item in findings] == [Severity.INFO]


def test_path_probe_reports_an_exposed_file_and_ignores_misses(scan_ctx, serve_http):
    handler = _handler({"/.env": (200, [], b"SECRET=1\n"), "/admin": (403, [], b"no")})
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = DirectoryProbeModule().run(ctx)

    exposed = _find(findings, lambda item: item.evidence.get("path") == "/.env")
    assert exposed and exposed[0].severity is Severity.CRITICAL
    protected = _find(findings, lambda item: item.evidence.get("path") == "/admin")
    assert protected and protected[0].severity is Severity.LOW
    assert "access-controlled" in protected[0].title
    assert not _find(findings, lambda item: item.evidence.get("path") == "/.git/HEAD")
    summary = _find(findings, lambda item: "paths probed" in item.title)[0]
    assert summary.evidence["probed"] <= MAX_PATH_PROBES


def test_path_probe_ignores_trailing_slash_redirects(scan_ctx, serve_http):
    """A framework normalising /admin -> /admin/ is routing, not exposure."""
    handler = _handler(
        {
            "/admin": (308, [("Location", "/admin/")], b""),
            "/phpmyadmin/": (308, [("Location", "/phpmyadmin")], b""),
        }
    )
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = DirectoryProbeModule().run(ctx)

    assert [item.title for item in findings if "Redirects" in item.title] == []
    assert len(findings) == 1
    assert "paths probed" in findings[0].title


def test_path_probe_reports_a_redirect_to_a_different_path(scan_ctx, serve_http):
    handler = _handler({"/admin": (302, [("Location", "/login")], b"")})
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = DirectoryProbeModule().run(ctx)

    redirects = [item for item in findings if "Redirects" in item.title]
    assert [item.evidence["location"] for item in redirects] == ["/login"]


def test_path_probe_aborts_on_a_soft_404(scan_ctx, serve_http):
    """A server that answers 200 to anything must not produce 26 'hits'."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"<html><body>welcome</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    with serve_http(Handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = DirectoryProbeModule().run(ctx)

    assert len(findings) == 1
    assert "calibration" in findings[0].title or "skipped" in findings[0].title
    assert findings[0].evidence["soft_404"] is True


def test_path_probe_is_silent_in_dry_run(scan_ctx):
    ctx = scan_ctx("http://127.0.0.1:9", dry_run=True)
    assert DirectoryProbeModule().run(ctx) == []


def test_probe_list_is_small_and_fixed():
    assert len(PROBE_PATHS) <= MAX_PATH_PROBES
    assert len({path for path, _label, _severity in PROBE_PATHS}) == len(PROBE_PATHS)
    assert all(path.startswith("/") for path, _label, _severity in PROBE_PATHS)


def test_cors_and_cookie_findings_create_a_session_theft_thread():
    findings = [
        {
            "attack_id": "web.cors_policy",
            "title": "CORS reflects any origin with credentials",
            "severity": "high",
            "evidence": {"acao": "https://relift-probe.invalid", "exploitable": True},
        },
        {
            "attack_id": "web.cookie_flags",
            "title": "Cookie readable from JavaScript",
            "severity": "medium",
            "evidence": {"insecure_session": ["sessionid"]},
        },
    ]
    chains = chain_engine.analyse(findings)
    assert "thread.cors-session-theft" in [chain.id for chain in chains]


def test_cors_without_an_insecure_cookie_does_not_chain():
    findings = [
        {
            "attack_id": "web.cors_policy",
            "title": "CORS reflects any origin with credentials",
            "severity": "high",
            "evidence": {"exploitable": True},
        }
    ]
    chains = chain_engine.analyse(findings)
    assert "thread.cors-session-theft" not in [chain.id for chain in chains]


def test_cors_json_evidence_survives_serialisation(scan_ctx, serve_http):
    handler = _handler(
        {"/": (200, [("Access-Control-Allow-Origin", "*")], b"<html></html>")}
    )
    with serve_http(handler) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        findings = CorsPolicyModule().run(ctx)

    payload = json.loads(json.dumps([item.to_dict() for item in findings]))
    assert payload[0]["evidence"]["wildcard"] in (True, False)
