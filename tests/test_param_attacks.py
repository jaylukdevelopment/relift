"""The parameter attacks that prove impact: open redirect and path traversal.

Loopback server, fixed payload lists, and an assertion that a confirmed read
never carries file contents into the run artefact.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler

import pytest

from relift.models import Severity
from relift.modules.base import MissingInput
from relift.modules.web import OpenRedirectModule, PathTraversalModule

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _handler(behaviour):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
            status, headers, body = behaviour(self.path)
            payload = body.encode("utf-8")
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    return Handler


def _param(path: str, name: str) -> str:
    values = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get(name)
    return values[0] if values else ""


def _ctx(scan_ctx, server, path: str, param: str):
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return scan_ctx(
        base,
        inject_url=f"{base}{path}",
        inject_param=param,
    )


def test_open_redirect_is_confirmed_only_for_an_offsite_location(scan_ctx, serve_http):
    def behaviour(path):
        target = _param(path, "next")
        if "relift-probe.invalid" in target:
            return 302, [("Location", target)], ""
        return 200, [], "fine"

    with serve_http(_handler(behaviour)) as server:
        findings = OpenRedirectModule().run(_ctx(scan_ctx, server, "/go?next=home", "next"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["confirmed"] is True
    assert "relift-probe.invalid" in finding.evidence["location"]
    assert finding.evidence["requests_sent"] <= 5


def test_a_same_host_redirect_is_not_an_open_redirect(scan_ctx, serve_http):
    def behaviour(path):
        return 302, [("Location", "/login")], ""

    with serve_http(_handler(behaviour)) as server:
        findings = OpenRedirectModule().run(_ctx(scan_ctx, server, "/go?next=home", "next"))

    assert findings[0].evidence["confirmed"] is False
    assert findings[0].severity is Severity.INFO


def test_no_parameter_means_no_requests_at_all(scan_ctx, serve_http):
    calls: list[str] = []

    def behaviour(path):
        calls.append(path)
        return 200, [], "fine"

    with serve_http(_handler(behaviour)) as server:
        ctx = scan_ctx(f"http://127.0.0.1:{server.server_address[1]}")
        assert OpenRedirectModule().run(ctx) == []

    assert calls == []


def test_path_traversal_is_proved_by_a_marker_not_the_file(scan_ctx, serve_http):
    def behaviour(path):
        if "etc/passwd" in _param(path, "file"):
            return 200, [], PASSWD
        return 200, [], "not found"

    with serve_http(_handler(behaviour)) as server:
        findings = PathTraversalModule().run(
            _ctx(scan_ctx, server, "/download?file=report.pdf", "file")
        )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["confirmed"] is True
    assert finding.evidence["marker"] == "root:x:0:0:"
    assert finding.evidence["marker_label"] == "Unix passwd file"

    artefact = json.dumps(finding.to_dict())
    assert "root:x:0:0:" in artefact  # the marker is evidence
    assert "/bin/bash" not in artefact  # the file body is not
    assert "daemon:x:1:1:" not in artefact


def test_path_traversal_reports_a_clean_miss_honestly(scan_ctx, serve_http):
    def behaviour(path):  # noqa: ARG001
        return 200, [], "not found"

    with serve_http(_handler(behaviour)) as server:
        findings = PathTraversalModule().run(
            _ctx(scan_ctx, server, "/download?file=report.pdf", "file")
        )

    assert findings[0].evidence["confirmed"] is False
    assert "not that the parameter is safe" in findings[0].detail


def test_path_traversal_needs_a_named_parameter(scan_ctx):
    with pytest.raises(MissingInput):
        PathTraversalModule().run(scan_ctx("http://127.0.0.1:9"))
