"""SQL-injection detection: bounded, detection-only, and honest about misses."""

from __future__ import annotations

import urllib.parse
from http.server import BaseHTTPRequestHandler

import pytest

from relift.models import Severity
from relift.modules.sqlinject import MAX_REQUESTS, SqlInjectionModule

BASE_BODY = "<html><body>" + "".join(
    f"<div class='row'>item {index}</div>" for index in range(60)
) + "</body></html>"


def _parameter(path, name="q"):
    query = urllib.parse.urlsplit(path).query
    return urllib.parse.parse_qs(query).get(name, [""])[0]


def _handler(behaviour, log):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            log.append(self.path)
            body, status = behaviour(self.path)
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # keep pytest output clean
            return

    return Handler


def _run(serve_http, scan_ctx, behaviour, path="/search?q=test"):
    log: list[str] = []
    with serve_http(_handler(behaviour, log)) as server:
        port = server.server_address[1]
        ctx = scan_ctx(
            f"http://127.0.0.1:{port}/",
            inject_url=f"http://127.0.0.1:{port}{path}",
            inject_param="q",
        )
        findings = SqlInjectionModule().run(ctx)
    return findings, log


def _error_behaviour(path):
    value = _parameter(path)
    if "'" in value:
        return (
            "<h1>Database error</h1><p>You have an error in your SQL syntax; "
            "check the manual that corresponds to your MySQL server version</p>",
            500,
        )
    return BASE_BODY, 200


def _boolean_behaviour(path):
    value = _parameter(path)
    if "'1'='1" in value:
        return BASE_BODY, 200
    if "'1'='2" in value:
        return "<html><body>no rows</body></html>", 200
    return BASE_BODY, 200


def _clean_behaviour(path):
    return BASE_BODY, 200


def _proof_behaviour(path):
    """The quote errors like MySQL; the cast leaks the version in the error."""
    value = _parameter(path)
    if "EXTRACTVALUE" in value:
        return "<p>XPATH syntax error: '~8.0.36'</p>", 500
    if "'" in value:
        return (
            "<h1>Database error</h1><p>You have an error in your SQL syntax; "
            "check the manual that corresponds to your MySQL server version</p>",
            500,
        )
    return BASE_BODY, 200


# -- positive results --------------------------------------------------------
def test_proof_of_impact_extracts_the_engine_version(serve_http, scan_ctx):
    findings, log = _run(serve_http, scan_ctx, _proof_behaviour)
    finding = findings[0]

    assert finding.evidence["injectable"] is True
    assert finding.evidence["proof_of_impact"]["version"] == "8.0.36"
    assert finding.evidence["proof_of_impact"]["engine"] == "mysql"
    assert "reads mysql data" in finding.title
    assert "No table rows" in finding.detail
    assert len(log) <= MAX_REQUESTS


def test_error_signature_is_reported_as_injection(serve_http, scan_ctx):
    findings, log = _run(serve_http, scan_ctx, _error_behaviour)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["injectable"] is True
    assert finding.evidence["styles"] == ["error"]
    assert finding.evidence["dbms_hint"] == "mysql"
    assert "CWE-89" in finding.references
    assert len(log) <= MAX_REQUESTS


def test_boolean_differential_is_reported(serve_http, scan_ctx):
    findings, log = _run(serve_http, scan_ctx, _boolean_behaviour)
    finding = findings[0]
    assert finding.evidence["injectable"] is True
    assert "boolean" in finding.evidence["styles"]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == "medium"
    assert len(log) <= MAX_REQUESTS


# -- negative results -------------------------------------------------------
def test_clean_target_reports_no_injection_and_stays_under_the_cap(serve_http, scan_ctx):
    findings, log = _run(serve_http, scan_ctx, _clean_behaviour)
    finding = findings[0]
    assert finding.severity is Severity.INFO
    assert finding.evidence["injectable"] is False
    assert finding.evidence["styles"] == []
    assert finding.evidence["requests_sent"] <= MAX_REQUESTS
    assert len(log) <= MAX_REQUESTS
    assert "not that the parameter is safe" in finding.detail


def test_url_without_the_parameter_sends_nothing(serve_http, scan_ctx):
    findings, log = _run(serve_http, scan_ctx, _clean_behaviour, path="/search")
    assert findings[0].severity is Severity.INFO
    assert findings[0].evidence["requests_sent"] == 0
    assert log == []


def test_missing_input_is_a_skip_not_a_crash(scan_ctx):
    from relift.modules import MissingInput

    ctx = scan_ctx("http://127.0.0.1:9/")
    with pytest.raises(MissingInput):
        SqlInjectionModule().run(ctx)


# -- the safety property ----------------------------------------------------
def test_no_payload_ever_contains_an_extraction_or_command_primitive(
    serve_http, scan_ctx
):
    forbidden = (
        "UNION",
        "INTO OUTFILE",
        "LOAD_FILE",
        "XP_CMDSHELL",
        "DROP ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "COPY ",
    )
    _, log = _run(serve_http, scan_ctx, _clean_behaviour)
    assert log, "the clean run should still have sent probes"
    for path in log:
        decoded = urllib.parse.unquote_plus(path).upper()
        for marker in forbidden:
            assert marker not in decoded, f"{marker} appeared in a probe: {path}"


def test_module_has_no_payload_input_surface():
    """There is no constructor argument, attribute or env var carrying a payload."""
    import inspect

    source = inspect.getsource(SqlInjectionModule)
    assert "argv" not in source
    assert "environ" not in source
    assert "input(" not in source
