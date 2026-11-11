"""The connect sweep: find the open port, map it back correctly, never stall.

The sweep runs the port list in a small thread pool. A closed loopback port
refuses immediately, so this tests the result mapping (which a refactor can
easily invert) and the empty case, without depending on wall-clock timing.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler

from relift.models import Target
from relift.modules import ScanContext
from relift.modules.recon import PortScanModule


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _ctx(scope, port: int, ports: tuple[int, ...]) -> ScanContext:
    return ScanContext(
        target=Target.parse(f"http://127.0.0.1:{port}"),
        scope=scope,
        ports=ports,
        timeout=1.0,
    )


def test_open_port_is_reported_once_and_mapped_to_itself(scope, serve_http):
    with serve_http(_Handler) as server:
        port = server.server_address[1]
        ports = (port, 9, 7)
        findings = PortScanModule().run(_ctx(scope, port, ports))

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["open"] == [port]
    assert evidence["probed"] == list(ports)
    assert f"{len(evidence['open'])} open port(s): {port}" in findings[0].title


def test_no_open_port_is_an_informational_finding(scope):
    findings = PortScanModule().run(_ctx(scope, 9, (9, 7)))

    assert len(findings) == 1
    assert "No TCP port answered" in findings[0].title
    assert findings[0].evidence["open"] == []
