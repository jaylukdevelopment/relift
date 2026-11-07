"""Desktop API: loopback only, token-gated, and the same scope gate as the CLI."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from relift import __version__
from relift.api import TOKEN_HEADER, build_server, static_root


@pytest.fixture
def api(write_scope):
    server, token = build_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "server": server,
            "token": token,
            "port": server.server_address[1],
            "host": server.server_address[0],
            "scope": str(write_scope()),
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(api, path, method="GET", body=None, token=True, extra_headers=None):
    url = f"http://127.0.0.1:{api['port']}{path}"
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header(TOKEN_HEADER, api["token"])
    for key, value in (extra_headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


# -- binding and auth --------------------------------------------------------
def test_server_binds_loopback_only(api):
    assert api["host"] == "127.0.0.1"


def test_api_rejects_a_request_without_the_token(api):
    status, body, _headers = request(api, "/api/meta", token=False)
    assert status == 401
    assert b"X-Relift-Token" in body


def test_api_rejects_a_wrong_token(api):
    status, _body, _headers = request(
        api, "/api/meta", token=False, extra_headers={TOKEN_HEADER: "not-the-token"}
    )
    assert status == 401


def test_api_rejects_a_cross_origin_browser_request(api):
    status, _body, _headers = request(
        api, "/api/meta", extra_headers={"Origin": "https://evil.example"}
    )
    assert status == 401


# -- read endpoints ---------------------------------------------------------
def test_meta_reports_the_running_version(api):
    status, body, headers = request(api, "/api/meta")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    payload = json.loads(body)
    assert payload["version"] == __version__
    assert payload["counts"]["total"] > 0
    assert payload["categories"]
    assert payload["profiles"]


def test_catalog_endpoint_matches_the_catalogue(api):
    status, body, _headers = request(api, "/api/catalog")
    assert status == 200
    techniques = json.loads(body)["techniques"]
    assert techniques
    assert all("families" in item for item in techniques)
    assert any(item["id"] == "db.fingerprint" for item in techniques)


def test_runs_endpoint_is_empty_before_any_scan(api):
    status, body, _headers = request(api, "/api/runs")
    assert status == 200
    assert json.loads(body)["runs"] == []


# -- validation -------------------------------------------------------------
def test_scope_endpoint_requires_a_path(api):
    status, body, _headers = request(api, "/api/scope", method="POST", body={})
    assert status == 400
    assert b"scope file path is required" in body


def test_scope_endpoint_refuses_a_missing_file(api, tmp_path):
    status, body, _headers = request(
        api, "/api/scope", method="POST", body={"path": str(tmp_path / "absent.json")}
    )
    # A missing scope is a scope refusal, so it leaves through the ScopeError path.
    assert status == 403
    assert b"refused" in body


def test_scope_endpoint_loads_a_valid_file(api):
    status, body, _headers = request(
        api, "/api/scope", method="POST", body={"path": api["scope"]}
    )
    assert status == 200
    scope = json.loads(body)
    assert scope["engagement"] == "relift-tests"
    assert scope["allowed_hosts"] == ["127.0.0.1"]


def test_plan_endpoint_lists_only_matching_families(api):
    status, body, _headers = request(
        api,
        "/api/plan",
        method="POST",
        body={
            "target": "http://127.0.0.1:9/",
            "scope": api["scope"],
            "profile": "safe",
        },
    )
    assert status == 200
    plan = json.loads(body)
    assert plan["techniques"]
    for technique in plan["techniques"]:
        assert "http" in technique["families"]
    assert "web.headers" in [item["id"] for item in plan["techniques"]]
    assert "db.fingerprint" not in [item["id"] for item in plan["techniques"]]


def test_scan_refuses_a_target_outside_the_scope(api):
    status, body, _headers = request(
        api,
        "/api/scan",
        method="POST",
        body={"target": "http://192.0.2.1/", "scope": api["scope"]},
    )
    assert status == 403
    assert b"refused" in body
    assert b"not in allowed_hosts" in body


def test_scan_requires_a_scope(api):
    status, body, _headers = request(
        api, "/api/scan", method="POST", body={"target": "http://127.0.0.1:9/"}
    )
    assert status == 400
    assert b"scope file is required" in body


def test_unknown_api_route_is_404(api):
    status, body, _headers = request(api, "/api/nope")
    assert status == 404
    assert b"not found" in body


# -- static UI --------------------------------------------------------------
def _assets_present():
    root = static_root()
    return all((root / name).is_file() for name in ("app.html", "app.js", "app.css"))


needs_ui = pytest.mark.skipif(
    not _assets_present(), reason="desktop UI assets are delivered by their own slice"
)


@needs_ui
def test_root_serves_the_ui_with_the_bootstrap_token(api):
    status, body, headers = request(api, "/")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert b"RELIFT_BOOT" in body
    assert api["token"].encode() in body


@needs_ui
def test_js_asset_is_served_with_a_javascript_content_type(api):
    status, body, headers = request(api, "/app.js")
    assert status == 200
    assert "javascript" in headers.get("Content-Type", "")
    assert body


@needs_ui
def test_unknown_static_path_is_not_served(api):
    status, _body, _headers = request(api, "/../relift/api.py")
    assert status in (400, 404)
