"""Shared fixtures for the Relift test suite.

Everything here is hermetic: no internet, no docker, no service already running
on the machine. Servers are started on port 0 (the OS picks one) and shut down
again; the scope and run fixtures all live under pytest's ``tmp_path`` so a test
run cannot touch a real engagement or the operator's home directory.
"""

from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

# The package is installed editable, but running straight from a checkout must
# work too — that is what CI does on a fresh clone before `pip install -e .`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def make_scope_doc(**overrides):
    """A valid scope document. Override any field to build a refusal case."""
    document = {
        "engagement": "relift-tests",
        "authorized_by": "Test Suite",
        "organization": "Pixelcity",
        "acknowledge_authorization": True,
        "expires": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(
            timespec="seconds"
        ),
        "allowed_hosts": ["127.0.0.1"],
        "denied_hosts": [],
        "max_risk": "safe",
        "allow_intrusive": False,
        "allow_wide_ranges": False,
        # High enough that a module making six probes is not throttled into a
        # slow test; the production default is 5.
        "rate_limit_rps": 200,
        "ports": [22, 80, 443, 5432, 3306, 6379, 27017],
        "notes": "test scope",
    }
    document.update(overrides)
    return document


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Keep run artefacts, the audit log and AI detection inside tmp_path."""
    monkeypatch.setenv("RELIFT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RELIFT_AUDIT_FILE", str(tmp_path / "audit.jsonl"))
    # Deterministic analyst: never probe for a local model daemon.
    monkeypatch.setenv("RELIFT_AI_PROVIDER", "offline")
    yield


@pytest.fixture
def scope_doc():
    return make_scope_doc


@pytest.fixture
def write_scope(tmp_path):
    """Write a scope file and return its path."""

    def _write(**overrides):
        path = tmp_path / f"scope-{len(list(tmp_path.glob('scope-*.json')))}.json"
        path.write_text(json.dumps(make_scope_doc(**overrides)), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def scope(write_scope):
    from relift.scope import load_scope

    return load_scope(write_scope())


@pytest.fixture
def scan_ctx(scope):
    """Build a ScanContext for a target with the loaded test scope."""

    def _build(target, **kwargs):
        from relift.models import Target
        from relift.modules import ScanContext

        options = {"timeout": 3.0}
        options.update(kwargs)
        return ScanContext(
            target=Target.parse(target), scope=scope, ports=(80, 443), **options
        )

    return _build


@pytest.fixture
def serve_http():
    """Start a ThreadingHTTPServer on 127.0.0.1:0 and yield it."""

    @contextmanager
    def _serve(handler_cls):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return _serve
