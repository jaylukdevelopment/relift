"""Coverage: the report has to say what it did not test, not just what it found."""

from __future__ import annotations

import json

from relift.report import coverage, render_json, render_markdown, render_run_text


def _payload(**overrides):
    payload = {
        "run_id": "unit-run",
        "target": {
            "raw": "https://example.test/",
            "families": ["http"],
            "kind": "http",
        },
        "profile": "safe",
        "provider": "offline",
        "engagement": "unit",
        "scope_sha256": "deadbeef",
        "started": "2026-01-01T00:00:00+00:00",
        "executions": [
            {"attack_id": "web.headers", "status": "ok", "duration_ms": 10, "finding_count": 2}
        ],
        "planned": ["web.headers", "web.cors_policy"],
        "findings": [],
        "chains": [],
        "narrative": "",
    }
    payload.update(overrides)
    return payload


def test_coverage_separates_tested_from_untested():
    rows = {row["attack_id"]: row for row in coverage(_payload())}

    assert rows["web.headers"]["status"] == "tested"
    assert rows["web.headers"]["detail"] == "2 finding(s)"
    assert rows["db.fingerprint"]["status"] == "not tested"
    assert rows["db.fingerprint"]["detail"] == "not applicable to this target family"
    assert rows["system.host_audit"]["detail"] == "not applicable to this target family"
    assert rows["web.dir_bruteforce"]["detail"] == "above the safe ceiling"
    assert rows["web.template_scan"]["detail"] == (
        "external tools are not enabled in this profile"
    )


def test_planned_but_missing_execution_is_called_out():
    payload = _payload(planned=["web.headers", "web.cors_policy", "web.methods"])
    rows = {row["attack_id"]: row for row in coverage(payload)}
    assert rows["web.methods"]["detail"] == "planned but not executed"


def test_old_artefacts_without_planned_still_render():
    payload = _payload()
    payload.pop("planned")
    rows = coverage(payload)
    assert any(row["attack_id"] == "web.headers" and row["status"] == "tested" for row in rows)


def test_text_report_has_a_coverage_section():
    output = render_run_text(_payload())
    assert "COVERAGE" in output
    assert "not tested" in output
    # A skipped technique must be visible with its reason, not silently omitted.
    assert "db.fingerprint" in output
    assert "not applicable to this target family" in output


def test_markdown_report_lists_every_technique_in_coverage():
    output = render_markdown(_payload())
    assert "## Coverage" in output
    assert "| `db.fingerprint` | not tested |" in output


def test_json_report_carries_the_coverage_array():
    payload = json.loads(render_json(_payload()))
    assert isinstance(payload["coverage"], list)
    assert any(row["attack_id"] == "db.fingerprint" for row in payload["coverage"])
