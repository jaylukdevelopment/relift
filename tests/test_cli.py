"""CLI surface, driven through main() so exit codes are part of the assertion."""

from __future__ import annotations

import json

import pytest

from relift import __version__, catalog
from relift.cli import main


def test_list_json_matches_the_catalogue(capsys):
    assert main(["list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == catalog.counts()["total"]
    assert sum(1 for row in rows if row["implemented"]) == catalog.counts()["implemented"]


def test_list_category_filter(capsys):
    assert main(["list", "--category", "db", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows
    assert {row["category"] for row in rows} == {"db"}


def test_list_implemented_only_hides_design_only_entries(capsys):
    assert main(["list", "--implemented-only", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert all(row["implemented"] for row in rows)
    assert all(row["status"] != "design-only" for row in rows)


def test_unknown_category_is_a_usage_error(capsys):
    assert main(["list", "--category", "nope"]) == 3
    assert "unknown category" in capsys.readouterr().err


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_init_scope_writes_a_loadable_file(tmp_path, capsys):
    path = tmp_path / "scope.json"
    code = main(
        [
            "--no-color",
            "init-scope",
            "--engagement",
            "unit",
            "--host",
            "127.0.0.1",
            "--out",
            str(path),
        ]
    )
    assert code == 0
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["engagement"] == "unit"
    assert document["acknowledge_authorization"] is True
    assert "wrote scope" in capsys.readouterr().out


def test_init_scope_refuses_to_overwrite_without_force(tmp_path, capsys):
    path = tmp_path / "scope.json"
    assert main(["init-scope", "--engagement", "unit", "--out", str(path)]) == 0
    assert main(["init-scope", "--engagement", "unit", "--out", str(path)]) == 3
    assert "already exists" in capsys.readouterr().err


def test_dry_run_prints_a_plan_and_sends_nothing(write_scope, capsys):
    scope = write_scope()
    code = main(
        ["--no-color", "scan", "--target", "http://127.0.0.1:9", "--scope", str(scope), "--no-ai"]
    )
    assert code == 0
    output = capsys.readouterr().out
    assert "dry run" in output
    assert "--execute" in output
    assert "db.fingerprint" not in output  # not an http-family technique


def test_scan_out_of_scope_target_exits_two(write_scope, capsys):
    scope = write_scope()
    code = main(
        ["--no-color", "scan", "--target", "http://192.0.2.1", "--scope", str(scope), "--no-ai"]
    )
    assert code == 2
    assert "refused" in capsys.readouterr().err


def test_scan_without_a_scope_file_exits_two(tmp_path, capsys):
    code = main(
        [
            "--no-color",
            "scan",
            "--target",
            "http://127.0.0.1:9",
            "--scope",
            str(tmp_path / "nope.json"),
        ]
    )
    assert code == 2
    assert "nothing was sent" in capsys.readouterr().err


def test_report_with_no_runs_exits_three(capsys):
    assert main(["report"]) == 3


def test_chains_command_renders_a_stored_run(tmp_path, capsys):
    run = {
        "tool": "relift",
        "version": __version__,
        "run_id": "unit-run",
        "target": {"raw": "redis://127.0.0.1:6379/", "scheme": "redis"},
        "profile": "safe",
        "provider": "offline",
        "engagement": "unit",
        "scope_sha256": "deadbeef",
        "authorized_by": "tests",
        "started": "2026-01-01T00:00:00+00:00",
        "finished": "2026-01-01T00:00:01+00:00",
        "executions": [],
        "findings": [
            {
                "attack_id": "db.security_config",
                "target": "redis://127.0.0.1:6379/",
                "title": "Redis answers commands without authentication",
                "severity": "critical",
                "detail": "",
                "evidence": {"engine": "redis", "auth_required": False, "port": 6379},
                "references": [],
                "confidence": "high",
            }
        ],
        "chains": [],
        "narrative": "",
        "error": "",
    }
    path = tmp_path / "run.json"
    path.write_text(json.dumps(run), encoding="utf-8")

    assert main(["--no-color", "chains", "--run", str(path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "unit-run"
    assert [chain["id"] for chain in payload["chains"]] == ["thread.datastore-no-auth"]


def test_no_subcommand_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_desktop_command_is_registered():
    from relift.cli import _build_parser

    args = _build_parser().parse_args(["desktop", "--no-window", "--port", "0"])
    assert args.command == "desktop"
    assert args.no_window is True
