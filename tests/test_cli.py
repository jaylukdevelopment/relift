"""CLI surface, driven through main() so exit codes are part of the assertion."""

from __future__ import annotations

import json

import pytest

from relift import __version__, catalog
from relift.cli import _parse_depth, main


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


def test_run_reference_latest_resolves_to_the_newest_run(tmp_path, monkeypatch, capsys):
    run_dir = tmp_path / "runs" / "20260101-000000-aaaa"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_id": "20260101-000000-aaaa",
                "target": {"raw": "https://example.test/"},
                "findings": [],
                "chains": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RELIFT_RUNS_DIR", str(tmp_path / "runs"))
    assert main(["--no-color", "chains", "--run", "latest", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "20260101-000000-aaaa"


def test_attack_depth_accepts_numbers_and_names():
    assert _parse_depth("1")[1] == "passive"
    assert _parse_depth("passive")[1] == "passive"
    assert _parse_depth("4")[2].value == "intrusive"
    assert _parse_depth("full")[3] is True  # intrusive
    assert _parse_depth("full")[4] is True  # external tools
    with pytest.raises(ValueError):
        _parse_depth("9")


def test_attack_authors_a_scope_and_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RELIFT_SCOPE_DIR", str(tmp_path / "scopes"))
    code = main(
        ["--no-color", "attack", "--target", "http://127.0.0.1:9", "--depth", "1", "--no-ai"]
    )
    assert code == 0
    output = capsys.readouterr().out
    assert "depth    1/5" in output
    scopes = list((tmp_path / "scopes").glob("*.json"))
    assert len(scopes) == 1
    document = json.loads(scopes[0].read_text(encoding="utf-8"))
    assert document["acknowledge_authorization"] is True
    assert "127.0.0.1" in document["allowed_hosts"]
    assert document["allowed_hosts"].count("127.0.0.1") == 1
    assert document["max_risk"] == "passive"
    assert document["allow_intrusive"] is False
    # The target's own port must be swept, or `attack host:8099` never sees 8099.
    assert 9 in document["ports"]


def test_attack_intrusive_depth_authorises_the_intrusive_ceiling(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RELIFT_SCOPE_DIR", str(tmp_path / "scopes"))
    code = main(
        ["--no-color", "attack", "--target", "http://127.0.0.1:9", "--depth", "4", "--no-ai"]
    )
    assert code == 0
    assert "intrusive tier" in capsys.readouterr().out
    document = json.loads(next((tmp_path / "scopes").glob("*.json")).read_text(encoding="utf-8"))
    assert document["max_risk"] == "intrusive"
    assert document["allow_intrusive"] is True


def test_no_subcommand_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_desktop_command_is_registered():
    from relift.cli import _build_parser

    args = _build_parser().parse_args(["desktop", "--no-window", "--port", "0"])
    assert args.command == "desktop"
    assert args.no_window is True


def test_attack_accepts_a_positional_target_and_a_dry_run(write_scope, capsys):
    scope = write_scope()
    code = main(
        ["--no-color", "attack", "127.0.0.1", "--scope", str(scope), "--dry-run", "--no-ai"]
    )
    assert code == 0
    output = capsys.readouterr().out
    assert "dry run" in output
    assert "127.0.0.1" in output


def test_attack_without_a_target_is_a_usage_error(capsys):
    assert main(["--no-color", "attack", "--dry-run"]) == 3
    assert "target is required" in capsys.readouterr().err


def test_list_search_filters_by_text_and_reports_no_match(capsys):
    assert main(["--no-color", "list", "--search", "cors", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert "web.cors_policy" in [row["id"] for row in rows]
    # Every hit has to actually mention the needle somewhere.
    assert all(
        "cors" in (row["id"] + row["name"] + row["summary"]).lower() for row in rows
    )

    assert main(["--no-color", "list", "--search", "no-such-technique"]) == 3
    assert "no technique matches" in capsys.readouterr().err


def test_explain_describes_a_technique_and_its_module(capsys):
    assert main(["--no-color", "explain", "web.dir_bruteforce", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "web.dir_bruteforce"
    assert payload["module"] == "DirectoryProbeModule"
    assert payload["risk"] == "intrusive"
    # An intrusive technique is only planned under the lab profile.
    assert payload["profiles"] == ["lab"]


def test_explain_refuses_an_unknown_id(capsys):
    assert main(["--no-color", "explain", "web.nope"]) == 3
    assert "unknown technique" in capsys.readouterr().err


def test_doctor_reports_paths_and_tools(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RELIFT_SCOPE_DIR", str(tmp_path / "scopes"))
    assert main(["--no-color", "doctor", "127.0.0.1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    checks = {row["check"]: row for row in payload["checks"]}
    assert checks["python"]["level"] == "ok"
    assert checks["target"]["level"] == "ok"
    assert "external tools" in checks
    assert payload["failures"] == 0


def test_doctor_accepts_a_nested_scope_directory_that_does_not_exist_yet(
    tmp_path, monkeypatch, capsys
):
    # /root/.relift/scopes on a fresh host: two levels that mkdir -p creates.
    monkeypatch.setenv("RELIFT_SCOPE_DIR", str(tmp_path / "a" / "b" / "scopes"))
    assert main(["--no-color", "doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    scope = {row["check"]: row for row in payload["checks"]}["scope dir"]
    assert scope["level"] == "warn"
    assert "will be created" in scope["detail"]


def test_doctor_text_names_the_scope_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RELIFT_SCOPE_DIR", str(tmp_path / "scopes"))
    assert main(["--no-color", "doctor"]) == 0
    assert "scope dir" in capsys.readouterr().out
