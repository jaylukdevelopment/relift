"""Codebase audit: secrets, sinks and dependency advisories.

Everything is hermetic: a tmp tree, and a fake HTTP layer in place of OSV.
The one thing these tests are strict about is redaction — a scanner that writes
a live key into its own run artefact makes the problem worse.
"""

from __future__ import annotations

import json
from pathlib import Path

from relift.cli import main
from relift.models import Severity, Target
from relift.modules import ScanContext
from relift.modules.code import (
    DangerousSinksModule,
    DependenciesModule,
    SecretsModule,
    collect_packages,
    osv_query,
    redact,
    walk_codebase,
)
from relift.scope import offline_scope

AWS_KEY = "AKIA3XJ7QK2M9WPLZ4TB"
STRIPE_KEY = "sk_live_51HxQ2ZrT8mKpN4vB7wLd"
# AWS's own documentation key and a typed-out alphabet run: placeholders, not leaks.
AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"


def _ctx(root: Path, **kwargs) -> ScanContext:
    target = Target(
        raw=f"code://{root}", scheme="code", host="local", port=0, path=str(root)
    )
    return ScanContext(target=target, scope=offline_scope(root), ports=(), **kwargs)


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                f"AWS_KEY = \"{AWS_KEY}\"",
                "",
                "def find(user_id):",
                "    cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
                "    subprocess.run(user_id, shell=True)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(f"STRIPE_KEY={STRIPE_KEY}\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
    return tmp_path


def test_walk_skips_vendored_code_and_binaries(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02")

    scan = walk_codebase(tmp_path)
    names = [name for name, _text in scan.files]

    assert "src/main.py" in names
    assert not any("node_modules" in name for name in names)
    assert "blob.bin" not in names


def test_secrets_are_found_and_redacted(tmp_path):
    root = _tree(tmp_path)
    findings = SecretsModule().run(_ctx(root))

    rules = {item.evidence.get("rule") for item in findings}
    assert {"aws-access-key", "stripe-secret"} <= rules

    aws = [item for item in findings if item.evidence.get("rule") == "aws-access-key"][0]
    assert aws.severity is Severity.HIGH
    assert aws.evidence["file"] == "app.py"
    assert aws.evidence["line"] == 3
    assert AWS_KEY not in json.dumps(aws.to_dict())
    assert aws.evidence["redacted"].startswith("AKIA")
    assert "QK2M9WPLZ4TB" not in aws.evidence["redacted"]

    everything = json.dumps([item.to_dict() for item in findings])
    assert AWS_KEY not in everything
    assert STRIPE_KEY not in everything


def test_placeholder_values_are_not_reported(tmp_path):
    (tmp_path / "config.py").write_text(
        'api_key = "your_api_key_here"\npassword = "xxxxxxxxxxxx"\n', encoding="utf-8"
    )
    findings = SecretsModule().run(_ctx(tmp_path))
    assert not [item for item in findings if item.evidence.get("rule")]


def test_documented_example_and_sequential_values_are_not_reported(tmp_path):
    (tmp_path / "config.py").write_text(
        f'AWS = "{AWS_EXAMPLE_KEY}"\nSTRIPE = "sk_live_abcdefghijklmnop1234"\n',
        encoding="utf-8",
    )
    findings = SecretsModule().run(_ctx(tmp_path))
    assert not [item for item in findings if item.evidence.get("rule")]


def test_markdown_snippet_is_not_a_sink(tmp_path):
    (tmp_path / "README.md").write_text(
        'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n', encoding="utf-8"
    )
    hits = [
        item
        for item in DangerousSinksModule().run(_ctx(tmp_path))
        if item.evidence.get("file")
    ]
    assert [item.evidence["file"] for item in hits] == ["app.py"]


def test_passwd_shaped_data_is_not_a_credential(tmp_path):
    (tmp_path / "auth.py").write_text(
        'PASSWD = "root:x:0:0:root:/root:/bin/bash"\n', encoding="utf-8"
    )
    findings = SecretsModule().run(_ctx(tmp_path))
    assert not [item for item in findings if item.evidence.get("rule")]


def test_regex_exec_is_not_code_execution(tmp_path):
    (tmp_path / "app.js").write_text(
        "const match = /x/.exec(value);\nexec(code);\n", encoding="utf-8"
    )
    findings = DangerousSinksModule().run(_ctx(tmp_path))
    exec_hits = [item for item in findings if item.evidence.get("rule") == "exec"]

    assert len(exec_hits) == 1
    assert exec_hits[0].evidence["line"] == 2


def test_pyproject_parses_requirements_not_tool_settings(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'version = "0.3.0"',
                "dependencies = [",
                '  "requests>=2.0",',
                '  "flask==3.0.3",',
                "]",
                "[tool.pytest.ini_options]",
                'addopts = "-q"',
            ]
        ),
        encoding="utf-8",
    )
    packages, unpinned, _parsed = collect_packages(tmp_path)

    assert [item.name for item in packages] == ["flask"]
    assert any("requests" in entry for entry in unpinned)
    assert not any("-q" in entry or "0.3.0" in entry for entry in unpinned)


def test_dangerous_sinks_name_file_line_and_cwe(tmp_path):
    root = _tree(tmp_path)
    findings = DangerousSinksModule().run(_ctx(root))
    by_rule = {item.evidence.get("rule"): item for item in findings}

    assert by_rule["sql-string-built"].evidence["cwe"] == "CWE-89"
    assert by_rule["sql-string-built"].evidence["file"] == "app.py"
    assert by_rule["sql-string-built"].severity is Severity.HIGH
    assert by_rule["shell-true"].evidence["cwe"] == "CWE-78"
    assert by_rule["django-debug"].evidence["file"] == "settings.py"
    # A sink is a lead, not a proof: confidence says so.
    assert all(item.confidence == "low" for item in by_rule.values())


def test_clean_tree_produces_the_summary_finding(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    findings = SecretsModule().run(_ctx(tmp_path))
    assert len(findings) == 1
    assert "No credential-shaped strings" in findings[0].title


def test_redact_keeps_a_hint_and_no_more():
    assert redact(AWS_KEY) == "AKIA…TB"
    assert redact("short") == "s…"


def test_package_json_pins_and_ranges(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "4.17.4", "express": "^4.18.0"},
                "devDependencies": {"jest": "29.7.0"},
            }
        ),
        encoding="utf-8",
    )
    packages, unpinned, parsed = collect_packages(tmp_path)
    names = {(item.name, item.version) for item in packages}

    assert ("lodash", "4.17.4") in names
    assert ("jest", "29.7.0") in names
    assert any("express" in entry for entry in unpinned)
    assert parsed == ["package.json"]


def test_requirements_parser_only_pins_double_equals(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.0\nflask>=3.0\n# comment\n-r other.txt\n", encoding="utf-8"
    )
    packages, unpinned, _parsed = collect_packages(tmp_path)
    assert [(item.name, item.version) for item in packages] == [("requests", "2.32.0")]
    assert any("flask" in entry for entry in unpinned)


def _fake_urlopen(store, results):
    class FakeResponse:
        def read(self, _limit=-1):
            return json.dumps({"results": results}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def opener(request, timeout=0):
        store["body"] = json.loads(request.data)
        store["timeout"] = timeout
        return FakeResponse()

    return opener


def test_osv_query_batches_every_package(tmp_path, monkeypatch):
    from relift.modules import code as code_module

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.4", "left-pad": "1.3.0"}}),
        encoding="utf-8",
    )
    packages, _unpinned, _parsed = collect_packages(tmp_path)
    store: dict = {}
    monkeypatch.setattr(
        code_module.urllib.request,
        "urlopen",
        _fake_urlopen(store, [{"vulns": [{"id": "GHSA-1"}]}, {}]),
    )

    results, error = osv_query(packages, 5.0)

    assert error == ""
    assert len(store["body"]["queries"]) == 2
    assert store["body"]["queries"][0]["package"]["ecosystem"] == "npm"
    assert results[0][0]["id"] == "GHSA-1"
    assert results[1] == []


def test_dependency_module_reports_cve_and_fixed_version(tmp_path, monkeypatch):
    from relift.modules import code as code_module

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.4"}}), encoding="utf-8"
    )
    advisory = {
        "id": "GHSA-jf85-cpcp-j695",
        "aliases": ["CVE-2019-10744"],
        "summary": "Prototype pollution in lodash",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}
        ],
    }
    monkeypatch.setattr(
        code_module, "osv_query", lambda packages, timeout: ([[advisory]], "")
    )
    monkeypatch.setattr(code_module, "osv_details", lambda ids, timeout: {})

    findings = DependenciesModule().run(_ctx(tmp_path))
    vulnerable = [item for item in findings if "known vulnerability" in item.title]

    assert vulnerable
    finding = vulnerable[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["package"] == "lodash"
    assert finding.evidence["vulns"][0]["fixed"] == "4.17.12"
    assert "CVE-2019-10744" in finding.references


def test_dependency_severity_uses_rank_not_initial_letter(tmp_path, monkeypatch):
    """`medium` sorts after `critical` alphabetically, so rank must decide."""
    from relift.modules import code as code_module

    (tmp_path / "requirements.txt").write_text("foo==1.0\n", encoding="utf-8")
    advisories = [
        {
            "id": "GHSA-low",
            "summary": "Minor issue",
            "database_specific": {"severity": "LOW"},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
        },
        {
            "id": "GHSA-critical",
            "details": "Remote code execution via crafted input.\n\nMore prose.",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
        },
    ]
    monkeypatch.setattr(
        code_module, "osv_query", lambda packages, timeout: ([advisories], "")
    )
    monkeypatch.setattr(code_module, "osv_details", lambda ids, timeout: {})

    findings = DependenciesModule().run(_ctx(tmp_path))
    finding = next(item for item in findings if "known vulnerability" in item.title)
    assert finding.severity is Severity.CRITICAL
    # An advisory without a summary falls back to its details, not "no summary".
    assert "Remote code execution" in finding.detail
    assert "no summary" not in finding.detail


def test_dependency_details_fill_severity_summary_and_fix(tmp_path, monkeypatch):
    """querybatch returns stubs; the detail lookup is what makes the finding real."""
    from relift.modules import code as code_module

    (tmp_path / "requirements.txt").write_text("foo==1.0\n", encoding="utf-8")
    monkeypatch.setattr(
        code_module,
        "osv_query",
        lambda packages, timeout: ([[{"id": "GHSA-aaaa-bbbb-cccc", "modified": "x"}]], ""),
    )
    requested = []

    def fake_details(ids, timeout):
        requested.extend(ids)
        return {
            "GHSA-aaaa-bbbb-cccc": {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2026-0001"],
                "summary": "Command injection in foo",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "foo"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.3"}]}],
                    }
                ],
            }
        }

    monkeypatch.setattr(code_module, "osv_details", fake_details)

    finding = next(
        item
        for item in DependenciesModule().run(_ctx(tmp_path))
        if "known vulnerability" in item.title
    )
    assert requested == ["GHSA-aaaa-bbbb-cccc"]
    assert finding.severity is Severity.HIGH
    assert "Command injection in foo" in finding.detail
    assert "-> 1.0.3" in finding.detail
    assert finding.evidence["vulns"][0]["fixed"] == "1.0.3"


def test_dependency_module_honours_no_osv(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    findings = DependenciesModule().run(_ctx(tmp_path, osv=False))
    assert any("skipped (--no-osv)" in item.title for item in findings)
    assert not any("known vulnerability" in item.title for item in findings)


def test_dependency_module_survives_an_osv_failure(tmp_path, monkeypatch):
    from relift.modules import code as code_module

    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    monkeypatch.setattr(
        code_module, "osv_query", lambda packages, timeout: ([], "OSV query failed: offline")
    )
    findings = DependenciesModule().run(_ctx(tmp_path))
    assert any("did not complete" in item.title for item in findings)


def test_code_command_needs_no_scope_file(tmp_path, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    assert main(["--no-color", "code", str(tmp_path), "--no-osv", "--json"]) == 0
    output = capsys.readouterr().out
    assert "codebase" in output
    assert "code.secrets" in output
    assert "coverage" in output
