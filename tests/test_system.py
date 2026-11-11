"""Local host audit. Linux-only, read-only, and it must never raise."""

from __future__ import annotations

import platform

import pytest

from relift.modules.system import HostAuditModule

pytestmark = pytest.mark.skipif(
    platform.system() != "Linux", reason="the host audit targets Linux"
)

EVIDENCE_CONTRACT = (
    "os",
    "kernel",
    "arch",
    "suid",
    "sgid",
    "capabilities",
    "sudo_rules",
    "world_writable_paths",
    "docker_socket",
    "docker_socket_detail",
    "listening",
    "kernel_cves",
)

LIST_KEYS = (
    "suid",
    "sgid",
    "capabilities",
    "sudo_rules",
    "world_writable_paths",
    "listening",
    "kernel_cves",
)


def _summary(findings):
    for item in findings:
        if "kernel" in item.evidence:
            return item
    return None


def test_audit_returns_at_least_the_summary(scan_ctx):
    findings = HostAuditModule().run(scan_ctx("local://"))
    assert findings
    summary = _summary(findings)
    assert summary is not None, "the summary finding carries the evidence contract"
    assert summary.attack_id == "system.host_audit"


def test_summary_evidence_has_the_whole_contract(scan_ctx):
    summary = _summary(HostAuditModule().run(scan_ctx("local://")))
    assert summary is not None
    missing = [key for key in EVIDENCE_CONTRACT if key not in summary.evidence]
    assert missing == []
    for key in LIST_KEYS:
        value = summary.evidence[key]
        assert isinstance(value, list), key
        assert all(isinstance(entry, str) for entry in value), key
    assert isinstance(summary.evidence["docker_socket"], bool)
    assert isinstance(summary.evidence["os"], str)
    assert isinstance(summary.evidence["kernel"], str)
    assert isinstance(summary.evidence["arch"], str)


def test_every_finding_is_tagged_and_severity_is_known(scan_ctx):
    findings = HostAuditModule().run(scan_ctx("local://"))
    for item in findings:
        assert item.attack_id == "system.host_audit"
        assert item.title
        assert item.severity is not None


def test_audit_is_repeatable_without_raising(scan_ctx):
    ctx = scan_ctx("local://")
    first = HostAuditModule().run(ctx)
    second = HostAuditModule().run(ctx)
    assert len(_summary(first).evidence["kernel"]) > 0
    assert _summary(second).evidence["kernel"] == _summary(first).evidence["kernel"]


def test_kernel_cve_entries_are_advisory_strings(scan_ctx):
    summary = _summary(HostAuditModule().run(scan_ctx("local://")))
    for entry in summary.evidence["kernel_cves"]:
        assert entry.startswith("CVE-")
        assert "fixed in" in entry


def test_merged_usr_binary_is_counted_once(tmp_path, monkeypatch):
    """On a usrmerge host /bin/x and /usr/bin/x are the same file."""
    import os

    from relift.modules import system

    real = tmp_path / "usr-bin"
    real.mkdir()
    binary = real / "helper"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o4755)
    link = tmp_path / "bin"
    link.symlink_to(real)

    monkeypatch.setattr(system, "SCAN_DIRS", (str(real), str(link)))
    suid, sgid, _caps = system._suid_surface()

    assert suid == [str(binary)]
    assert sgid == []


def test_a_passworded_sudo_rule_is_not_called_passwordless(scan_ctx, monkeypatch):
    from relift.modules import system

    monkeypatch.setattr(system, "_sudo_rules", lambda: ["%sudo\tALL=(ALL:ALL) ALL"])
    titles = [item.title for item in HostAuditModule().run(scan_ctx("local://"))]

    assert any("unrestricted rights" in title for title in titles)
    assert not any("without a password" in title for title in titles)


def test_a_nopasswd_rule_is_reported_as_such(scan_ctx, monkeypatch):
    from relift.modules import system

    monkeypatch.setattr(
        system,
        "_sudo_rules",
        lambda: ["root\tALL=(ALL:ALL) ALL", "deploy\tALL=(ALL) NOPASSWD:ALL"],
    )
    findings = HostAuditModule().run(scan_ctx("local://"))
    passwordless = [item for item in findings if "without a password" in item.title]

    assert passwordless, [item.title for item in findings]
    assert passwordless[0].evidence["rules"] == ["deploy\tALL=(ALL) NOPASSWD:ALL"]
    assert passwordless[0].severity is not None
