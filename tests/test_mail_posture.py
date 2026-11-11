"""Mail posture: the DNS packet layer and the SPF/DMARC grading.

The wire format is tested with hand-built packets — no resolver, no network —
and the grading is tested with a fake resolver, so both halves run anywhere.
"""

from __future__ import annotations

import struct

import pytest

from relift import chains as chain_engine
from relift.models import Severity
from relift.modules import dnsproto, recon
from relift.modules.recon import MailPostureModule, _spf_lookup_count, _spf_qualifier


def _response(records, qname="example.test", qtype=16, qid=0x1234) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, len(records), 0, 0)
    question = dnsproto.encode_name(qname) + struct.pack("!HH", qtype, 1)
    body = b""
    for rtype, rdata in records:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + body


def _txt(*chunks: str) -> bytes:
    return b"".join(bytes([len(chunk.encode())]) + chunk.encode() for chunk in chunks)


def test_encode_name_is_wire_format():
    assert dnsproto.encode_name("example.test") == b"\x07example\x04test\x00"
    assert dnsproto.encode_name("example.test.") == b"\x07example\x04test\x00"
    with pytest.raises(ValueError):
        dnsproto.encode_name("")


def test_parse_txt_response():
    packet = _response([(dnsproto.TYPE_TXT, _txt("v=spf1 -all"))])
    result = dnsproto.parse_response(packet, 0x1234)
    assert result.error == ""
    assert dnsproto.txt_values(result) == ["v=spf1 -all"]


def test_long_txt_record_is_reassembled_from_chunks():
    packet = _response(
        [(dnsproto.TYPE_TXT, _txt("v=spf1 " + "include:a.example.test " * 8, "-all"))]
    )
    values = dnsproto.txt_values(dnsproto.parse_response(packet, 0x1234))
    assert len(values) == 1
    assert values[0].endswith("-all")


def test_parse_mx_response_follows_compression_pointers():
    rdata = struct.pack("!H", 10) + b"\xc0\x0c"  # exchange points at the qname
    packet = _response([(dnsproto.TYPE_MX, rdata)], qtype=dnsproto.TYPE_MX)
    result = dnsproto.parse_response(packet, 0x1234)
    assert result.mx == [(10, "example.test")]


def test_parse_response_rejects_a_mismatched_id_and_short_packets():
    packet = _response([(dnsproto.TYPE_TXT, _txt("v=spf1 -all"))])
    assert "id does not match" in dnsproto.parse_response(packet, 0xBEEF).error
    assert dnsproto.parse_response(b"\x00\x01").error


def test_parse_response_reports_nxdomain_without_raising():
    header = struct.pack("!HHHHHH", 0x1234, 0x8183, 0, 0, 0, 0)  # rcode 3
    result = dnsproto.parse_response(header, 0x1234)
    assert result.rcode == 3
    assert result.negative and result.data == []


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=spf1 -all", "-"),
        ("v=spf1 include:x.example ~all", "~"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        ("v=spf1 all", "+"),
        ("v=spf1 ip4:192.0.2.0/24", "missing"),
    ],
)
def test_spf_qualifier_parsing(record, expected):
    assert _spf_qualifier(record) == expected


def test_spf_lookup_count_only_counts_lookup_mechanisms():
    record = "v=spf1 include:a include:b a:host mx redirect=c.example ip4:10.0.0.0/8 -all"
    assert _spf_lookup_count(record) == 5


def _install_dns(monkeypatch, txt=None, mx=None):
    txt_map = txt or {}
    mx_map = mx or {}

    def lookup_txt(name, timeout=4.0):
        return list(txt_map.get(name, [])), ""

    def lookup_mx(name, timeout=4.0):
        return [(pref, host) for pref, host in mx_map.get(name, [])], ""

    monkeypatch.setattr(recon.dnsproto, "lookup_txt", lookup_txt)
    monkeypatch.setattr(recon.dnsproto, "lookup_mx", lookup_mx)


def test_a_strong_posture_produces_no_findings_above_info(scan_ctx, monkeypatch):
    _install_dns(
        monkeypatch,
        txt={
            "example.test": ["v=spf1 include:_spf.example.test -all"],
            "_dmarc.example.test": [
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.test"
            ],
        },
        mx={"example.test": [(10, "mail.example.test")]},
    )
    findings = MailPostureModule().run(scan_ctx("https://example.test"))

    assert findings
    assert all(item.severity is Severity.INFO for item in findings)
    summary = findings[0]
    assert summary.evidence["spf_ok"] is True
    assert summary.evidence["dmarc_ok"] is True


def test_missing_dmarc_and_soft_spf_are_reported_and_chain(scan_ctx, monkeypatch):
    _install_dns(
        monkeypatch,
        txt={"example.test": ["v=spf1 include:_spf.example.test ?all"]},
        mx={"example.test": [(10, "mail.example.test")]},
    )
    findings = MailPostureModule().run(scan_ctx("https://example.test"))
    titles = " | ".join(item.title for item in findings)

    assert "No DMARC record" in titles
    assert "SPF ends in ?all" in titles
    assert not any("No SPF record" in item.title for item in findings)

    chains = chain_engine.analyse([item.to_dict() for item in findings])
    thread = [chain for chain in chains if chain.id == "thread.mail-spoofing"]
    assert thread and thread[0].severity is Severity.HIGH


def test_a_domain_without_mail_gets_a_quieter_thread(scan_ctx, monkeypatch):
    _install_dns(monkeypatch, txt={}, mx={})
    findings = MailPostureModule().run(scan_ctx("https://example.test"))

    assert any("does not accept mail" in item.title for item in findings)
    chains = chain_engine.analyse([item.to_dict() for item in findings])
    thread = [chain for chain in chains if chain.id == "thread.mail-spoofing"][0]
    assert thread.severity is Severity.LOW


def test_www_target_reads_the_parent_domain_policy(scan_ctx, monkeypatch):
    _install_dns(
        monkeypatch,
        txt={"example.test": ["v=spf1 -all"], "_dmarc.example.test": ["v=DMARC1; p=reject"]},
        mx={"example.test": [(10, "mail.example.test")]},
    )
    findings = MailPostureModule().run(scan_ctx("https://www.example.test"))

    summary = findings[0]
    assert summary.evidence["domain"] == "example.test"
    assert summary.evidence["queried_host"] == "www.example.test"


def test_spf_over_the_lookup_limit_is_flagged(scan_ctx, monkeypatch):
    includes = " ".join(f"include:i{index}.example.test" for index in range(11))
    _install_dns(
        monkeypatch,
        txt={"example.test": [f"v=spf1 {includes} -all"], "example.test2": []},
        mx={"example.test": [(10, "mail.example.test")]},
    )
    findings = MailPostureModule().run(scan_ctx("https://example.test"))

    assert any("10-lookup" in item.title for item in findings)


def test_an_ip_target_is_reported_as_not_applicable(scan_ctx):
    findings = MailPostureModule().run(scan_ctx("https://192.0.2.10"))
    assert len(findings) == 1
    assert "not applicable" in findings[0].title
