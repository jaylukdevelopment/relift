"""Scope gate: the one control that stands between a tool and an incident."""

from __future__ import annotations

import json

import pytest

from relift.models import Risk
from relift.scope import (
    ScopeError,
    build_scope_document,
    compile_pattern,
    load_scope,
)


def _write(tmp_path, document, name="scope.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# -- pattern matching --------------------------------------------------------
def test_exact_host_pattern_matches_only_itself():
    pattern = compile_pattern("example.com")
    assert pattern.matches("example.com")
    assert pattern.matches("EXAMPLE.COM")
    assert not pattern.matches("api.example.com")
    assert not pattern.matches("example.com.evil.test")


def test_wildcard_matches_subdomain_but_not_apex():
    pattern = compile_pattern("*.lab.example.com")
    assert pattern.matches("a.lab.example.com")
    assert pattern.matches("deep.a.lab.example.com")
    assert not pattern.matches("lab.example.com")
    assert not pattern.matches("a.lab.example.com.evil.test")


def test_cidr_matches_member_addresses_only():
    pattern = compile_pattern("10.10.10.0/24")
    assert pattern.matches("10.10.10.5")
    assert not pattern.matches("10.10.11.5")


def test_ipv6_literal_is_normalised():
    pattern = compile_pattern("::1")
    assert pattern.matches("0:0:0:0:0:0:0:1")


# -- authorisation -----------------------------------------------------------
def test_allows_literal_address_inside_cidr(write_scope):
    scope = load_scope(write_scope(allowed_hosts=["10.10.10.0/24"]))
    assert scope.authorize("10.10.10.5") == "10.10.10.0/24"


def test_refuses_address_outside_every_pattern(write_scope):
    scope = load_scope(write_scope(allowed_hosts=["10.10.10.0/24"]))
    with pytest.raises(ScopeError, match="not in allowed_hosts"):
        scope.authorize("10.10.11.5")


def test_deny_rule_wins_over_allow_rule(write_scope):
    scope = load_scope(
        write_scope(allowed_hosts=["10.10.10.0/24"], denied_hosts=["10.10.10.7"])
    )
    with pytest.raises(ScopeError, match="explicitly denied"):
        scope.authorize("10.10.10.7")
    # A neighbouring address is still allowed: the deny is not a block on the net.
    assert scope.authorize("10.10.10.8")


def test_hostname_resolving_into_a_denied_address_is_refused(write_scope):
    """A name is only as trustworthy as what it resolves to right now."""
    scope = load_scope(
        write_scope(allowed_hosts=["localhost"], denied_hosts=["127.0.0.1", "::1"])
    )
    with pytest.raises(ScopeError):
        scope.authorize("localhost")


def test_empty_host_is_refused(write_scope):
    scope = load_scope(write_scope())
    with pytest.raises(ScopeError, match="no target host"):
        scope.authorize("  ")


# -- file validation --------------------------------------------------------
def test_expired_scope_is_refused(write_scope):
    path = write_scope(expires="2020-01-01T00:00:00+00:00")
    with pytest.raises(ScopeError, match="expired"):
        load_scope(path)


def test_missing_authorisation_acknowledgement_is_refused(write_scope):
    path = write_scope(acknowledge_authorization=False)
    with pytest.raises(ScopeError, match="acknowledge_authorization"):
        load_scope(path)


def test_empty_allowed_hosts_is_refused(write_scope):
    path = write_scope(allowed_hosts=[])
    with pytest.raises(ScopeError, match="allows nothing"):
        load_scope(path)


def test_missing_engagement_is_refused(write_scope):
    path = write_scope(engagement="")
    with pytest.raises(ScopeError, match="engagement"):
        load_scope(path)


def test_unreadable_scope_file_is_refused(tmp_path):
    with pytest.raises(ScopeError, match="cannot read"):
        load_scope(tmp_path / "does-not-exist.json")


def test_non_json_scope_file_is_refused(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScopeError, match="not valid JSON"):
        load_scope(path)


@pytest.mark.parametrize("entry", ["not-a-cidr/33", ""])
def test_malformed_scope_entry_is_refused(write_scope, entry):
    path = write_scope(allowed_hosts=[entry])
    with pytest.raises(ScopeError):
        load_scope(path)


# -- range and tier guards ---------------------------------------------------
def test_wide_cidr_is_refused_by_default(write_scope):
    path = write_scope(allowed_hosts=["10.0.0.0/8"])
    with pytest.raises(ScopeError, match="allow_wide_ranges"):
        load_scope(path)


def test_wide_cidr_is_accepted_with_the_explicit_switch(write_scope):
    scope = load_scope(
        write_scope(allowed_hosts=["10.0.0.0/8"], allow_wide_ranges=True)
    )
    assert scope.allow_wide_ranges is True


def test_modest_cidr_needs_no_switch(write_scope):
    scope = load_scope(write_scope(allowed_hosts=["10.10.10.0/24"]))
    assert scope.allowed_raw == ["10.10.10.0/24"]


def test_intrusive_without_matching_risk_ceiling_is_refused(write_scope):
    path = write_scope(allow_intrusive=True, max_risk="safe")
    with pytest.raises(ScopeError, match="max_risk"):
        load_scope(path)


def test_intrusive_scope_with_intrusive_ceiling_loads(write_scope):
    scope = load_scope(write_scope(allow_intrusive=True, max_risk="intrusive"))
    assert scope.allow_intrusive is True
    assert scope.max_risk is Risk.INTRUSIVE
    assert scope.risk_ceiling(Risk.INTRUSIVE) is Risk.INTRUSIVE


def test_scope_ceiling_is_the_stricter_of_two(write_scope):
    scope = load_scope(write_scope(max_risk="passive"))
    assert scope.risk_ceiling(Risk.INTRUSIVE) is Risk.PASSIVE


def test_intrusive_cannot_be_enabled_without_the_scope_switch(write_scope):
    scope = load_scope(write_scope(max_risk="safe"))
    # The profile asks for intrusive, the scope refuses it.
    assert scope.risk_ceiling(Risk.INTRUSIVE) is Risk.SAFE


def test_destructive_ceiling_is_refused(write_scope):
    path = write_scope(max_risk="destructive")
    with pytest.raises(ScopeError, match="destructive"):
        load_scope(path)


@pytest.mark.parametrize("rps", [0, -1, 201])
def test_rate_limit_bounds(write_scope, rps):
    path = write_scope(rate_limit_rps=rps)
    with pytest.raises(ScopeError, match="rate_limit_rps"):
        load_scope(path)


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_port_bounds(write_scope, port):
    path = write_scope(ports=[port])
    with pytest.raises(ScopeError, match="port"):
        load_scope(path)


# -- identity ---------------------------------------------------------------
def test_digest_is_stable_for_identical_bytes(write_scope):
    path = write_scope()
    assert load_scope(path).digest == load_scope(path).digest


def test_digest_changes_when_the_file_changes(write_scope):
    path = write_scope()
    before = load_scope(path).digest
    document = json.loads(path.read_text(encoding="utf-8"))
    document["notes"] = "edited after the first load"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert load_scope(path).digest != before


def test_expiry_countdown_is_reported(write_scope):
    scope = load_scope(write_scope())
    assert 28 <= scope.expires_in_days <= 30


# -- document factory -------------------------------------------------------
def test_build_scope_document_defaults_to_loopback():
    document = build_scope_document(engagement="unit")
    assert document["acknowledge_authorization"] is True
    assert "127.0.0.1" in document["allowed_hosts"]
    assert document["max_risk"] == "safe"
    assert document["allow_intrusive"] is False
    assert document["allow_wide_ranges"] is False


def test_build_scope_document_expands_localhost_to_both_families():
    document = build_scope_document(engagement="unit", hosts=["localhost"])
    assert "127.0.0.1" in document["allowed_hosts"]
    assert "::1" in document["allowed_hosts"]


def test_build_scope_document_is_loadable(tmp_path):
    document = build_scope_document(
        engagement="round-trip", hosts=["10.10.10.0/24"], ports=[80, 443]
    )
    path = tmp_path / "generated.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    scope = load_scope(path)
    assert scope.engagement == "round-trip"
    assert scope.ports == (80, 443)
