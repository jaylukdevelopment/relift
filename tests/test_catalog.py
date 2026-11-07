"""Catalogue integrity: the contract between what is listed and what can run."""

from __future__ import annotations

import pytest

from relift import catalog
from relift.models import RISK_RANK, Risk
from relift.modules import MODULES


def test_every_runnable_technique_has_a_module():
    missing = [
        spec.id
        for spec in catalog.all_specs()
        if spec.implemented
        and spec.category not in ("report", "analysis")
        and spec.id not in MODULES
    ]
    assert missing == [], f"implemented but unrunnable: {missing}"


def test_no_module_is_outside_the_catalogue():
    unknown = sorted(set(MODULES) - set(catalog.CATALOG))
    assert unknown == [], f"modules with no catalogue entry: {unknown}"


def test_every_module_reports_the_id_it_is_registered_under():
    for attack_id, module in MODULES.items():
        assert module.attack_id == attack_id


def test_design_only_techniques_are_marked_as_such():
    for attack_id in MODULES:
        assert catalog.spec(attack_id).implemented is True


def test_spec_lookup_refuses_unknown_ids():
    with pytest.raises(KeyError, match="unknown technique"):
        catalog.spec("db.does_not_exist")


def test_category_order_covers_every_category_present():
    present = {spec.category for spec in catalog.all_specs()}
    assert set(catalog.categories()) == present
    assert list(catalog.categories()) == [
        name for name in catalog.CATEGORY_ORDER if name in present
    ]


def test_every_spec_declares_at_least_one_family():
    for spec in catalog.all_specs():
        assert spec.families, f"{spec.id} has no target family"
        assert set(spec.families) <= set(catalog.ALL_FAMILIES)


def test_select_respects_the_risk_ceiling():
    chosen = catalog.select("passive")
    assert chosen, "a passive plan should not be empty"
    assert all(spec.risk is Risk.PASSIVE for spec in chosen)


def test_select_respects_an_explicit_lower_ceiling():
    for spec in catalog.select("lab", max_risk=Risk.SAFE):
        assert RISK_RANK[spec.risk] <= RISK_RANK[Risk.SAFE]


def test_select_filters_by_target_family():
    chosen = catalog.select("lab", families=("db",))
    assert chosen
    assert all("db" in spec.families for spec in chosen)
    assert any(spec.category == "db" for spec in chosen)


def test_host_family_selection_includes_the_host_audit():
    chosen = catalog.select("lab", families=("host",))
    ids = [spec.id for spec in chosen]
    assert "system.host_audit" in ids
    assert all("host" in spec.families for spec in chosen)
    # Nothing network-only may appear in a local-host plan.
    assert "web.headers" not in ids
    assert "db.fingerprint" not in ids


def test_external_techniques_follow_the_profile():
    assert not any(spec.external for spec in catalog.select("safe"))
    standard = catalog.select("standard")
    assert any(spec.external for spec in standard)


def test_unknown_profile_is_refused():
    with pytest.raises(ValueError, match="unknown profile"):
        catalog.select("not-a-profile")


def test_counts_are_internally_consistent():
    counts = catalog.counts()
    specs = catalog.all_specs()
    assert counts["total"] == len(specs)
    assert counts["implemented"] == sum(1 for s in specs if s.implemented)
    assert counts["external"] == sum(1 for s in specs if s.implemented and s.external)
    assert counts["design_only"] == sum(1 for s in specs if not s.implemented)


def test_implemented_includes_the_new_techniques():
    for attack_id in (
        "db.fingerprint",
        "db.security_config",
        "db.credential_verify",
        "web.sql_injection_check",
        "system.host_audit",
        "auth.ssh_algorithms",
        "analysis.attack_chains",
    ):
        assert catalog.spec(attack_id).implemented is True


def test_never_shipped_technique_stays_unimplemented():
    spec = catalog.spec("auth.default_credentials")
    assert spec.implemented is False
    assert "NEVER SHIPPED" in spec.notes


def test_risky_techniques_are_not_in_the_default_profile():
    risky = {"db.credential_verify", "web.sql_injection_check", "web.server_audit"}
    default_ids = {spec.id for spec in catalog.select(catalog.DEFAULT_PROFILE)}
    assert risky.isdisjoint(default_ids)


def test_input_requiring_techniques_are_intrusive():
    for attack_id in ("db.credential_verify", "web.sql_injection_check"):
        assert catalog.spec(attack_id).risk is Risk.INTRUSIVE
