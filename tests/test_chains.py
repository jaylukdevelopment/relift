"""Attack-thread correlation: findings in, multi-stage paths out."""

from __future__ import annotations

from relift.chains import analyse, headline
from relift.models import SEVERITY_RANK, Severity


def finding(attack_id, title, detail="", severity="info", evidence=None):
    return {
        "attack_id": attack_id,
        "title": title,
        "detail": detail,
        "severity": severity,
        "evidence": evidence or {},
    }


def ids(chains):
    return [chain.id for chain in chains]


def one(chains, chain_id):
    matches = [chain for chain in chains if chain.id == chain_id]
    assert len(matches) == 1, f"expected exactly one {chain_id}, got {ids(chains)}"
    return matches[0]


# -- datastore threads -------------------------------------------------------
def test_unauthenticated_datastore_is_critical_with_three_stages():
    chains = analyse(
        [
            finding("db.fingerprint", "redis 7.4 fingerprinted", evidence={"engine": "redis"}),
            finding(
                "db.security_config",
                "Redis answers commands without authentication",
                evidence={"engine": "redis", "auth_required": False, "port": 6379},
            ),
        ]
    )
    chain = one(chains, "thread.datastore-no-auth")
    assert chain.severity is Severity.CRITICAL
    assert len(chain.stages) == 3
    assert "redis" in chain.title
    assert chain.break_at


def test_authenticated_datastore_does_not_produce_the_open_thread():
    chains = analyse(
        [
            finding(
                "db.security_config",
                "mysql requires authentication",
                evidence={"engine": "mysql", "auth_required": True},
            )
        ]
    )
    assert "thread.datastore-no-auth" not in ids(chains)


def test_cleartext_authentication_thread():
    chains = analyse(
        [
            finding(
                "db.security_config",
                "mysql negotiates a replayable credential exchange",
                evidence={
                    "engine": "mysql",
                    "auth_required": True,
                    "cleartext_auth": True,
                    "auth_method": "mysql_native_password",
                },
            )
        ]
    )
    chain = one(chains, "thread.datastore-cleartext-auth")
    assert chain.severity is Severity.HIGH
    assert "mysql_native_password" in chain.stages[1].detail


def test_end_of_life_thread_names_the_version():
    chains = analyse(
        [
            finding(
                "db.security_config",
                "postgres 9.6 is past end of life",
                evidence={"engine": "postgres", "version": "9.6.24", "eol": True},
            )
        ]
    )
    chain = one(chains, "thread.datastore-eol")
    assert "9.6.24" in chain.title
    assert "upgrade" in chain.break_at.lower()


def test_sql_injection_to_datastore_thread():
    chains = analyse(
        [
            finding(
                "web.sql_injection_check",
                "SQL injection in parameter q",
                evidence={
                    "url": "http://127.0.0.1:9/search",
                    "param": "q",
                    "injectable": True,
                    "styles": ["error"],
                    "dbms_hint": "mysql",
                },
            ),
            finding(
                "db.fingerprint",
                "mysql fingerprinted",
                evidence={"engine": "mysql"},
            ),
        ]
    )
    chain = one(chains, "thread.web-to-datastore")
    assert chain.severity is Severity.CRITICAL
    assert chain.stages[0].attack_id == "web.sql_injection_check"
    assert "mysql" in chain.title


def test_injection_without_a_datastore_finding_is_not_a_thread():
    chains = analyse(
        [
            finding(
                "web.sql_injection_check",
                "SQL injection in parameter q",
                evidence={"injectable": True, "param": "q", "styles": ["error"]},
            )
        ]
    )
    assert "thread.web-to-datastore" not in ids(chains)


def test_verified_superuser_credential_is_critical():
    chains = analyse(
        [
            finding(
                "db.credential_verify",
                "Credential for postgres accepted",
                evidence={
                    "engine": "postgres",
                    "username": "postgres",
                    "login_ok": True,
                    "privilege_level": "superuser",
                },
            )
        ]
    )
    chain = one(chains, "thread.valid-credential")
    assert chain.severity is Severity.CRITICAL
    assert any(step.stage == "privilege escalation" for step in chain.stages)


def test_verified_ordinary_credential_is_high():
    chains = analyse(
        [
            finding(
                "db.credential_verify",
                "Credential for app accepted",
                evidence={
                    "engine": "mysql",
                    "username": "app",
                    "login_ok": True,
                    "privilege_level": "authenticated",
                },
            )
        ]
    )
    chain = one(chains, "thread.valid-credential")
    assert chain.severity is Severity.HIGH
    assert not any(step.stage == "privilege escalation" for step in chain.stages)


def test_rejected_credential_produces_no_thread():
    chains = analyse(
        [
            finding(
                "db.credential_verify",
                "Credential for app rejected",
                evidence={"engine": "mysql", "login_ok": False},
            )
        ]
    )
    assert "thread.valid-credential" not in ids(chains)


# -- web threads -------------------------------------------------------------
def test_plaintext_session_thread_includes_disclosed_paths():
    chains = analyse(
        [
            finding(
                "recon.http_fingerprint",
                "Service is served over plaintext HTTP",
                evidence={"url": "http://127.0.0.1/"},
            ),
            finding(
                "web.headers",
                "Missing security header: strict-transport-security",
            ),
            finding(
                "web.content_disclosure",
                "robots.txt names 2 disallowed path(s)",
                evidence={"interesting": ["/admin", "/backup"]},
            ),
        ]
    )
    chain = one(chains, "thread.plaintext-session")
    assert chain.severity is Severity.HIGH
    assert any(step.attack_id == "web.content_disclosure" for step in chain.stages)


def test_plaintext_without_hsts_is_a_medium_thread():
    chains = analyse(
        [
            finding(
                "recon.http_fingerprint",
                "Service is served over plaintext HTTP",
            )
        ]
    )
    chain = one(chains, "thread.plaintext-session")
    assert chain.severity is Severity.MEDIUM


def test_self_signed_certificate_thread():
    chains = analyse(
        [
            finding(
                "tls.certificate",
                "Certificate is self-signed",
                evidence={"self_signed": True, "days_left": 200},
            )
        ]
    )
    chain = one(chains, "thread.certificate-mitm")
    assert "self-signed" in chain.title


def test_expired_certificate_counts_as_no_anchor():
    chains = analyse(
        [
            finding(
                "tls.certificate",
                "Certificate expired 4 day(s) ago",
                evidence={"self_signed": False, "days_left": -4},
            )
        ]
    )
    assert "thread.certificate-mitm" in ids(chains)


def test_valid_certificate_produces_no_mitm_thread():
    chains = analyse(
        [
            finding(
                "tls.certificate",
                "Certificate read",
                evidence={"self_signed": False, "days_left": 120},
            )
        ]
    )
    assert "thread.certificate-mitm" not in ids(chains)


def test_writable_admin_surface_thread():
    chains = analyse(
        [
            finding(
                "web.methods",
                "Risky HTTP methods declared: PUT, DELETE",
                evidence={"risky": ["PUT", "DELETE"]},
            ),
            finding(
                "web.content_disclosure",
                "robots.txt names 1 disallowed path(s)",
                evidence={"interesting": ["/admin"]},
            ),
        ]
    )
    chain = one(chains, "thread.writable-admin-surface")
    assert chain.severity is Severity.HIGH
    assert "PUT" in chain.stages[0].title


def test_risky_methods_without_write_semantics_are_ignored():
    chains = analyse(
        [finding("web.methods", "No risky methods declared", evidence={"risky": []})]
    )
    assert "thread.writable-admin-surface" not in ids(chains)


# -- host threads ------------------------------------------------------------
def test_local_escalation_and_container_escape_from_one_audit():
    chains = analyse(
        [
            finding(
                "system.host_audit",
                "Host audit: Debian 12 kernel 6.1.0",
                evidence={
                    "os": "Debian GNU/Linux 12",
                    "kernel": "6.1.0-18-amd64",
                    "suid": ["/usr/bin/sudo", "/usr/bin/passwd"],
                    "sgid": [],
                    "capabilities": ["/usr/bin/ping cap_net_raw"],
                    "sudo_rules": ["%sudo ALL=(ALL:ALL) NOPASSWD: ALL"],
                    "kernel_cves": ["CVE-2023-0386 overlayfs (fixed in 6.2.0)"],
                    "docker_socket": True,
                    "docker_socket_detail": "mode 0666",
                },
            )
        ]
    )
    local = one(chains, "thread.local-privilege-escalation")
    escape = one(chains, "thread.container-escape")
    assert local.severity is Severity.HIGH
    assert escape.severity is Severity.CRITICAL


def test_clean_host_audit_produces_no_local_thread():
    chains = analyse(
        [
            finding(
                "system.host_audit",
                "Host audit: clean",
                evidence={
                    "suid": [],
                    "sgid": [],
                    "capabilities": [],
                    "sudo_rules": [],
                    "kernel_cves": [],
                    "docker_socket": False,
                },
            )
        ]
    )
    assert "thread.local-privilege-escalation" not in ids(chains)
    assert "thread.container-escape" not in ids(chains)


# -- contract ----------------------------------------------------------------
def test_no_findings_means_no_threads():
    assert analyse([]) == []


def test_malformed_evidence_is_ignored_not_fatal():
    chains = analyse(
        [
            {"attack_id": "db.security_config", "title": "x", "evidence": "not-a-dict"},
            {"attack_id": "db.security_config", "title": "y", "evidence": None},
            "not-even-a-finding",
            None,
        ]
    )
    assert chains == []


def test_chains_are_ordered_worst_first():
    chains = analyse(
        [
            finding(
                "tls.certificate",
                "Certificate is self-signed",
                evidence={"self_signed": True},
            ),
            finding(
                "db.security_config",
                "Redis answers commands without authentication",
                evidence={"engine": "redis", "auth_required": False},
            ),
            finding(
                "web.methods",
                "Risky HTTP methods declared: PUT",
                evidence={"risky": ["PUT"]},
            ),
        ]
    )
    ranks = [SEVERITY_RANK[chain.severity] for chain in chains]
    assert ranks == sorted(ranks, reverse=True)


def test_chain_ids_are_unique():
    chains = analyse(
        [
            finding(
                "db.security_config",
                "open",
                evidence={"engine": "redis", "auth_required": False},
            ),
            finding(
                "db.security_config",
                "open again",
                evidence={"engine": "redis", "auth_required": False},
            ),
        ]
    )
    assert len(ids(chains)) == len(set(ids(chains)))


def test_chain_serialises_for_the_report():
    chains = analyse(
        [finding("db.security_config", "open", evidence={"auth_required": False})]
    )
    payload = chains[0].to_dict()
    assert set(payload) == {
        "id",
        "title",
        "severity",
        "summary",
        "stages",
        "break_at",
        "confidence",
    }
    assert all("stage" in step for step in payload["stages"])


def test_headline_reports_nothing_when_nothing_correlated():
    assert "no attack thread" in headline([])


def test_headline_names_the_worst_thread():
    chains = analyse(
        [finding("db.security_config", "open", evidence={"auth_required": False})]
    )
    assert "critical" in headline(chains).lower()
