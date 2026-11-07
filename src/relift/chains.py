"""Attack-thread correlation: findings in, multi-stage paths out.

A chain is built only from findings that exist in the current run. It is an
argument about how the observations join up — "this open datastore is step two
of a path that started at that exposed application" — and it names the stage an
attacker would have to get through plus the control that breaks the whole path.

Nothing here touches a target. It runs after the modules and reads their
evidence dictionaries, so adding a technique means adding a rule, not a
network call. Every rule must be able to say *which finding* proves each stage;
a rule that cannot is a guess and does not belong here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Callable

from .models import SEVERITY_RANK, AttackChain, ChainStep, Severity

# Kill-chain-ish stage labels. Chosen so a reader can line a thread up against
# a timeline without translating vocabulary first.
STAGE_RECON = "reconnaissance"
STAGE_ACCESS = "initial access"
STAGE_DISCOVERY = "discovery"
STAGE_CREDENTIAL = "credential access"
STAGE_PIVOT = "pivot"
STAGE_COLLECTION = "collection"
STAGE_ESCALATION = "privilege escalation"
STAGE_IMPACT = "impact"


def _find(
    findings: Iterable[dict[str, Any]],
    attack_id: str,
    **evidence: Any,
) -> dict[str, Any] | None:
    """First finding for a technique whose evidence matches every keyword."""
    for item in findings:
        if item.get("attack_id") != attack_id:
            continue
        bag = item.get("evidence") or {}
        if all(bag.get(key) == value for key, value in evidence.items()):
            return item
    return None


def _any(findings: Iterable[dict[str, Any]], attack_id: str) -> dict[str, Any] | None:
    return _find(findings, attack_id)


def _first_with(
    findings: Iterable[dict[str, Any]], attack_id: str, keys: tuple[str, ...]
) -> dict[str, Any] | None:
    """First finding for a technique whose evidence carries the given keys.

    Findings are sorted by severity before correlation, so the first entry for
    an attack is not necessarily the one that carries the machine-readable
    summary. Modules that emit several findings must be looked up by shape.
    """
    for item in findings:
        if item.get("attack_id") != attack_id:
            continue
        bag = item.get("evidence") or {}
        if all(key in bag for key in keys):
            return item
    return None


def _title(item: dict[str, Any] | None, fallback: str = "") -> str:
    return str((item or {}).get("title") or fallback)


def _detail(item: dict[str, Any] | None, fallback: str = "") -> str:
    text = str((item or {}).get("detail") or "")
    return text or fallback


def _step(stage: str, item: dict[str, Any] | None, fallback: str) -> ChainStep:
    return ChainStep(
        stage=stage,
        attack_id=str((item or {}).get("attack_id") or ""),
        title=_title(item, fallback),
        detail=_detail(item)[:240],
    )


@dataclass(frozen=True)
class Rule:
    """One correlation. ``build`` returns None when its evidence is absent."""

    id: str
    title: str
    build: Callable[[list[dict[str, Any]]], AttackChain | None]


# -- datastore threads -------------------------------------------------------
def _open_datastore(findings: list[dict[str, Any]]) -> AttackChain | None:
    config = _find(findings, "db.security_config", auth_required=False)
    if config is None:
        return None
    evidence = config.get("evidence") or {}
    engine = evidence.get("engine") or "database"
    fingerprint = _any(findings, "db.fingerprint")
    port = evidence.get("port")
    return AttackChain(
        id="thread.datastore-no-auth",
        title=f"Unauthenticated {engine} reachable: full datastore read path",
        severity=Severity.CRITICAL,
        summary=(
            f"The {engine} listener on port {port or '?'} answered the protocol "
            "probe without demanding credentials. Anyone who can route to this "
            "port has the application's data, and on several engines the same "
            "access reaches configuration and keys."
        ),
        stages=[
            _step(STAGE_RECON, fingerprint, f"{engine} listener identified"),
            ChainStep(
                stage=STAGE_ACCESS,
                attack_id="db.security_config",
                title="Authentication was not required",
                detail=f"negotiated auth method: {evidence.get('auth_method') or 'none'}",
            ),
            ChainStep(
                stage=STAGE_COLLECTION,
                attack_id="db.security_config",
                title="Datastore readable with no credential",
                detail="no further step is needed; the exposure is the whole path",
            ),
        ],
        break_at=(
            "Enable authentication and bind the listener to the loopback or an "
            "internal interface. Fix order: bind address first, then auth."
        ),
        confidence="high",
    )


def _cleartext_credentials(findings: list[dict[str, Any]]) -> AttackChain | None:
    config = _find(findings, "db.security_config", cleartext_auth=True)
    if config is None:
        return None
    evidence = config.get("evidence") or {}
    engine = evidence.get("engine") or "database"
    fingerprint = _any(findings, "db.fingerprint")
    return AttackChain(
        id="thread.datastore-cleartext-auth",
        title=f"{engine} accepts reusable credentials in the clear",
        severity=Severity.HIGH,
        summary=(
            "The server negotiated a password exchange that puts a replayable "
            "credential on the wire (clear-text or single-round hash). Anything "
            "with a tap on that path — a mirrored port, a compromised host, a "
            "logging proxy — turns one login into every login."
        ),
        stages=[
            _step(STAGE_RECON, fingerprint, f"{engine} listener identified"),
            ChainStep(
                stage=STAGE_CREDENTIAL,
                attack_id="db.security_config",
                title="Replayable credential on the wire",
                detail=f"auth method: {evidence.get('auth_method')}",
            ),
            ChainStep(
                stage=STAGE_PIVOT,
                attack_id="db.security_config",
                title="Reuse against the application tier",
                detail="the same account usually exists in the application config",
            ),
        ],
        break_at="Require SCRAM-SHA-256 (or the engine's equivalent) and TLS on the listener.",
        confidence="medium",
    )


def _eol_datastore(findings: list[dict[str, Any]]) -> AttackChain | None:
    config = _find(findings, "db.security_config", eol=True)
    if config is None:
        return None
    evidence = config.get("evidence") or {}
    engine = evidence.get("engine") or "database"
    version = evidence.get("version") or "unknown"
    fingerprint = _any(findings, "db.fingerprint")
    return AttackChain(
        id="thread.datastore-eol",
        title=f"{engine} {version} is past end of life and reachable",
        severity=Severity.HIGH,
        summary=(
            "The answering build no longer receives security fixes. Every future "
            "advisory for this engine is a permanent window on this host — and "
            "the exposure is the reachability, not a specific CVE. Verify any CVE "
            "claim against the build string before acting on it."
        ),
        stages=[
            _step(STAGE_RECON, fingerprint, f"{engine} {version} identified"),
            ChainStep(
                stage=STAGE_DISCOVERY,
                attack_id="db.security_config",
                title="Unsupported build answering",
                detail=f"{engine} {version} is below the supported line",
            ),
            ChainStep(
                stage=STAGE_IMPACT,
                attack_id="db.security_config",
                title="No fix will arrive for this listener",
                detail="the upgrade is the remediation; patching is not available",
            ),
        ],
        break_at="Upgrade to a supported major version, then re-run this assessment.",
        confidence="medium",
    )


def _web_to_database(findings: list[dict[str, Any]]) -> AttackChain | None:
    injection = _find(findings, "web.sql_injection_check", injectable=True)
    if injection is None:
        return None
    datastore = (
        _any(findings, "db.security_config")
        or _any(findings, "db.fingerprint")
    )
    if datastore is None:
        return None
    evidence = injection.get("evidence") or {}
    db_evidence = datastore.get("evidence") or {}
    engine = db_evidence.get("engine") or "database"
    hint = evidence.get("dbms_hint") or engine
    stages = [
        ChainStep(
            stage=STAGE_ACCESS,
            attack_id="web.sql_injection_check",
            title=f"Injectable parameter {evidence.get('param') or '?'}",
            detail=f"proved by: {', '.join(evidence.get('styles') or []) or 'signature'}",
        ),
        ChainStep(
            stage=STAGE_PIVOT,
            attack_id=datastore.get("attack_id", "db.fingerprint"),
            title=f"{engine} behind the application",
            detail=_title(datastore, "datastore fingerprint"),
        ),
    ]
    severity = Severity.CRITICAL
    config = _any(findings, "db.security_config")
    if config is not None:
        db_bag = config.get("evidence") or {}
        if db_bag.get("auth_required") is False:
            stages.append(
                ChainStep(
                    stage=STAGE_COLLECTION,
                    attack_id="db.security_config",
                    title="Injection reaches a datastore with no auth",
                    detail="the application's own query is the only gate left",
                )
            )
        if db_bag.get("privilege_level") == "superuser":
            severity = Severity.CRITICAL
    return AttackChain(
        id="thread.web-to-datastore",
        title=f"Application holds a live path into {hint}",
        severity=severity,
        summary=(
            f"A user-controlled parameter on {evidence.get('url') or 'the target'} "
            "changes the query the application sends. The database it talks to is "
            "reachable in the same run, so the application tier is not a boundary "
            "here — it is the route in."
        ),
        stages=stages,
        break_at=(
            "Fix the parameterised query first: it is the only stage that is "
            "entirely in the application's hands. Then revoke the application "
            "account's rights beyond its own schema."
        ),
        confidence="high",
    )


def _valid_credential(findings: list[dict[str, Any]]) -> AttackChain | None:
    verified = _find(findings, "db.credential_verify", login_ok=True)
    if verified is None:
        return None
    evidence = verified.get("evidence") or {}
    level = str(evidence.get("privilege_level") or "unknown")
    engine = evidence.get("engine") or "database"
    user = evidence.get("username") or "supplied account"
    severity = Severity.CRITICAL if level == "superuser" else Severity.HIGH
    stages = [
        ChainStep(
            stage=STAGE_CREDENTIAL,
            attack_id="db.credential_verify",
            title=f"Credential for {user} accepted",
            detail=f"{engine} login succeeded on the first and only attempt",
        ),
    ]
    if level in ("superuser", "admin"):
        stages.append(
            ChainStep(
                stage=STAGE_ESCALATION,
                attack_id="db.credential_verify",
                title=f"Account holds {level} rights",
                detail="no further escalation is required",
            )
        )
    stages.append(
        ChainStep(
            stage=STAGE_COLLECTION,
            attack_id="db.credential_verify",
            title="Every object the account can read",
            detail="scope of collection was not performed; this is the potential",
        )
    )
    return AttackChain(
        id="thread.valid-credential",
        title=f"Held {engine} credential still works and is {level}",
        severity=severity,
        summary=(
            f"A credential the operator already had was accepted by {engine}. "
            "That makes the credential — not the network — the weakest link, and "
            "it means whatever leaked it is still leaking."
        ),
        stages=stages,
        break_at=(
            "Rotate the credential, then find its source: config file, CI secret, "
            "backup, or an application default. Rotation without that step only "
            "resets the clock."
        ),
        confidence="high",
    )


# -- web threads -------------------------------------------------------------
def _plaintext_session(findings: list[dict[str, Any]]) -> AttackChain | None:
    plaintext = _find(findings, "recon.http_fingerprint") or None
    plaintext_hit = None
    for item in findings:
        if str(item.get("title") or "").lower().startswith("service is served over plaintext"):
            plaintext_hit = item
            break
    if plaintext_hit is None:
        return None
    hsts_missing = None
    for item in findings:
        if str(item.get("title") or "") == "Missing security header: strict-transport-security":
            hsts_missing = item
            break
    disclosure = _any(findings, "web.content_disclosure")
    interesting = (disclosure or {}).get("evidence", {}).get("interesting") or []
    stages = [
        _step(STAGE_RECON, plaintext, "Origin answers on plaintext HTTP"),
        ChainStep(
            stage=STAGE_CREDENTIAL,
            attack_id="recon.http_fingerprint",
            title="Session material crosses the wire in the clear",
            detail="a passive tap on the path yields cookies, tokens and passwords",
        ),
    ]
    if hsts_missing is not None:
        stages.append(
            ChainStep(
                stage=STAGE_PIVOT,
                attack_id="web.headers",
                title="Nothing pins the browser to HTTPS",
                detail="downgrade is possible, so the tap can be made active",
            )
        )
    if interesting:
        stages.append(
            ChainStep(
                stage=STAGE_ACCESS,
                attack_id="web.content_disclosure",
                title="Administrative paths are advertised",
                detail=", ".join(str(p) for p in interesting[:4]),
            )
        )
    return AttackChain(
        id="thread.plaintext-session",
        title="Session theft path over plaintext HTTP",
        severity=Severity.HIGH if interesting else Severity.MEDIUM,
        summary=(
            "The origin serves user sessions without TLS. Combined with the "
            "missing transport header, a network-local attacker can read or "
            "downgrade credentials, and the disclosed paths say where to spend "
            "them."
        ),
        stages=stages,
        break_at="Redirect every request to HTTPS and send HSTS with a long max-age.",
        confidence="high" if hsts_missing is not None else "medium",
    )


def _certificate_mitm(findings: list[dict[str, Any]]) -> AttackChain | None:
    cert = _any(findings, "tls.certificate")
    if cert is None:
        return None
    evidence = cert.get("evidence") or {}
    reasons = []
    if evidence.get("self_signed"):
        reasons.append("self-signed")
    days_left = evidence.get("days_left")
    if isinstance(days_left, int) and days_left < 0:
        reasons.append("expired")
    if not reasons:
        return None
    return AttackChain(
        id="thread.certificate-mitm",
        title=f"Certificate cannot anchor trust ({', '.join(reasons)})",
        severity=Severity.MEDIUM,
        summary=(
            "Clients have no cryptographic reason to believe they are talking to "
            "this host. In practice that is either an outage waiting for a "
            "monitoring window or a habit of clicking through warnings — both "
            "make an interception path cheaper than it should be."
        ),
        stages=[
            ChainStep(
                stage=STAGE_RECON,
                attack_id="tls.certificate",
                title=f"Certificate {', '.join(reasons)}",
                detail=_detail(cert)[:200],
            ),
            ChainStep(
                stage=STAGE_PIVOT,
                attack_id="tls.certificate",
                title="Warning fatigue or a pinned-down service",
                detail="users who click through cannot distinguish you from the host",
            ),
        ],
        break_at="Issue a valid certificate for the names actually served and monitor expiry.",
        confidence="medium",
    )


def _writable_admin_surface(findings: list[dict[str, Any]]) -> AttackChain | None:
    methods = _any(findings, "web.methods")
    risky = (methods or {}).get("evidence", {}).get("risky") or []
    if not risky:
        return None
    disclosure = _any(findings, "web.content_disclosure")
    interesting = (disclosure or {}).get("evidence", {}).get("interesting") or []
    stages = [
        ChainStep(
            stage=STAGE_DISCOVERY,
            attack_id="web.methods",
            title=f"Write-capable methods declared: {', '.join(risky)}",
            detail=_detail(methods)[:200],
        ),
    ]
    if interesting:
        stages.append(
            ChainStep(
                stage=STAGE_ACCESS,
                attack_id="web.content_disclosure",
                title="Named administrative locations",
                detail=", ".join(str(p) for p in interesting[:4]),
            )
        )
    stages.append(
        ChainStep(
            stage=STAGE_IMPACT,
            attack_id="web.methods",
            title="Content replacement path",
            detail="a write method plus a known path is defacement or code drop",
        )
    )
    return AttackChain(
        id="thread.writable-admin-surface",
        title="Write methods exposed on a discoverable surface",
        severity=Severity.HIGH if interesting else Severity.MEDIUM,
        summary=(
            "The server advertises methods that change state, and the paths "
            "worth changing are named in the site's own disclosure files. "
            "Whether the methods are actually authorised is the next question — "
            "this thread says why it matters."
        ),
        stages=stages,
        break_at=(
            "Reject PUT/DELETE/PATCH at the edge unless the route is authenticated "
            "and intended."
        ),
        confidence="medium",
    )


# -- host threads ------------------------------------------------------------
def _local_escalation(findings: list[dict[str, Any]]) -> AttackChain | None:
    audit = _first_with(
        findings, "system.host_audit", ("suid", "kernel_cves", "sudo_rules")
    )
    if audit is None:
        return None
    evidence = audit.get("evidence") or {}
    suid = evidence.get("suid") or []
    caps = evidence.get("capabilities") or []
    sudo_rules = evidence.get("sudo_rules") or []
    cves = evidence.get("kernel_cves") or []
    if not (suid or caps or sudo_rules or cves):
        return None
    stages = [ChainStep(
        stage=STAGE_RECON,
        attack_id="system.host_audit",
        title=f"Local surface on {evidence.get('os') or 'this host'}",
        detail=f"kernel {evidence.get('kernel') or '?'}",
    )]
    if suid or caps:
        stages.append(ChainStep(
            stage=STAGE_ESCALATION,
            attack_id="system.host_audit",
            title=f"{len(suid)} SUID/SGID binary(ies), {len(caps)} capability(ies)",
            detail=", ".join(str(x) for x in (list(suid) + list(caps))[:5]),
        ))
    if sudo_rules:
        stages.append(ChainStep(
            stage=STAGE_ESCALATION,
            attack_id="system.host_audit",
            title=f"{len(sudo_rules)} readable sudo rule(s)",
            detail=", ".join(str(x) for x in sudo_rules[:4]),
        ))
    if cves:
        stages.append(ChainStep(
            stage=STAGE_IMPACT,
            attack_id="system.host_audit",
            title="Kernel is below a known fix release",
            detail=", ".join(str(x) for x in cves[:4]),
        ))
    return AttackChain(
        id="thread.local-privilege-escalation",
        title="Local privilege-escalation path on this host",
        severity=Severity.HIGH if cves else Severity.MEDIUM,
        summary=(
            "This host presents a local escalation surface. None of it is "
            "exploited here — the point is that a low-privilege foothold (a "
            "service account, a build agent, a container) is not contained by "
            "the account boundary."
        ),
        stages=stages,
        break_at=(
            "Remove unnecessary SUID bits and file capabilities, then review the "
            "sudo rules that are readable at all. Kernel advisories are the "
            "second order of business."
        ),
        confidence="medium",
    )


def _container_escape(findings: list[dict[str, Any]]) -> AttackChain | None:
    audit = _first_with(findings, "system.host_audit", ("docker_socket",))
    if audit is None:
        return None
    evidence = audit.get("evidence") or {}
    if not evidence.get("docker_socket"):
        return None
    suid = evidence.get("suid") or []
    stages = [
        ChainStep(
            stage=STAGE_ACCESS,
            attack_id="system.host_audit",
            title="Container runtime socket is reachable from this account",
            detail=str(evidence.get("docker_socket_detail") or "docker socket accessible"),
        ),
        ChainStep(
            stage=STAGE_ESCALATION,
            attack_id="system.host_audit",
            title="Socket access is host root",
            detail="the socket can start a privileged container that mounts the host",
        ),
    ]
    if suid:
        stages.append(ChainStep(
            stage=STAGE_IMPACT,
            attack_id="system.host_audit",
            title=f"{len(suid)} SUID binary(ies) available afterwards",
            detail=", ".join(str(x) for x in suid[:4]),
        ))
    return AttackChain(
        id="thread.container-escape",
        title="Container socket access is effectively host root",
        severity=Severity.CRITICAL,
        summary=(
            "The account running this assessment can reach the container "
            "runtime socket. That is not a container boundary problem — it is a "
            "host boundary that does not exist."
        ),
        stages=stages,
        break_at=(
            "Take this account out of the docker group, use rootless containers, "
            "or front the socket with an authorising proxy."
        ),
        confidence="high",
    )


RULES: tuple[Rule, ...] = (
    Rule("thread.datastore-no-auth", "Unauthenticated datastore", _open_datastore),
    Rule("thread.web-to-datastore", "Application to datastore", _web_to_database),
    Rule("thread.valid-credential", "Working credential", _valid_credential),
    Rule("thread.container-escape", "Container socket", _container_escape),
    Rule("thread.datastore-cleartext-auth", "Cleartext datastore auth", _cleartext_credentials),
    Rule("thread.datastore-eol", "End-of-life datastore", _eol_datastore),
    Rule("thread.plaintext-session", "Plaintext session", _plaintext_session),
    Rule("thread.writable-admin-surface", "Writable admin surface", _writable_admin_surface),
    Rule("thread.certificate-mitm", "Certificate trust", _certificate_mitm),
    Rule("thread.local-privilege-escalation", "Local escalation", _local_escalation),
)


def analyse(findings: Iterable[dict[str, Any]]) -> list[AttackChain]:
    """Run every rule against a run's findings. Order: worst first, then id."""
    materialised = [item for item in findings if isinstance(item, dict)]
    if not materialised:
        return []
    chains: list[AttackChain] = []
    seen: set[str] = set()
    for rule in RULES:
        try:
            chain = rule.build(materialised)
        except Exception:  # noqa: BLE001 - a bad rule must not kill a report
            continue
        if chain is None or chain.id in seen:
            continue
        seen.add(chain.id)
        chains.append(chain)
    chains.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.id))
    return chains


def headline(chains: Iterable[AttackChain]) -> str:
    """One line for the report header and the desktop run card."""
    materialised = list(chains)
    if not materialised:
        return "no attack thread completed from these findings"
    worst = materialised[0]
    return (
        f"{len(materialised)} attack thread(s); worst is {worst.severity.value}: "
        f"{worst.title}"
    )
