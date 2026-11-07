"""The attack catalogue — the single source of truth for what Relift may run.

Adding a technique means adding an ``AttackSpec`` here *first*, with its risk
tier. The tier is the safety control: a technique nobody classified is a
technique nobody reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import AttackSpec, Risk, RISK_RANK

# Category display order. Least invasive first, so a run reads top-down.
CATEGORY_ORDER = ("recon", "tls", "web", "auth", "report")

_SPECS: tuple[AttackSpec, ...] = (
    # ---------------------------------------------------------------- recon
    AttackSpec(
        id="recon.dns",
        name="DNS resolution & address inventory",
        category="recon",
        risk=Risk.PASSIVE,
        summary="Resolve A/AAAA records and classify the address space "
                "(loopback, RFC1918, CGNAT, public).",
        produces=("addresses", "address_class", "cname"),
        ai_hint="Address inventory is the baseline for judging whether a host is "
                "an internal service or a public one; it changes how the rest of "
                "the findings should be read.",
        mitre="T1590.002",
    ),
    AttackSpec(
        id="recon.http_fingerprint",
        name="HTTP fingerprint",
        category="recon",
        risk=Risk.PASSIVE,
        summary="One GET on the root path; records status, Server, X-Powered-By "
                "and the page title.",
        produces=("status", "server", "powered_by", "title"),
        ai_hint="Server and framework headers tell you which finding classes are "
                "worth caring about for this stack.",
        mitre="T1592.004",
    ),
    AttackSpec(
        id="recon.port_scan",
        name="TCP connect sweep",
        category="recon",
        risk=Risk.SAFE,
        summary="Full TCP handshakes against the operator's port list. Logged by "
                "the target by design; this is not a stealth tool.",
        produces=("open_ports", "banners"),
        ai_hint="A port that answers but was not in the expected set is the most "
                "interesting thing in a sweep. Ask about it.",
        mitre="T1046",
    ),
    AttackSpec(
        id="recon.service_scan",
        name="Service/version detection",
        category="recon",
        risk=Risk.SAFE,
        summary="Version probing over the same port list via nmap -sV. Turns "
                "'port open' into 'which daemon'.",
        requires=("nmap",),
        produces=("services", "versions"),
        ai_hint="Version strings map to known-issue classes; never claim a CVE "
                "from a banner without a version match you can quote.",
        mitre="T1046",
    ),
    AttackSpec(
        id="recon.passive_subdomains",
        name="Passive subdomain inventory",
        category="recon",
        risk=Risk.PASSIVE,
        summary="Read-only inventory from certificate transparency logs. No DNS "
                "brute-force, ever.",
        implemented=False,
        produces=("subdomains",),
        ai_hint="Exposed staging or admin names usually explain the rest of the "
                "findings on this list.",
        mitre="T1590.005",
        notes="Design-only: CT log client not written yet.",
    ),
    # ------------------------------------------------------------------ tls
    AttackSpec(
        id="tls.certificate",
        name="Certificate inspection",
        category="tls",
        risk=Risk.PASSIVE,
        summary="Handshake, then parse subject, issuer, SANs, validity window and "
                "hostname coverage; flags expiry and self-signed certs.",
        produces=("subject", "issuer", "sans", "expires_in_days", "self_signed"),
        ai_hint="An expiring certificate and a self-signed certificate are "
                "different problems with different urgency.",
        mitre="T1592.002",
    ),
    AttackSpec(
        id="tls.protocol_support",
        name="TLS version support probe",
        category="tls",
        risk=Risk.SAFE,
        summary="Pins handshakes to TLS 1.2 and 1.3 and reports which negotiate.",
        produces=("tls12", "tls13"),
        ai_hint="A server that only offers 1.2 is a finding; a server that offers "
                "nothing is a different, worse finding.",
        mitre="T1595",
    ),
    AttackSpec(
        id="tls.cipher_preference",
        name="Cipher suite preference",
        category="tls",
        risk=Risk.SAFE,
        summary="Cipher list and preference order via sslscan.",
        implemented=False,
        requires=("sslscan",),
        produces=("ciphers", "preference"),
        ai_hint="CBC and RC4 in a modern stack mean an old config or an old library.",
        mitre="T1595",
        notes="Design-only: needs sslscan output parsing pinned per version.",
    ),
    # ------------------------------------------------------------------ web
    AttackSpec(
        id="web.headers",
        name="Security header audit",
        category="web",
        risk=Risk.PASSIVE,
        summary="Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
                "Referrer-Policy and Permissions-Policy.",
        produces=("present", "missing", "values"),
        ai_hint="Missing CSP and missing HSTS on an HTTPS origin are the two that "
                "actually enable something; the rest is hygiene.",
        mitre="T1592.004",
    ),
    AttackSpec(
        id="web.methods",
        name="HTTP method exposure",
        category="web",
        risk=Risk.SAFE,
        summary="OPTIONS on the root plus a TRACE probe; flags declared PUT, "
                "DELETE, TRACE and CONNECT.",
        produces=("allow", "trace_enabled"),
        ai_hint="A declared TRACE or PUT is a real finding; a 405 is a pass and "
                "should not be dressed up as a weakness.",
        mitre="T1595",
    ),
    AttackSpec(
        id="web.content_disclosure",
        name="robots.txt / sitemap disclosure",
        category="web",
        risk=Risk.PASSIVE,
        summary="Reads /robots.txt and /sitemap.xml. Reports the paths they name "
                "without fetching them.",
        produces=("disallowed_paths", "sitemap_urls"),
        ai_hint="Disallowed entries routinely name admin panels and backups. "
                "Report the names; do not imply they were accessed.",
        mitre="T1590",
    ),
    AttackSpec(
        id="web.template_scan",
        name="Template scan (safe severities)",
        category="web",
        risk=Risk.SAFE,
        summary="nuclei restricted to info/low/medium with fixed flags and no "
                "interactsh. The most valuable module and the most dangerous to "
                "leave unbounded.",
        requires=("nuclei",),
        produces=("matches", "templates"),
        ai_hint="Group template matches by template family; a single template "
                "hitting five URLs is one finding, not five.",
        mitre="T1595.002",
    ),
    AttackSpec(
        id="web.server_audit",
        name="Server misconfiguration audit",
        category="web",
        risk=Risk.INTRUSIVE,
        summary="nikto tuning restricted to configuration checks. Noisy and slow; "
                "requires --profile lab.",
        requires=("nikto",),
        produces=("misfits",),
        ai_hint="Treat every nikto line as a lead to verify, never as a "
                "confirmed issue.",
        mitre="T1595.002",
        notes="Intrusive: expect WAF/IDS reaction and real log noise.",
    ),
    AttackSpec(
        id="web.dir_bruteforce",
        name="Directory brute-force",
        category="web",
        risk=Risk.INTRUSIVE,
        summary="Wordlist enumeration with 404 calibration.",
        implemented=False,
        produces=("paths",),
        ai_hint="Uncalibrated soft-404s produce confident nonsense; verify any hit.",
        mitre="T1083",
        notes="Design-only: needs a wordlist policy and rate budget first.",
    ),
    # ----------------------------------------------------------------- auth
    AttackSpec(
        id="auth.ssh_algorithms",
        name="SSH algorithm audit",
        category="auth",
        risk=Risk.SAFE,
        summary="Deprecated KEX, cipher and MAC reporting via ssh-audit.",
        implemented=False,
        requires=("ssh-audit",),
        produces=("kex", "ciphers", "macs"),
        ai_hint="Deprecated algorithms matter most on internet-facing SSH, not on "
                "a lab box behind a jump host.",
        mitre="T1595",
        notes="Design-only: wrapper pending.",
    ),
    AttackSpec(
        id="auth.password_policy",
        name="Authentication policy probing",
        category="auth",
        risk=Risk.INTRUSIVE,
        summary="Lockout and rate-limit behaviour against a handful of accounts.",
        implemented=False,
        produces=("lockout_threshold", "rate_limit"),
        ai_hint="Lockout behaviour is an availability risk; report it as such.",
        mitre="T1110.001",
        notes="Design-only: needs the M2 correlation engine before it is safe even "
              "in a lab.",
    ),
    AttackSpec(
        id="auth.default_credentials",
        name="Default credential check",
        category="auth",
        risk=Risk.INTRUSIVE,
        summary="Permanently excluded from this tree.",
        implemented=False,
        produces=(),
        ai_hint="",
        mitre="T1078.001",
        notes="NEVER SHIPPED. One step from an actual break-in; excluded in every "
              "profile regardless of flags. See docs/03-RULES-OF-ENGAGEMENT.md §7.",
    ),
    # --------------------------------------------------------------- report
    AttackSpec(
        id="report.narrative",
        name="Analyst narrative",
        category="report",
        risk=Risk.PASSIVE,
        summary="Executive summary, grouped technical section and a fix-first "
                "list, from the run's findings. AI when available, rule engine "
                "otherwise. Never modifies findings.",
        produces=("summary", "priorities"),
        ai_hint="Say what to fix first and why it matters, not what was scanned.",
        mitre="",
    ),
)

CATALOG: dict[str, AttackSpec] = {spec.id: spec for spec in _SPECS}


@dataclass(frozen=True)
class Profile:
    """A named ceiling on what a run may do."""

    name: str
    max_risk: Risk
    include_external: bool
    description: str


PROFILES: dict[str, Profile] = {
    "passive": Profile(
        "passive", Risk.PASSIVE, False,
        "Resolution, headers, certificate, content disclosure. Logs look like browsing.",
    ),
    "safe": Profile(
        "safe", Risk.SAFE, False,
        "Adds port sweep, method probing, TLS protocol support. Stdlib only.",
    ),
    "standard": Profile(
        "standard", Risk.SAFE, True,
        "Adds external template scans (nmap, nuclei) when the binaries exist.",
    ),
    "lab": Profile(
        "lab", Risk.INTRUSIVE, True,
        "Everything up to intrusive. Only ever against your own lab.",
    ),
}

DEFAULT_PROFILE = "safe"


def spec(attack_id: str) -> AttackSpec:
    try:
        return CATALOG[attack_id]
    except KeyError:
        raise KeyError(
            f"unknown technique {attack_id!r} — not in the catalogue. "
            f"Run 'relift list' to see what exists."
        ) from None


def categories() -> list[str]:
    seen = {s.category for s in _SPECS}
    return [c for c in CATEGORY_ORDER if c in seen]


def all_specs() -> list[AttackSpec]:
    return list(_SPECS)


def select(
    profile_name: str = DEFAULT_PROFILE,
    max_risk: Risk | None = None,
    include_external: bool | None = None,
) -> list[AttackSpec]:
    """Return the ordered catalogue subset allowed by a profile and a scope.

    Ordering is (risk tier, category) so the quietest techniques run first and a
    reader can stop at the point where things got loud.
    """
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ValueError(
            f"unknown profile {profile_name!r}; choose from {', '.join(PROFILES)}"
        )

    ceiling = profile.max_risk
    if max_risk is not None and RISK_RANK[max_risk] < RISK_RANK[ceiling]:
        ceiling = max_risk

    want_external = profile.include_external if include_external is None else include_external

    chosen = []
    for item in _SPECS:
        if RISK_RANK[item.risk] > RISK_RANK[ceiling]:
            continue
        if item.external and not want_external:
            continue
        chosen.append(item)

    cat_index = {name: i for i, name in enumerate(CATEGORY_ORDER)}
    idle = len(CATEGORY_ORDER)
    chosen.sort(key=lambda s: (RISK_RANK[s.risk], cat_index.get(s.category, idle), s.id))
    return chosen


def summary_line() -> str:
    total = len(_SPECS)
    ready = sum(1 for s in _SPECS if s.implemented and not s.external)
    ext = sum(1 for s in _SPECS if s.implemented and s.external)
    design = sum(1 for s in _SPECS if not s.implemented)
    return (
        f"{total} techniques · {ready} ready · {ext} external "
        f"· {design} design-only / excluded"
    )
