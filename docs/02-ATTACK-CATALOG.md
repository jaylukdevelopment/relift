# Relift — Attack Catalogue

Every technique the tool knows about lives here. The catalogue is the contract:
if it is not in this table, Relift cannot run it, cannot plan it, and the AI
analyst cannot suggest it.

The table is generated from `src/relift/catalog.py` — run `relift list`
for the live version.

## Risk tiers

| Tier | Meaning | Typical footprint |
|---|---|---|
| `passive` | Reads on the wire. A single request or a DNS lookup. | Looks like a browser hit in access logs. |
| `safe` | Actively probes, never mutates. Connection sweeps, handshakes, OPTIONS. | Clearly a scan in logs and IDS. Annoying, not harmful. |
| `intrusive` | Loads or persists template sets, brute-forces paths, probes auth policy. | Triggers WAF/IDS rules, real log noise, possible lockouts. Lab only. |
| `destructive` | Mutates or denies service. | **Never implemented in this tree.** Documented so the tier is not a mystery. |

`intrusive` requires *two* switches: the scope file must set `allow_intrusive: true`
**and** the run must use `--profile lab`. A single mistake cannot enable it.

## The catalogue

| ID | Technique | Category | Tier | Status | Requires |
|---|---|---|---|---|---|
| `recon.dns` | DNS resolution & address inventory | recon | passive | ✅ implemented | — |
| `recon.http_fingerprint` | HTTP fingerprint (server, title, framework) | recon | passive | ✅ implemented | — |
| `recon.port_scan` | TCP connect sweep | recon | safe | ✅ implemented | — |
| `recon.service_scan` | Service/version detection | recon | safe | ✅ external | `nmap` |
| `recon.passive_subdomains` | Passive subdomain inventory | recon | passive | 🧩 design-only | — |
| `tls.certificate` | Certificate inspection | tls | passive | ✅ implemented | — |
| `tls.protocol_support` | TLS version support probe | tls | safe | ✅ implemented | — |
| `tls.cipher_preference` | Cipher suite preference | tls | safe | 🧩 design-only | `sslscan` |
| `web.headers` | Security header audit | web | passive | ✅ implemented | — |
| `web.methods` | HTTP method exposure | web | safe | ✅ implemented | — |
| `web.content_disclosure` | robots.txt / sitemap disclosure | web | passive | ✅ implemented | — |
| `web.template_scan` | Template scan, safe severities only | web | safe | ✅ external | `nuclei` |
| `web.server_audit` | Server misconfiguration audit | web | intrusive | ✅ external | `nikto` |
| `web.dir_bruteforce` | Directory brute-force | web | intrusive | 🧩 design-only | — |
| `auth.ssh_algorithms` | SSH algorithm audit | auth | safe | 🧩 design-only | `ssh-audit` |
| `auth.password_policy` | Authentication policy probing | auth | intrusive | 🧩 design-only | — |
| `auth.default_credentials` | Default credential check | auth | intrusive | ⛔ never shipped | — |
| `report.narrative` | Analyst narrative (AI or rule engine) | report | passive | ✅ implemented | — |

✅ implemented · ✅ external = wrapper around an installed tool, reports `skipped`
when the binary is absent · 🧩 design-only = spec written, module deliberately absent
· ⛔ never shipped = permanently excluded, see below.

> MITRE mapping in the code is indicative, not authoritative. It exists so a report
> can be read next to an ATT&CK matrix, not to claim precision.

---

## recon

### `recon.dns` — passive
Resolves A/AAAA records via `socket.getaddrinfo`, reports the address inventory and
whether the hostname resolves to loopback/RFC1918/CGNAT space. Baseline for every
later module: you cannot reason about a target you cannot address.

### `recon.http_fingerprint` — passive
One GET on the root path. Extracts `Server`, `X-Powered-By`, the page title, and the
HTTP status. Deliberately does *not* follow redirects into other hosts unless that
host is in scope.

### `recon.port_scan` — safe
TCP connect scan (`connect_ex`) over the operator's port list. Connect scans are
complete handshakes, so they land in the target's logs — that is intended, this is
not a stealth tool. Open/closed/filtered per port, with banner bytes where the
service speaks first.

### `recon.service_scan` — safe, external
`nmap -sV -Pn --version-light` over the same port list. Version detection is what
turns "port 22 is open" into "OpenSSH 8.4". Skipped if `nmap` is not on `PATH`.

### `recon.passive_subdomains` — design-only
Intended source: certificate transparency logs, read-only. No DNS brute-force, ever —
brute-forcing names against a third party's authoritative server is the single
easiest way to become someone else's incident.

---

## tls

### `tls.certificate` — passive
Handshake, then parse the peer certificate: subject, issuer, SANs, validity window,
days-to-expiry flag, self-signed detection, and whether the hostname actually appears
in the SAN list. This is the module that catches the renewal nobody did.

### `tls.protocol_support` — safe
Attempts handshakes pinned to TLS 1.2 and TLS 1.3 and reports which negotiate. A
server accepting only 1.2 is a finding; a server accepting 1.0 fails the parse
outright on modern OpenSSL, which is itself informative.

### `tls.cipher_preference` — design-only
Needs `sslscan` (it exposes the cipher list and preference order in one pass). The
module is a thin parser; it is not written because the parsed output shape needs to
be pinned per `sslscan` version first.

---

## web

### `web.headers` — passive
Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Missing CSP and
missing HSTS on an HTTPS origin are `medium`; the rest are `low`/`info`. Reports what
was present, not a score.

### `web.methods` — safe
`OPTIONS` on the root and `/`, plus a `TRACE` probe. Flags declared `PUT`, `DELETE`,
`TRACE` and `CONNECT`. A 405 is a pass, not a finding.

### `web.content_disclosure` — passive
Fetches `/robots.txt` and `/sitemap.xml`. Disallowed entries routinely name admin
panels, staging hosts and backup paths. Reports paths only — it does not go fetch them.

### `web.template_scan` — safe, external
`nuclei` restricted to informational/low/medium severities and *no* template
categories that send payloads. Fixed template selection, `-no-interactsh`, rate
limited. The single most valuable module and the most dangerous to leave unbounded —
hence the hard-coded flags.

### `web.server_audit` — intrusive, external
`nikto` with tuning restricted to configuration checks. Noisy, slow, and it will get
you blocked. Requires `--profile lab`.

### `web.dir_bruteforce` — design-only
Would need a wordlist, a rate budget and 404-calibration. Three things that are easy
to get wrong and produce false confidence, so it stays a spec.

---

## auth

### `auth.ssh_algorithms` — design-only
`ssh-audit` reports deprecated KEX/ciphers/MACs in one pass. Wrapper pending; the
technique is documented so it is not smuggled in as an "misc" feature later.

### `auth.password_policy` — design-only
Would probe a handful of accounts with a rate limit and lockout awareness. Not
written: lockout behaviour is a real availability risk and needs the correlation
engine from M2 before it can be run safely even in a lab.

### `auth.default_credentials` — never shipped
Vendor default credential checking is the closest thing to an actual break-in on this
list. It is permanently out of scope for this repository, in every profile,
regardless of flags. If you need it in a lab, that is a separate tool with a separate
review.

---

## report

### `report.narrative` — passive
Not a network technique. Takes the run's findings and produces prose: an executive
summary, a grouped technical section, and a "what to fix first" list. Uses the
configured AI provider when there is one, the deterministic rule engine otherwise.
Never modifies findings.

---

## Adding a technique

1. Pick the tier first. If you cannot name the failure mode it causes, it is not ready.
2. Add an `AttackSpec` to `catalog.py` with `implemented=False`.
3. Write the module in `modules/`, register it, flip `implemented=True`.
4. Add a row here. If you skip this step, the technique is not really in the tool.

Tier-D (destructive) techniques are not accepted, in any form, including as "opt-in
flags for advanced users".
