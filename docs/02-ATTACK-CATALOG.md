# Relift — Attack Catalogue

Every technique the tool knows about lives here. The catalogue is the contract:
if it is not in this table, Relift cannot run it, cannot plan it, and the AI
analyst cannot suggest it.

The table is maintained by hand next to `src/relift/catalog.py`; run
`relift list` for the live version, and treat any disagreement as a documentation
bug (see [`README.md`](README.md)).

## Risk tiers

| Tier | Meaning | Typical footprint |
|---|---|---|
| `passive` | Reads on the wire. A single request, a DNS lookup, a certificate. | Looks like a browser hit in access logs. |
| `safe` | Actively probes, never mutates. Connection sweeps, handshakes, protocol greetings, OPTIONS. | Clearly a scan in logs and IDS. Annoying, not harmful. |
| `intrusive` | Authenticates with credentials you supply, or sends injection probes. May lock an account or trip a WAF. | Real log entries, possible lockout, possible block. Lab only. |
| `destructive` | Mutates or denies service. | **Never implemented in this tree.** Documented so the tier is not a mystery. |

`intrusive` requires *two* switches: the scope file must set
`allow_intrusive: true` **and** `max_risk: "intrusive"`, and the run must use
`--profile lab`. A single mistake cannot enable it.

Each technique also declares the target families it applies to (`http`, `db`,
`ssh`, `host`). A plan only contains techniques whose families overlap the
target's, so a `postgres://` target never gets `web.*` and an `https://` target
never gets the database probes. Elasticsearch and CouchDB are both `http` and
`db`, and get both sets.

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
| `web.sql_injection_check` | Bounded SQL injection detection | web | intrusive | ✅ implemented | — |
| `web.dir_bruteforce` | Directory brute-force | web | intrusive | 🧩 design-only | — |
| `db.fingerprint` | Database protocol fingerprint | db | safe | ✅ implemented | — |
| `db.security_config` | Database security configuration audit | db | safe | ✅ implemented | — |
| `db.credential_verify` | Held-credential verification | db | intrusive | ✅ implemented | — |
| `system.host_audit` | Local privilege-escalation surface | system | safe | ✅ implemented | — |
| `analysis.attack_chains` | Attack-thread correlation | analysis | passive | ✅ implemented | — |
| `auth.ssh_algorithms` | SSH algorithm audit | auth | safe | ✅ implemented | — |
| `auth.password_policy` | Authentication policy probing | auth | intrusive | 🧩 design-only | — |
| `auth.default_credentials` | Default credential check | auth | intrusive | ⛔ never shipped | — |
| `report.narrative` | Analyst narrative (AI or rule engine) | report | passive | ✅ implemented | — |

✅ implemented · ✅ external = wrapper around an installed tool, reports `skipped`
when the binary is absent · 🧩 design-only = spec written, module deliberately absent
· ⛔ never shipped = permanently excluded, see below.

`24 techniques · 16 ready · 3 external · 5 design-only / excluded`

Two entries never appear in a plan by design: `analysis.attack_chains` runs after
the modules have produced findings, and `report.narrative` is written when a
report is rendered. Both are listed here because both are techniques the tool
performs, and `relift list` is the honest inventory.

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
HTTP status. Deliberately does *not* follow redirects: a `Location` can leave scope.

### `recon.port_scan` — safe
TCP connect scan (`socket.create_connection`) over the operator's port list.
Connect scans are complete handshakes, so they land in the target's logs — that is
intended, this is not a stealth tool. A port is reported when the handshake
completes; a closed port and a filtered one look the same from here (the connection
fails), so they are not distinguished. Banner bytes are captured where the service
speaks first, flattened to printable ASCII before they reach a report, because a
service banner is attacker-controlled text.

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
server accepting only 1.2 is a finding; a server accepting nothing fails the parse
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
`OPTIONS` on the root, plus a `TRACE` probe. Flags declared `PUT`, `DELETE`, `TRACE`
and `CONNECT`. A 405 is a pass, not a finding.

### `web.content_disclosure` — passive
Fetches `/robots.txt` and `/sitemap.xml`. Disallowed entries routinely name admin
panels, staging hosts and backup paths. Reports paths only — it does not go fetch them.

### `web.template_scan` — safe, external
`nuclei` with a hard-coded argument list: `-severity info,low,medium`,
`-no-interactsh`, `-disable-update-check`, `-jsonl`, `-silent` and a rate limit taken
from the scope file. The template set is the installed default set; the guard is the
severity ceiling, not a template allowlist, so a noisy or payload-sending template
that is rated low still runs. Do not treat the output as passive. It is the single
most valuable module and the most dangerous to leave unbounded — hence the hard-coded
flags and the `standard` profile requirement.

### `web.server_audit` — intrusive, external
`nikto` with `-Tuning 123b`: interesting files, misconfiguration, information
disclosure and software identification, with the upload and injection tuning groups
left out. It is read-only, and it is still noisy and slow — it will get you blocked.
Requires `--profile lab` and the external-tool profile (`--depth 5`, or
`include_external` in a plan).

### `web.sql_injection_check` — intrusive
Detection only, one operator-named parameter, hard cap of **8 HTTP requests**.

Three probes, in order, stopping as soon as one proves the point:

1. **error** — append a single quote and look for a database error signature in the
   response body (20-entry table covering MySQL, SQL Server, PostgreSQL, SQLite,
   Oracle and generic ORM/JDBC errors). A signature already present on the baseline
   page proves nothing and is ignored.
2. **boolean** — `<value>' AND '1'='1` against `<value>' AND '1'='2`, comparing both
   bodies to the baseline with a similarity ratio and a length delta. Both guards
   must agree, otherwise no finding.
3. **time** — one delayed read-only query per engine family
   (`SELECT SLEEP(2)`, `SELECT pg_sleep(2)`), measured once against the baseline:
   a response only counts when it is at least 1500 ms slower than the baseline
   (`max(1500, baseline + 1500)` ms). A delayed *error page* is not proof.

What it cannot do, in any configuration: there is no flag, file, environment
variable or config key that supplies a payload string; no set-operator extraction,
no statement stacking, no file or command primitives, no schema enumeration, no
loops over results. The only inputs are `--sqli-url` and `--sqli-param`, and the URL
must be on the authorised target host (`http_get_url` refuses any other host before
opening a socket).

Evidence: `url`, `param`, `injectable`, `styles`, `dbms_hint`, `requests_sent`,
`baseline_ms`. A positive result is `critical` with `CWE-89`; a clean result is
`info` and says the probe set is narrow, not that the parameter is safe.

### `web.dir_bruteforce` — design-only
Would need a wordlist, a rate budget and 404-calibration. Three things that are easy
to get wrong and produce false confidence, so it stays a spec.

---

## db

The reference for this section is [`07-DATABASE-AUDIT.md`](07-DATABASE-AUDIT.md).

### `db.fingerprint` — safe
Speaks each engine's real wire protocol and records what the protocol hands out
before authentication:

| Engine | Exchange | Facts recorded |
|---|---|---|
| PostgreSQL | SSLRequest, StartupMessage v3 | TLS capability, auth type, SASL mechanisms, `server_version` on trust |
| MySQL / MariaDB | server handshake, then `COM_QUIT` | version, capability flags, auth plugin, TLS bit |
| MSSQL | TDS pre-login | build, encryption setting, instance name |
| Redis | `PING`, `INFO server` | version, mode, config file, whether auth is required |
| MongoDB | OP_MSG `hello` | version, max wire version, mechanisms |
| Elasticsearch / CouchDB | `GET /` | version, cluster name, whether the root is open |

Evidence: `engine`, `version`, `build`, `port`, `tls_capable`, `auth_methods`,
`facts`. No login is attempted here; no write command exists in the module.

### `db.security_config` — safe
Turns those facts into a posture: does the listener demand authentication at all,
which method did it negotiate (trust / cleartext / md5 / SCRAM / none), is a
replayable credential exchange on the wire, is TLS offered, is the build past end of
life.

Evidence block, which the correlation engine reads by name: `engine`, `version`,
`port`, `auth_required`, `auth_method`, `cleartext_auth`, `tls_capable`, `eol`.

Severities: no authentication demanded → `critical` for postgres, mysql, mssql and
redis, `high` for Elasticsearch/CouchDB (HTTP answers without a credential), and
`medium` for MongoDB `hello` (unauthenticated by design, so reachability only);
replayable exchange → `medium`, raised to `high` by the separate no-TLS finding when
the socket is plaintext; past end of life → `high`; no TLS → `medium` for
postgres/mysql/mssql, `low` for redis/mongo. Elasticsearch and CouchDB report
transport posture through the `web.*`/`tls.*` modules instead, so
`db.security_config` emits no no-TLS finding for them.

### `db.credential_verify` — intrusive
Verifies credentials the operator **already holds**. One login attempt per
credential, deduplicated by `(engine, username)`, no wordlist, no spray, no retry
loop. Then it reads that account's privilege level (`superuser`, `admin`,
`authenticated`, `unknown`).

Supported flows: PostgreSQL trust/cleartext/MD5/SCRAM-SHA-256, MySQL
`mysql_native_password`, Redis `AUTH` (ACL and pre-ACL shapes), MongoDB
SCRAM-SHA-256. MySQL `caching_sha2_password`/`sha256_password` over a plaintext
socket is reported as "needs TLS or an RSA exchange; not attempted" rather than
faked. MSSQL is not attempted at all: the whole technique is recorded as skipped
with a reason, so no credential is offered to a TDS listener.

The password is never written to a finding, an evidence dictionary, an exception
message or the audit log; server errors are scrubbed because some engines echo part
of the secret back. Evidence: `engine`, `username`, `login_ok`, `privilege_level`,
`roles`, `detail`, `port`.

Requires `--db-creds` **and** `--profile lab` **and** an intrusive scope. Without
the file the module reports `skipped` and says why.

---

## system

### `system.host_audit` — safe
Read-only audit of the machine Relift runs on, in the shape of a privilege-escalation
surface enumeration. Target it with `local://`, which still needs the local address
in scope and still writes an audit line.

Collected, all through `os`/`stat`/`/proc`/`/etc` — no subprocess, no `sudo`, no
writes:

- OS name, kernel release, architecture;
- bounded SUID/SGID walk of `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`,
  `/usr/local/{bin,sbin}`, `/usr/libexec` and `/opt` (depth 3, 400 entries per
  directory, 60 results per list);
- file capabilities decoded from `security.capability`;
- readable `/etc/sudoers` and `/etc/sudoers.d/*` rules;
- world-writable `PATH` entries, plus `/tmp`, `/var/tmp`, `/dev/shm` when the
  sticky bit is missing;
- container runtime socket accessibility (mode, group, `DOCKER_HOST`);
- listening sockets decoded from `/proc/net/tcp` and `/proc/net/tcp6`;
- a coarse kernel-advisory comparison (Dirty COW, fs-context, Dirty Pipe, overlayfs,
  nf_tables ×2).

Evidence: `os`, `kernel`, `arch`, `suid`, `sgid`, `capabilities`, `sudo_rules`,
`world_writable_paths`, `docker_socket`, `docker_socket_detail`, `listening`,
`kernel_cves`.

Findings: SUID/SGID and capabilities → `medium`; broad `NOPASSWD` sudo rules →
`medium`; reachable container socket → `critical`; kernel below a published fix →
`high` at `low` confidence, worded as an advisory because distributions backport;
non-loopback listeners → `info`.

It reports the surface. It never claims an exploit, never runs one, and never
changes a file. Non-Linux hosts get a single `info` finding saying the collectors
are not portable.

---

## analysis

### `analysis.attack_chains` — passive
Runs after every executed scan. Takes the findings that exist in the run and joins
them into multi-stage threads, naming the stage an attacker would have to get
through and the single control that breaks the path. It sends no traffic and reads
no new data; it cannot invent a stage that no finding supports.

| Thread | Triggered by | Severity |
|---|---|---|
| `thread.datastore-no-auth` | datastore answered without authentication | critical |
| `thread.web-to-datastore` | injectable parameter + a datastore on the same target | critical |
| `thread.valid-credential` | verification succeeded (critical for superuser) | high/critical |
| `thread.container-escape` | runtime socket reachable | critical |
| `thread.datastore-cleartext-auth` | replayable credential exchange | high |
| `thread.datastore-eol` | end-of-life build answering | high |
| `thread.plaintext-session` | plaintext HTTP + missing HSTS | medium/high |
| `thread.writable-admin-surface` | write methods + advertised admin paths | medium/high |
| `thread.certificate-mitm` | self-signed or expired certificate | medium |
| `thread.local-privilege-escalation` | SUID/capabilities/sudo/advisory present | medium/high |

`relift chains` prints them for a stored run; `relift scan` includes them in the
run output, the text report, the Markdown report and `run.json`.

---

## auth

### `auth.ssh_algorithms` — safe
Reads the identification string and the server's KEXINIT name-lists directly over
TCP — the same information `ssh -vv` shows before authentication. No key exchange is
completed, no user is named, no password or key is presented, no channel is opened.

Flags deprecated KEX (`group1-sha1`, `group14-sha1`, `gss-group1-sha1-*`), host keys
(`ssh-dss`, `ssh-rsa`), CBC/RC4/blowfish ciphers, and `hmac-md5`/`hmac-sha1-96`/
`umac-64`. Evidence: `banner`, `software`, `kex`, `host_keys`, `ciphers`, `macs`,
`deprecated`, `port`.

Deprecated algorithms → `medium` with `CWE-327`. An old banner → `low` at
`medium` confidence, because a banner is a claim by the server and not proof of the
running build.

### `auth.password_policy` — design-only
Would probe a handful of accounts with a rate limit and lockout awareness. Not
written: lockout behaviour is a real availability risk and needs a correlation
engine before it can be run safely even in a lab. `db.credential_verify` is a
different thing — it presents one credential you already own, once.

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
2. Add an `AttackSpec` to `catalog.py` with `implemented=False` and its `families`.
3. Write the module in `modules/`, register it, flip `implemented=True`.
4. Add a row here. If you skip this step, the technique is not really in the tool.
5. If it produces evidence another technique could chain with, add the rule to
   `chains.py` and a row to the analysis table above.

Tier-D (destructive) techniques are not accepted, in any form, including as "opt-in
flags for advanced users".
