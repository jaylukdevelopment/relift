# Relift — Roadmap

Phases, not dates. A phase is done when its exit criteria are met, not when the
calendar says so.

## v0.1 — Walking skeleton (shipped)

**Scope:** engine, catalogue, scope gate, stdlib modules, AI abstraction, reporting.

- [x] Packaging, `relift` entry point, `python -m relift` fallback
- [x] Catalogue with tiers, MITRE hints, implementation status
- [x] Scope gate: allow/deny, CIDR, wildcard, expiry, risk ceiling, wide-range guard
- [x] Dry-run default; `--execute` required
- [x] Stdlib modules across recon / tls / web
- [x] External wrappers for `nmap`, `nuclei`, `nikto` with fixed argv templates
- [x] Local, cloud and offline provider matrix behind one interface
- [x] Audit JSONL + per-run artefact + text/markdown/json rendering

**Exit:** `list` renders; a lab host produces ≥6 executions; `--no-ai` findings are
identical to an AI run.

## v0.2 — Depth (shipped in 0.2.0)

**Theme:** make one run worth reading twice, and let it read the things that hold
the data.

- [x] **Database auditing**: real wire-protocol fingerprint and security-posture
      checks for PostgreSQL, MySQL/MariaDB, MSSQL, Redis, MongoDB,
      Elasticsearch and CouchDB (`db.fingerprint`, `db.security_config`)
- [x] **Held-credential verification**: one attempt per operator-supplied
      credential, plus privilege level per engine (`db.credential_verify`, lab only)
- [x] **Bounded SQL injection detection**: error, boolean and time probes against
      one named parameter, 8-request cap, no extraction (`web.sql_injection_check`)
- [x] **Local privilege-escalation surface audit**: SUID/SGID, capabilities, sudo
      rules, container sockets, listening sockets, kernel advisory pass
      (`system.host_audit`, read-only, Linux)
- [x] **Attack threads**: findings correlated into multi-stage paths with an explicit
      break point (`analysis.attack_chains`, `relift chains`)
- [x] **Target families**: `db://`, `ssh://`, `local://` targets, plans filtered by
      family so a datastore is never sent an HTTP template scan
- [x] **SSH algorithm audit** implemented natively — the `ssh-audit` dependency is
      gone
- [x] **Desktop application**: loopback-only API, native window via `pywebview`,
      browser fallback, `relift desktop` / `relift-desktop`
- [x] Terminal, Markdown and JSON reports carry the threads

**Exit:** a lab datastore yields a critical exposure finding and a thread; a held
credential is verified once and graded; the desktop app runs a scan through the same
scope gate as the CLI.

## v0.3 — Coverage without dependencies (this tree, 0.3.0)

**Theme:** the techniques that matter should not wait for an external binary.

- [x] **Mail posture**: SPF, DMARC and MX graded from read-only resolver queries
      (`recon.mail_posture`)
- [x] **CORS policy audit**: reflected origin with and without credentials
      (`web.cors_policy`)
- [x] **Cookie flag audit**: Secure, HttpOnly, SameSite, Domain scope, session
      cookies called out (`web.cookie_flags`)
- [x] **TLS cipher acceptance** from the standard library; the `sslscan`
      dependency is gone (`tls.cipher_preference`)
- [x] **Bounded well-known-path probe**: fixed 26-path list, 40 requests,
      404 calibration, soft-404 abort (`web.dir_bruteforce`)
- [x] **Threads** for CORS session theft and mail spoofing
- [x] **First-run CLI**: `doctor`, `explain`, `list --search`, `attack --dry-run`,
      positional targets
- [x] **Port sweep** runs in a small thread pool under the same rate-limit lock

**Exit:** a host with no nmap/nuclei/nikto installed still produces a run with these
findings, and every claim the modules make is backed by a test. Met on pixelcity.dev
(no external binaries present).

## v0.4 — Proof, not just detection (this tree, 0.4.0)

**Theme:** a finding should say what an attacker could actually do, and a short
report should say what was not tested.

- [x] **Codebase target family**: `relift code PATH` audits files only — no scope
      file, no socket, its own audit line
- [x] **Hardcoded secrets** with redaction before the value reaches any output
- [x] **Dangerous sinks**, labelled as sinks rather than exploits
- [x] **Dependency advisories** from OSV, pinned versions only, with per-advisory
      severity, summary and fixed version (batch ids, then capped detail lookups)
- [x] **SQL injection proof of impact**: error-based cast returns the engine version
- [x] **Path traversal proof**: fixed payloads, `/etc/passwd`/`win.ini` marker only
- [x] **Open redirect proof**: reserved `.invalid` host, exact `Location` match
- [x] **Coverage report** in text, markdown and JSON; the run record stores what was
      planned so skipped techniques are named with a reason
- [x] **Port sweep includes the target's own port** in an authored attack scope

**Exit:** on the lab target, injection, traversal and redirect each produce a
critical/high finding carrying proof; `relift code` finds a real CVE with its fixed
version; and a run against pixelcity.dev lists 32 techniques with 26 tested and the
rest explained. Met.

## v0.3.1 — Breadth

**Theme:** internal network, not just one URL.

- [ ] **Multi-target runs**: `--targets FILE` with one scope check per host, one run
      artefact per host, one combined report
- [ ] **Passive subdomain inventory** from certificate transparency logs
      (`recon.passive_subdomains`; still no DNS brute-force)
- [ ] **Scheduled assessments**: a documented `cron`/systemd-timer recipe plus a
      `--fail-on <severity>` exit code for CI
- [ ] **`relift diff <runA> <runB>`** — new / fixed / changed findings and threads
- [ ] **HTML report**, single self-contained file, opens offline
- [ ] Whole-plan parallel execution sharing one global rate budget (the port sweep
      already does this inside one module)
- [ ] Test suite: scope matcher, target parsing, runner, chains rules, each module
      against a local fixture server

**Exit:** a /24 sweep stays inside the budget, every host gets its own plan and
artefact, and two sweeps a week apart produce a diff a human can act on.

## v0.4 — Analyst quality

**Theme:** the AI should be interesting, not merely present.

- [ ] JSON-mode structured triage with schema validation and repair
- [ ] Prompt-injection test suite (hostile banner → analyst must ignore it)
- [ ] Per-provider quality harness on a fixed finding corpus
- [ ] Redaction pass on by default for cloud providers
- [ ] Chain-aware narration: the model is given the threads and their break points,
      not just the finding list

**Exit:** the injection suite passes for all providers; a model that fails schema
validation falls back instead of guessing.

## v0.5 — Hardening

- [ ] Fault injection: module raises, DNS fails mid-run, provider dies
- [ ] Windows path/encoding pass for the host audit (currently Linux-only by design)
- [ ] Security review of the scope gate by someone who did not write it
- [ ] Security review of the desktop API surface (token handling, Origin check, job
      lifetime)
- [ ] Fuzz the protocol parsers in `dbproto.py` with malformed frames

**Exit:** the gate cannot be bypassed by any documented or documented-adjacent route,
and a malformed database frame produces a finding, not a traceback.

## v1.0 — Release decision

- [ ] External review of `03-RULES-OF-ENGAGEMENT.md`
- [ ] Relicense (Apache-2.0 vs AGPL-3.0 — Jay's call)
- [ ] CONTRIBUTING with the tier-D exclusion stated as policy
- [ ] Public docs site or a very good README

**Exit:** a stranger clones, reads for ten minutes, and cannot accidentally scan a
host they do not own.

---

## Explicitly not on the roadmap

Denial of service · exploit delivery · credential brute-force and spraying ·
default-credential checking · data extraction or dumping · persistence · lateral
movement · exfiltration. These are excluded by policy, not deferred by priority. See
`03-RULES-OF-ENGAGEMENT.md` §7.

## Idea parking lot

Things worth writing down, not worth promising:

- A `--json` output shape stable enough to feed a small dashboard
- Signed scope files (ed25519) so a scope cannot be edited after sign-off
- Per-module request budgets instead of one global rate
- A "pre-flight" mode that reports what *would* be skipped and why, before `--execute`
- Comparison against a baseline posture file ("this is what my lab looked like last month")
- Chain rules contributed as data (a small predicate language) instead of Python
