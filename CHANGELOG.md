# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). While pre-`1.0`, a minor bump may
change behaviour; the scope gate and the catalogue stay compatible within a
minor.

## [0.4.0] — 2026-11-11

### Added

- The `code` target family and `relift code PATH`: audit a directory with no scope
  file and no socket to the target. Vendored, generated and binary trees are
  skipped; the audit line records that only local files were read.
- `code.secrets`: fixed credential patterns (AWS, GitHub, GitLab, Slack, Google,
  Stripe, private keys, JWTs, password assignments). Every value is redacted before
  it reaches a finding, artefact or report; placeholders, passwd-shaped data and
  `os.environ` references are not reported.
- `code.dangerous_sinks`: SQL built by concatenation, `shell=True`, `os.system`,
  `eval`/`exec`, unsafe `pickle`/`yaml`, each labelled as a sink rather than a
  proven vulnerability.
- `code.dependencies`: pinned versions from nine manifest formats against the OSV
  database (`querybatch`, no key). The batch response carries ids only, so matched
  advisories are then fetched individually — capped at 25, concurrently — for real
  severity, summary and fixed version. Unpinned ranges are reported separately;
  `--no-osv` inventories without contacting anything; a failed lookup is an `info`
  finding, never a pass.
- `web.path_traversal`: six fixed payloads against the one operator-named parameter;
  a hit reports the `/etc/passwd` or `win.ini` marker as `critical` and never the
  file contents.
- `web.open_redirect`: five fixed payloads aimed at `relift-probe.invalid`; only an
  exact host match in `Location` counts, so same-site routing stays silent.
- Proof of impact for SQL injection: once detection succeeds, fixed error-based cast
  payloads make the engine return its own version, which is recorded as
  `proof_of_impact` — evidence that the parameter reads data, without reading a row.
- Coverage reporting: every run records what was planned and renders tested, skipped
  and not-planned techniques with reasons, in text, markdown and JSON.
- `--param-url` / `--param` as aliases for `--sqli-url` / `--sqli-param`, since one
  parameter point now feeds three techniques.

### Changed

- An authored `attack` scope includes the target's own port in the default sweep;
  `attack host:8099` previously never probed 8099.
- Advisory severity is chosen by rank, not string order, and a `CRITICAL` advisory is
  reported as `critical` rather than folded into `high`.

### Fixed

- Dogfooding `relift code .` on the repository: `.relift-runs` artefacts were scanned
  as source, `regex.exec(` was read as code execution, `addopts = "-q"` was read as a
  dependency, a passwd-line string was treated as a credential, and a bare version in
  `pyproject.toml` was accepted as pinned.
- Sink matching is limited to source files, so a SQL snippet inside a Markdown page
  is no longer reported as a dangerous sink.
- Documented example keys (AWS's `AKIAIOSFODNN7EXAMPLE`) and typed-out alphabet runs
  are no longer reported as secrets.

## [Unreleased]

### Added

- `docs/11-FAQ.md`: install failures, scope refusals, missing techniques at a
depth, and where every artefact lives.
- `tests/test_docs.py`: every relative documentation link resolves, every document
  is indexed, and no document points at a hostname that does not exist.
- An issue template pair, a pull-request template, `CODE_OF_CONDUCT.md`,
  `SECURITY.md` and the Dependabot configuration for a public repository.
- A screenshot of the desktop findings view in the README.

### Changed

- The repository is public and source-available; `LICENSE` spells out the limited
  permission, and the module docstring no longer calls the build internal.
- `docs/06-CLI-REFERENCE.md` matches the code again: depth `4` excludes external
  tools, `init-scope` defaults to `127.0.0.1` and `::1`, the `relift list` sample
  puts the count line where the code prints it, and argparse's own `2` is
  distinguished from a scope refusal.
- `docs/02-ATTACK-CATALOG.md`, `docs/07-DATABASE-AUDIT.md` and
  `docs/08-DESKTOP.md` now describe what the modules actually do (nuclei severity
  cap versus template allowlist, nikto `-Tuning 123b`, Elasticsearch severity, the
  splash asset, and how the desktop token can be read with `--debug`).
- `web.server_audit`'s catalogue summary names the nikto tuning groups it uses and
  the profile plus external-tool requirement.

### Fixed

- `relift.api`'s docstring said four static files; three are served.

## [0.3.0] — 2026-11-11

### Added

- `recon.mail_posture`: SPF, DMARC and MX for the target's name — the part of an
  attack surface that never appears in a port scan. Two to four read-only resolver
  queries, none against the target. A `www.` target reads the parent name's policy
  instead of reporting a false absence.
- `web.cors_policy`: one request with an `Origin` from a reserved `.invalid` name.
  A reflected origin **with** credentials is `high`; reflected without credentials
  `medium`; `*` with credentials is a `low` config smell because browsers reject
  that pair; `*` without credentials is informational.
- `web.cookie_flags`: audits every `Set-Cookie` for `Secure`, `HttpOnly`,
  `SameSite` and `Domain` scope, calling out session-looking cookie names
  separately. Cookies are parsed, never decoded or replayed.
- `tls.cipher_preference`: implemented without `sslscan`. One pinned TLS 1.2
  handshake per legacy suite (RC4, 3DES, NULL, export, AES-CBC) records which are
  still accepted, plus the suite the default handshake negotiates. Suites this
  OpenSSL cannot offer are reported as unavailable, not as refused by the server.
- `web.dir_bruteforce`: implemented as a bounded probe over a fixed 26-path list,
  40 requests maximum, 404 calibration first. It aborts on a soft-404 instead of
  reporting every miss as a hit, ignores trailing-slash routing redirects, and
  reports `401`/`403` as “exists, access-controlled” rather than exposure.
- Two attack-thread rules: `thread.cors-session-theft` (reflected origin with
  credentials plus an under-protected session cookie) and `thread.mail-spoofing`
  (no enforced SPF/DMARC on a domain that accepts mail).
- `relift doctor [TARGET] [--json]`: read-only environment check — interpreter,
  config in use, writable scope/run/audit paths, external binaries, AI provider
  and, given a target, what it resolves to. Sends no traffic.
- `relift explain ID [--json]`: one technique in full — tier, families, the
  profiles that plan it, whether a module is wired up, and what it will not do.
- `relift list --search TEXT`.
- `relift attack TARGET --dry-run`: authorise and plan, then send nothing.

### Changed

- `plan`, `scan` and `attack` accept the target as a positional argument as well
  as `--target`; the flag keeps working for existing scripts.
- `relift` with no command prints a quick-start block before the help text, and the
  help epilog carries examples.
- The port sweep runs its port list in a small thread pool under the same
  rate-limit lock. Six ports against a host with filtered ports went from ~40s to
  ~13s in the pixelcity.dev run; the budget is unchanged.
- `web.headers` now distinguishes `Content-Security-Policy-Report-Only` from no
  policy at all: report-only collects violations and blocks nothing, and the
  finding says so instead of implying the header is absent.
- The catalogue is 27 techniques: 21 ready, 3 external, 3 design-only/excluded.
  `tls.cipher_preference` and `web.dir_bruteforce` left the design-only set.

### Fixed

- `modules/dnsproto.py`: the name parser returned an offset one byte early at the
  terminating root label, shifting every field after the question. Caught by the
  new packet tests before it reached a resolver.
- `relift doctor` checked only one directory level up, so `/root/.relift/scopes`
  on a fresh host was reported as unwritable. It now checks the nearest existing
  ancestor, matching `mkdir -p` semantics.
- The host audit counted a merged-`/usr` binary twice (`/bin/mount` and
  `/usr/bin/mount`) and described every `ALL=(ALL)` sudo rule as passwordless.
  Both inflated the report; the count is now per binary and the two claims are
  reported separately.

## [0.2.0] — 2026-11-07

### Added

- `relift attack --target HOST --depth 1-5`: authors a 24-hour scope for exactly
  that host, then plans and runs. Depth maps to passive, safe, standard
  (external tools), intrusive and full.
- Correlated attack threads (`analysis.attack_chains`, `relift chains`): findings
  joined into multi-stage paths with the control that breaks each one.
- Database protocol modules spoken directly over the socket: PostgreSQL
  (startup, SCRAM, security config), MySQL/MariaDB, MSSQL/TDS, Redis, MongoDB,
  Elasticsearch and CouchDB. Safe fingerprinting plus one-attempt credential
  verification at the intrusive tier.
- SSH algorithm audit from the KEXINIT exchange.
- Local host audit: SUID/SGID, capabilities, sudo rules, container sockets,
  listening ports, kernel advisory pass.
- Desktop application for Windows and Linux: loopback-only server, per-launch
  token, GTK/WebView2 window, splash, and the same engine as the CLI.
- PyInstaller builds for CLI and desktop, with `.sha256` sidecars, published by
  the `v*` tag workflow.
- Hosted Linux downloads and a checksum-verifying `install.sh` at
  <https://pixelcity.dev/lab/relift/install.sh>.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md` and a release guide.

### Changed

- `relift chains --run latest` and `relift report --run latest` accept `latest`
  as the newest run instead of looking for a run with that literal name.
- Desktop console rebuilt around the authorisation itself: ceiling, intrusive
  flag, allow-list size, expiry and scope hash above the target.
- Linux desktop bundles no GLib/GTK/libstdc++ copies; it uses the host's
  libraries, which fixes WebKitGTK load failures on current distributions
  (`CXXABI_1.3.15`, `g_once_init_enter_pointer`, `MOUNT_2_40`).

### Fixed

- Catalogue CI assertion no longer hard-codes the technique count; it now checks
  that every runnable catalogue entry has a module.
- Release workflow pins PyGObject 3.50 on Linux, because 3.52+ requires
  girepository-2.0, which Ubuntu 22.04 does not ship.

## [0.1.0] — 2026-11-07

### Added

- Initial public build of the scope-gated orchestrator: catalogue, scope file
  with expiry and deny rules, dry-run planning, HTTP/TLS/DNS/web modules,
  external `nmap`/`nuclei`/`nikto` wrappers, AI analyst providers with an offline
  rule-engine fallback, audit log and run artefacts, Markdown/JSON reports.
- Single-file CLI builds for Linux and Windows, a portable `.pyz`, and an
  sdist/wheel.

[0.3.0]: https://github.com/jaylukdevelopment/relift/releases/tag/v0.3.0
[0.2.0]: https://github.com/jaylukdevelopment/relift/releases/tag/v0.2.0
[0.1.0]: https://github.com/jaylukdevelopment/relift/releases/tag/v0.1.0
