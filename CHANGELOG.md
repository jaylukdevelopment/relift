# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). While pre-`1.0`, a minor bump may
change behaviour; the scope gate and the catalogue stay compatible within a
minor.

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

[0.2.0]: https://github.com/jaylukdevelopment/relift/releases/tag/v0.2.0
[0.1.0]: https://github.com/jaylukdevelopment/relift/releases/tag/v0.1.0
