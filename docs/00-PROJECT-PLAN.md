# Relift — Project Plan

| Field | Value |
|---|---|
| Project | Relift |
| Company | Pixelcity |
| Developer / owner | Jay |
| Version | 0.1.0 (internal) |
| Status | Scaffold + working engine, catalogue-driven |
| License | Proprietary for now, open source later (see `LICENSE`) |

---

## 1. Problem

Testing your own infrastructure against realistic attack techniques is normally a
pile of shell history: one `nmap` here, a `nuclei` template there, a `curl -I` to
check headers, a browser to look at the certificate. The output is scattered, the
ordering is improvised, and nothing records *what was tested and what was not*.

Relift turns that pile into one command with one output. The catalogue is the
product: it states exactly which techniques exist, how invasive each one is, and
which of them have actually been run against a given target.

## 2. Goals

| # | Goal | Measured by |
|---|---|---|
| G1 | One CLI entry point for the whole assessment loop | `relift list → plan → scan → report` end-to-end on a lab host |
| G2 | The tool documents itself | `relift list` shows every technique, its risk tier and status |
| G3 | Deny-by-default execution | Zero module runs without a matching, unexpired scope entry |
| G4 | Optional AI, never required | Full run with `--no-ai`, byte-identical findings to an AI-enabled run |
| G5 | Swap AI providers in one flag | Same engine output across Ollama / OpenAI / offline |
| G6 | Reconstruct any past run | Per-run JSON artefact + append-only audit log |
| G7 | Extensible without forks | A new technique is one file plus one catalogue entry |

## 3. Non-goals (deliberate, permanent)

- **No exploitation of third-party systems.** Ever. Not a feature.
- **No destructive capability** in the shipped tree: no denial-of-service, no data
  tampering, no payload delivery, no persistence, no lateral movement automation.
- **No credential brute-force engine.** The catalogue documents the technique class
  and the module stays unimplemented by design (see `02-ATTACK-CATALOG.md`, tier D).
- **Not a hosted service / SaaS.** Local CLI only.
- **Not a compliance scanner.** It does not try to certify anything.

## 4. Users

1. **Jay** — primary. Runs it against Pixelcity infrastructure and a homelab.
2. **Pixelcity engineers** — run it before shipping a service, read the report.
3. **Future self / contributors** — after open-sourcing, need the catalogue and the
   scope model to be obvious within ten minutes.

## 5. Workstreams

| WS | Name | Scope | Owner |
|---|---|---|---|
| WS-1 | **Core engine** | Catalogue, scope gate, runner, findings model, audit | Jay |
| WS-2 | **Modules** | Passive → active techniques, stdlib implementations | Jay |
| WS-3 | **External wrappers** | nmap / nuclei / whatweb / nikto, fixed arg templates | Jay |
| WS-4 | **AI layer** | Provider abstraction, local + cloud adapters, rule engine fallback | Jay |
| WS-5 | **Reporting** | Terminal, Markdown, JSON; AI narrative | Jay |
| WS-6 | **Safety & legal** | Scope schema, authorisation gate, excluded-class policy, docs | Jay |
| WS-7 | **Packaging & release** | pyproject, `relift` entry point, versioning, changelog | Jay |

## 6. Milestones

### M1 — Walking skeleton (done in this scaffold)
- [x] Repository layout, packaging, `relift` console script
- [x] 16-entry attack catalogue with risk tiers and MITRE mapping
- [x] `list`, `providers`, `plan`, `scan`, `report`, `init-scope` commands
- [x] Scope file with allowlist / denylist / CIDR / expiry / risk ceiling
- [x] Dry-run default; `--execute` required to send packets
- [x] Stdlib modules: DNS, TCP connect scan, HTTP fingerprint, headers, methods,
      robots/sitemap, TLS certificate, TLS protocol support
- [x] AI abstraction with Ollama, LM Studio / llama.cpp, OpenAI, Anthropic,
      OpenRouter, Groq and an offline rule engine
- [x] JSONL audit log + per-run JSON artefact
- **Exit criteria:** `relift list` renders; `scan --execute` runs at least six
  modules against a local service; `--no-ai` produces the same findings as `--ai none`.

### M2 — Depth (next)
- [ ] Findings correlation: merge header + TLS + method findings into per-host posture
- [ ] Severity scoring with CVSS-style vector strings from the module, not the AI
- [ ] HTML report, single self-contained file
- [ ] `relift diff runA runB` — what changed since last sweep
- [ ] Config file (`relift.config.json`) with profiles and per-engagement defaults
- **Exit criteria:** two consecutive runs produce a readable diff; HTML opens offline.

### M3 — Breadth
- [ ] Subdomain enumeration from a passive source (no brute-force) as a module
- [ ] SMB / LDAP / SSH handshake fingerprinting for the internal network
- [ ] Discovery mode: enumerate live hosts on an in-scope CIDR before scanning
- [ ] Parallel execution with a global request budget
- **Exit criteria:** internal /24 sweep completes under the configured request budget
  without tripping any scope rule.

### M4 — Analyst quality
- [ ] Provider-side structured output (JSON mode) for triage, with schema validation
- [ ] Local model recommendation table (VRAM vs. quality) in `04-AI-PROVIDERS.md`
- [ ] Prompt-injection defence: banner/title text is data, never instructions
- **Exit criteria:** a hostile banner containing instructions cannot make the analyst
  emit a non-catalogue module or a shell string — covered by a test.

### M5 — Open-source release (decision point)
- [ ] External review of the authorisation gate
- [ ] Relicense (Apache-2.0 or AGPL-3.0 — decision deferred to Jay)
- [ ] CONTRIBUTING with the "no tier-D modules" rule stated up front
- **Exit criteria:** a stranger can run the quickstart in ten minutes and cannot
  accidentally scan a host outside a scope file.

## 7. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Tool used against a non-owned host | Legal exposure, harm to others | Mandatory scope file, deny-by-default, `--execute` flag, prominent docs |
| Scope file authored carelessly (`0.0.0.0/0`) | Accidental mass scanning | Range-size guard: refuse CIDRs broader than /22 without `--i-know` |
| AI hallucinates a technique or a shell command | Unsafe or misleading action | Catalogue-ID whitelist, no command generation, output validated before use |
| Local model produces confident nonsense | Bad report | Findings come from modules; AI only rephrases, and a `--no-ai` run is always possible |
| External tool version drift | Wrapper breaks | Fixed flag templates, fail soft, record the missing binary as a skipped execution |
| Own tool flagged by IDS/SOC on company network | Noise, false alarm | Tier classification + rate limits + "announce your own sweeps" note in WS-6 docs |

## 8. Success metrics (first 90 days)

- Zero runs against hosts not in a scope file (audit log is the source of truth).
- `list → scan → report` on a fresh lab VM in under 5 minutes from clone.
- Every finding traceable to a catalogue ID and an execution record.
- Full offline operation verified: airplane mode, `--no-ai`, nothing breaks.

## 9. Working agreements (single-developer, but future-proof)

- A technique is not "in" the tool until it has a catalogue entry with a risk tier.
- Any module that mutates target state is rejected at review, not "temporarily disabled".
- Docs describe behaviour that exists. Design-only entries say so in the same table.
- Credits stay explicit: Jay / Pixelcity in `__init__`, `pyproject.toml`, README, CLI banner.

## 10. Immediate next actions

1. Run `relift list` and prune anything that does not earn its risk tier.
2. Spin a deliberately vulnerable container in the lab and run M1's exit criteria.
3. Decide the module contract for M2 correlation before adding more modules.
4. Pick the local model the analyst will actually use day to day.
