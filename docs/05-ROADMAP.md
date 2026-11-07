# Relift — Roadmap

Phases, not dates. A phase is done when its exit criteria are met, not when the
calendar says so.

## v0.1 — Walking skeleton (this tree)

**Scope:** engine, catalogue, scope gate, stdlib modules, AI abstraction, reporting.

- [x] Packaging, `relift` entry point, `python -m relift` fallback
- [x] 18-entry catalogue with tiers, MITRE hints, implementation status
- [x] Scope gate: allow/deny, CIDR, wildcard, expiry, risk ceiling, wide-range guard
- [x] Dry-run default; `--execute` required
- [x] 10 stdlib modules across recon / tls / web
- [x] External wrappers for `nmap`, `nuclei`, `nikto` with fixed argv templates
- [x] 7 AI providers + offline rule engine behind one interface
- [x] Audit JSONL + per-run artefact + text/markdown/json rendering

**Exit:** `list` renders; a lab host produces ≥6 executions; `--no-ai` findings are
identical to an AI run.

## v0.2 — Depth

**Theme:** make one run worth reading twice.

- [ ] Findings correlation into a per-host posture (headers + TLS + methods → one card)
- [ ] HTML report, single file, no external assets, opens offline
- [ ] `relift diff <runA> <runB>` — new / fixed / changed findings
- [ ] `relift.config.json` with named profiles and per-engagement defaults
- [ ] `--fail-on <severity>` for CI: exit non-zero when a real issue shows up

**Exit:** two sweeps a week apart produce a diff a human can act on; HTML renders in
a browser with no network.

## v0.3 — Breadth

**Theme:** internal network, not just one URL.

- [ ] Discovery: live hosts on an in-scope CIDR, then per-host plans
- [ ] Passive subdomain inventory from certificate transparency
- [ ] `tls.cipher_preference` once `sslscan` output shape is pinned
- [ ] SSH/LDAP handshake fingerprinting (the non-auth half of `auth.*`)
- [ ] Bounded parallel execution sharing one global rate budget

**Exit:** a /24 sweep stays inside the budget and every host gets a plan.

## v0.4 — Analyst quality

**Theme:** the AI should be interesting, not merely present.

- [ ] JSON-mode structured triage with schema validation and repair
- [ ] Prompt-injection test suite (hostile banner → analyst must ignore it)
- [ ] Per-provider quality harness on a fixed finding corpus
- [ ] Redaction pass on by default for cloud providers

**Exit:** the injection suite passes for all providers; a model that fails schema
validation falls back instead of guessing.

## v0.5 — Hardening

- [ ] `pytest` suite: scope matcher, runner, each module against a local fixture server
- [ ] Fault injection: module raises, DNS fails mid-run, provider dies
- [ ] Windows path/encoding pass (this tree was scoped for win32 too)
- [ ] Security review of the scope gate by someone who did not write it

**Exit:** gate cannot be bypassed by any documented or documented-adjacent route.

## v1.0 — Release decision

- [ ] External review of `03-RULES-OF-ENGAGEMENT.md`
- [ ] Relicense (Apache-2.0 vs AGPL-3.0 — Jay's call)
- [ ] CONTRIBUTING with the tier-D exclusion stated as policy
- [ ] Public docs site or a very good README

**Exit:** a stranger clones, reads for ten minutes, and cannot accidentally scan a
host they do not own.

---

## Explicitly not on the roadmap

Denial of service · exploit delivery · credential brute-force · default-credential
checking · persistence · lateral movement · exfiltration. These are excluded by
policy, not deferred by priority. See `03-RULES-OF-ENGAGEMENT.md` §7.

## Idea parking lot

Things worth writing down, not worth promising:

- A `--json` output shape stable enough to feed a small dashboard
- Signed scope files (ed25519) so a scope cannot be edited after sign-off
- Per-module request budgets instead of one global rate
- A "pre-flight" mode that reports what *would* be skipped and why, before `--execute`
- Comparison against a baseline posture file ("this is what my lab looked like last month")
