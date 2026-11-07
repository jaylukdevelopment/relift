# Relift — Architecture

## 1. Layering

```
                 ┌──────────────────────────────────────────────┐
                 │  cli.py                                      │
                 │  argparse surface, banner, exit codes        │
                 └───────────────┬──────────────────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────────┐
        │                        │                             │
┌───────▼─────────┐   ┌──────────▼──────────┐   ┌──────────────▼────────┐
│ catalog.py      │   │ runner.py           │   │ report.py             │
│ the technique   │   │ plan → execute →    │   │ terminal / md / json  │
│ catalogue       │   │ collect             │   │ rendering             │
└───────┬─────────┘   └──────┬───────┬──────┘   └──────────────┬────────┘
        │                    │       │                         │
        │            ┌───────▼──┐  ┌─▼──────────┐    ┌─────────▼────────┐
        │            │scope.py  │  │ audit.py   │    │ ai/  (optional)  │
        │            │the gate  │  │ JSONL trail│    │ provider plugins │
        │            └──────────┘  └────────────┘    └──────────────────┘
        │                    │
        │            ┌───────▼──────────────────────────────┐
        └───────────►│ modules/  (base.py + recon/web/tls)   │
                     │ one class per catalogue entry         │
                     └───────────────┬──────────────────────┘
                                     │
                             sockets / ssl / urllib
                             subprocess (nmap, nuclei…)
```

**Rule:** the engine never imports `ai/`. The analyst layer is handed a read-only
view of the run after the fact, or a plan request before it. Deleting `ai/` from the
tree leaves a fully working scanner.

Two things sit beside the CLI without forking it:

- `chains.py` reads a finished `RunRecord` and returns attack threads. It is pure:
  findings in, threads out, no network, so it runs on stored runs (`relift chains`)
  as well as fresh ones.
- `desktop.py` + `api.py` are a second front-end. The API calls the *same*
  `load_scope()` and `runner.scan()` the CLI calls; there is no alternate scan path
  that could skip the gate. The API binds `127.0.0.1` only, requires a per-launch
  bearer token, and rejects any request carrying a foreign `Origin`.

## 2. File map

| Path | Responsibility |
|---|---|
| `models.py` | `AttackSpec`, `Target`, `Finding`, `Execution`, `RunRecord`, risk/severity enums |
| `catalog.py` | The catalogue: every technique, its tier, status, requirements |
| `scope.py` | Scope file parsing, CIDR/wildcard matching, expiry, risk ceiling, denial |
| `audit.py` | Append-only JSONL audit log + per-run artefact writer |
| `modules/base.py` | `Module` contract, `ScanContext`, `TCPConn` (+ raw TLS), rate limiter, shared HTTP helper |
| `modules/recon.py` | DNS, TCP connect scan, HTTP fingerprint, service scan |
| `modules/web.py` | Security headers, HTTP methods, robots/sitemap disclosure, template scan |
| `modules/tls.py` | Certificate inspection, protocol version support |
| `modules/db.py` | Pre-auth database audit; opens the wire protocol and reads what it answers |
| `modules/dbauth.py` | Credential verification and post-auth privilege grading, one attempt per credential |
| `modules/dbproto.py` | Wire codecs: PG v3, MySQL, Redis RESP, MongoDB BSON/OP_MSG, TDS, Elasticsearch |
| `modules/system.py` | Host audit of the machine the tool runs on (sshd config, users, SUID, world-writable) |
| `modules/ssh.py` | SSH transport-banner and KEXINIT enumeration, deprecated algorithm detection |
| `modules/sqlinject.py` | Single-request error-based and boolean SQLi check, fixed payload set |
| `chains.py` | Findings → multi-stage attack threads, with the stage that breaks the path |
| `runner.py` | Profile → plan, plan → executions, findings aggregation, chain building |
| `report.py` | Text table, Markdown, JSON, threads section, optional AI narrative |
| `api.py` | Loopback JSON API for the desktop UI (token, Origin check, job registry) |
| `desktop.py` | Native window (pywebview) or browser fallback; frozen-entry friendly |
| `desktop/` | `app.html`, `app.css`, `app.js` — offline, no CDN, no framework |
| `ai/base.py` | `AIProvider` interface + `Analyst` (prompt building, output validation) |
| `ai/local.py` | Ollama, LM Studio / llama.cpp / vLLM (OpenAI-compatible) |
| `ai/cloud.py` | OpenAI, Anthropic, OpenRouter, Groq |
| `ai/offline.py` | Rule engine: deterministic planning and summarisation, zero network |
| `cli.py` | Command dispatch and all user-facing output |

## 3. Module contract

```python
class Module:
    attack_id: str                      # must exist in catalog.CATALOG

    def run(self, ctx: ScanContext) -> list[Finding]: ...
```

`ScanContext` carries everything a module is allowed to touch:

```python
ctx.target      # parsed Target: scheme, host, port, path
ctx.scope       # the loaded Scope; re-checked per host by the runner
ctx.ports       # the port set the operator opted into
ctx.timeout     # per-operation socket timeout
ctx.insecure    # skip TLS verification (lab self-signed certs)
ctx.dry_run     # True → modules must not send packets
ctx.throttle()  # call before each network operation; enforces RPS budget
ctx.audit       # append an audit event
ctx.credentials # list of optional credentials for verifier modules
```

Protocol modules do not use `urllib`; they open a `TCPConn` instead, which gives
them a socket with a deadline, `recv_exact()`, and an optional TLS upgrade. Any
module that needs more than a request/response (PostgreSQL startup, Redis RESP,
TDS pre-login) builds the bytes in `dbproto.py` so the codecs stay testable
without a server.

Rules a module must follow:

1. **One technique.** If it needs two, it is two catalogue entries.
2. **No state mutation on the target.** Read-only requests, handshakes, and
   connections that the target's own logs would call "a request".
3. **Never raise.** Return an empty list and let the runner record the error;
   a broken module must not abort a run.
4. **No shell strings.** External tools are invoked with an argv list built from a
   fixed template. Target values are never interpolated into a shell.
5. **Evidence, not opinions.** `Finding.evidence` holds the observed bytes, headers
   or numbers. Interpretation happens later, or in the analyst.

## 4. Execution flow

```
scan --target T --scope S [--execute]
   │
   ├─ load scope ──► expired? unsigned? ──► refuse (exit 2)
   ├─ parse target
   ├─ scope.authorize(T.host) ──► deny ──► refuse (exit 2), audit the denial
   ├─ profile ──► ordered catalogue subset (risk ceiling from scope + profile)
   ├─ [AI] planner may reorder / annotate the subset; output is validated
   │        against catalogue IDs — anything else is dropped
   ├─ dry_run? ──► print plan + would-be argv, exit 0
   ├─ for each id:
   │     module = MODULES.get(id)
   │     missing module or missing binary ──► Execution(status="skipped")
   │     else: ctx.throttle(); findings = module.run(ctx)
   │           ──► Execution(status="ok"|"error", findings=n)
   ├─ aggregate findings (dedupe by (attack_id, target, title))
   ├─ build attack threads (chains.py, pure, no network)
   ├─ write .relift-runs/<run_id>/run.json
   ├─ append to ~/.relift/audit.jsonl
   └─ render
```

Exit codes: `0` ok · `1` module errors · `2` refused (scope/authorisation) ·
`3` bad usage.

## 5. Data model

`Finding` is intentionally boring: `attack_id`, `target`, `title`, `severity`,
`detail`, `evidence`, `references`, `confidence`. No free-form severity guessing
inside modules — a module that cannot decide says `info` and explains.

`RunRecord` is the unit of truth. The AI narrative is stored **next to** the
findings, never merged into them, so a run can be re-rendered without any model.

## 6. Storage

| Artefact | Location | Retention |
|---|---|---|
| Run record | `.relift-runs/<run_id>/run.json` | operator's choice |
| Audit log | `~/.relift/audit.jsonl` | append-only, never rotated by the tool |
| Config | `relift.config.json` (repo or cwd) | gitignored |
| Scope | `scope.json` (path given per run) | gitignored |

The audit log records the engagement name, the target, the decision, and a hash of
the scope file — never credentials, never bodies.

## 7. Extension points

- **New technique** → subclass `Module`, add a `sitecustomize`-free entry in
  `modules/__init__.py:MODULES`, add an `AttackSpec` to `catalog.py`. Nothing else.
- **New external tool** → build an argv template in the module, gate on
  `shutil.which`, record the resolved version in the execution.
- **New AI provider** → subclass `AIProvider` in `ai/local.py` or `ai/cloud.py`,
  register in `ai/__init__.py:PROVIDERS`. One `complete()` method is the whole surface.

## 8. Threat model of the tool itself

| Threat | Consequence | Control |
|---|---|---|
| Operator points it at a non-owned host | Illegality, harm | Scope file + deny-by-default + audit |
| Over-broad CIDR typo | Mass scanning | /22 guard, explicit opt-in |
| Scope file silently edited after sign-off | Untracked scope creep | SHA-256 of the scope file stored in every run and audit line |
| Prompt injection via a target's banner/title | Analyst emits unsafe advice | Target text is delimited data; module IDs whitelisted; no shell generation |
| Cloud key leaked into artefact | Credential exposure | Keys read from env only, never written to disk, redacted in audit |
| Aggressive module used "just to check" | Service disruption | Tier system: `intrusive` requires both scope permission and `lab` profile |
| Findings leak internal topology | Info disclosure | Run artefacts gitignored, report redaction helper |

## 9. Sequencing rationale

The catalogue is built before the modules because the catalogue is the safety
control: a technique without a tier cannot be reasoned about, and a tool whose
catalogue is an afterthought ends up with destructive capability nobody audited.
