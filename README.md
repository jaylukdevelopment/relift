# Relift

**Authorized infrastructure attack-surface testing — as a CLI.**
A [Pixelcity](https://pixelcity.dev) tool. Built and maintained by **Jay**.

```
relift  ::  Pixelcity Red Team Orchestrator  ::  v0.1.0
```

---

## What this is

Relift is a single-binary-friendly Python CLI that runs a **catalogue of real,
well-known assessment techniques** against hosts you own, orchestrates them in a
sane order, correlates what they return, and lists every technique it knows about
in its own output — so the tool is self-documenting.

It has two independent halves:

| Half | Purpose | Needs AI? |
|---|---|---|
| **Engine** | Scope enforcement, catalogue, module execution, findings, reporting | No |
| **Analyst** | Plan selection, triage, narrative reports, "what next?" advice | Optional |

The AI layer is a *plugin*, not a dependency. Every provider — local or cloud — sits
behind one interface, and `--no-ai` (or the `offline` provider) runs the deterministic
rule engine instead. Nothing in the tool requires a network connection to an LLM.

## What this is **not**

Relift is built for **your own infrastructure** — your lab, your servers, your
VPS, your internal network. It is not a hosted attack service, it does not target
third parties, and it deliberately ships **no destructive capability**. Read
[`docs/03-RULES-OF-ENGAGEMENT.md`](docs/03-RULES-OF-ENGAGEMENT.md) before pointing it
at anything, and never at a host you do not control.

> **You are responsible for your target.** Unauthorised scanning and exploitation is
> a criminal offence in most jurisdictions (StGB §202a-c in Germany, CFAA in the US,
> Computer Misuse Act in the UK). Relift refuses to run outside a signed scope
> file — that gate is not a formality, it is the only thing standing between a useful
> tool and an expensive mistake.

## Highlights

- **18-entry attack catalogue** with risk tiers, MITRE mapping and implementation status.
- **`relift list`** prints the whole catalogue — every technique, what it touches,
  and whether it is implemented or design-only.
- **Scope gate**: nothing runs unless the target matches an explicit, expiring,
  signed-off allowlist (`scope.json`). Deny rules always win.
- **Dry-run by default**: `scan` prints the plan; `--execute` is a separate, deliberate flag.
- **Real network operations**, not simulations: DNS resolution, TCP connect scan,
  TLS handshake probing, certificate parsing, HTTP header/method analysis.
- **External tool wrappers** for `nmap`, `nuclei`, `whatweb`, `nikto` when installed —
  fixed argument templates, no shell interpolation.
- **8 AI providers + offline**: Ollama, LM Studio, llama.cpp and any OpenAI-compatible
  gateway (local, no data leaves the box), OpenAI, Anthropic, OpenRouter and Groq
  (cloud), plus a deterministic rule engine.
- **Audit trail**: every authorisation decision, module run and AI call lands in an
  append-only JSONL log plus a per-run JSON artefact.

## Quickstart

```bash
cd relift

# 1. Install (editable, no dependencies outside the stdlib)
python -m pip install -e .

# 2. See every attack the tool knows about
relift list

# 3. Create a scope file for your own lab
relift init-scope --engagement homelab --host 127.0.0.1 --host 192.168.1.0/24

# 4. Plan (dry-run is the default, no packets sent except DNS)
relift scan --target http://127.0.0.1:8080 --scope scope.json

# 5. Actually execute
relift scan --target http://127.0.0.1:8080 --scope scope.json --execute
```

Without installing, use `python -m relift` from inside `src/`:

```bash
cd src && python -m relift list
```

## Releases

Every `v*` tag publishes prebuilt assets to
[Releases](https://github.com/jaylukdevelopment/relift/releases):

| Asset | Platform | Needs Python |
|---|---|---|
| `relift-windows-x64.exe` | Windows 10/11 x64 | no |
| `relift-linux-x64` | Linux x86_64, glibc 2.35+ | no |
| `relift.pyz` | any OS | 3.9+ |
| `relift-0.1.0-py3-none-any.whl` | any OS | 3.9+ |

Each executable ships with a `.sha256` sidecar; verify before running:

```bash
sha256sum -c relift-linux-x64.sha256
```

The Windows executable is **not code-signed**, so SmartScreen will warn on first
launch (More info → Run anyway). The Linux binary is built on Ubuntu 24.04; on an
older glibc, use the wheel or the `.pyz` instead. Nothing in any build phones home.

## Commands

```
relift list        [--category C] [--implemented-only] [--json]   Catalogue dump
relift providers   [--json]                                      AI provider matrix
relift init-scope  --engagement NAME --host H [--host H ...]      Write a scope file
relift plan        --target T [--profile P]                      Ordered run plan
relift scan        --target T --scope S [--execute]              Run it
relift report      --run RUN_ID [--format md|json|text]          Render a run
```

Profiles: `passive`, `safe` (default), `standard`, `lab`.

## AI providers

Selection order: `--ai` flag → `RELIFT_AI_PROVIDER` → `relift.config.json`
→ auto-detect (local daemons first, then cloud keys, then offline).

```bash
# local, fully offline
export RELIFT_AI_PROVIDER=ollama
export RELIFT_AI_MODEL=qwen2.5-coder:7b

# cloud, own key
export RELIFT_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# no AI at all
relift scan --target https://lab.internal --scope scope.json --no-ai
```

The analyst is constrained: it may only recommend module IDs that exist in the
catalogue, it never emits shell commands, and it never sees credentials. Details in
[`docs/04-AI-PROVIDERS.md`](docs/04-AI-PROVIDERS.md).

## Documentation

| Doc | Contents |
|---|---|
| [`docs/00-PROJECT-PLAN.md`](docs/00-PROJECT-PLAN.md) | Vision, goals, workstreams, milestones, acceptance criteria |
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Layering, module contract, data flow, extension points |
| [`docs/02-ATTACK-CATALOG.md`](docs/02-ATTACK-CATALOG.md) | Every technique, tier by tier, with scope of effect |
| [`docs/03-RULES-OF-ENGAGEMENT.md`](docs/03-RULES-OF-ENGAGEMENT.md) | Scope schema, authorisation gate, excluded classes |
| [`docs/04-AI-PROVIDERS.md`](docs/04-AI-PROVIDERS.md) | Provider matrix, env vars, prompt contract, guardrails |
| [`docs/05-ROADMAP.md`](docs/05-ROADMAP.md) | v0.1 → v1.0 phases and release gates |
| [`docs/06-CLI-REFERENCE.md`](docs/06-CLI-REFERENCE.md) | Full flag reference and output shapes |

## Status

`v0.1.0` — internal build, **not** open source yet. Licensed
[source-available / all rights reserved](LICENSE) while it is battle-tested on
Pixelcity infrastructure. The intent is to relicense once the authorisation model
and the catalogue have been hardened.

## Credits

- **Developer:** Jay — architecture, engine, modules, AI layer
- **Company:** Pixelcity
- **License:** Proprietary (see `LICENSE`)

Built for people who would rather know what their own servers look like from the
outside than find out from someone else.
