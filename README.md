# Relift

**Authorized infrastructure attack-surface testing — as a CLI and a desktop app.**
A [Pixelcity](https://pixelcity.dev) tool. Built and maintained by **Jay**.

[![ci](https://github.com/jaylukdevelopment/relift/actions/workflows/ci.yml/badge.svg)](https://github.com/jaylukdevelopment/relift/actions/workflows/ci.yml)
[![release](https://github.com/jaylukdevelopment/relift/actions/workflows/release.yml/badge.svg)](https://github.com/jaylukdevelopment/relift/releases)
[![license: source-available](https://img.shields.io/badge/license-source--available-blue.svg)](LICENSE)

[relift.pixelcity.dev](https://relift.pixelcity.dev) · [download](https://relift.pixelcity.dev/download) · [documentation](https://relift.pixelcity.dev/docs)

```
relift  ::  Pixelcity Red Team Orchestrator  ::  v0.2.0
```

---

## What this is

Relift is a single-binary-friendly Python tool that runs a **catalogue of real,
well-known assessment techniques** against hosts you own, orchestrates them in a
sane order, correlates what they return into attack threads, and lists every
technique it knows about in its own output — so the tool is self-documenting.

It has three independent parts:

| Part | Purpose | Needs AI? |
|---|---|---|
| **Engine** | Scope enforcement, catalogue, module execution, findings, attack threads, reporting | No |
| **Analyst** | Plan selection, triage, narrative reports, "what next?" advice | Optional |
| **Desktop** | The same engine in a local window over a loopback JSON API | No |

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

- **24-entry attack catalogue** with risk tiers, MITRE mapping and implementation status.
- **`relift list`** prints the whole catalogue — every technique, what it touches,
  and whether it is implemented or design-only.
- **Scope gate**: nothing runs unless the target matches an explicit, expiring,
  signed-off allowlist (`scope.json`). Deny rules always win.
- **Dry-run by default**: `scan` prints the plan; `--execute` is a separate, deliberate flag.
- **Real network operations**, not simulations: DNS resolution, TCP connect scan,
  TLS handshake probing, certificate parsing, HTTP header/method analysis, SSH
  KEXINIT parsing.
- **Real database protocols**, spoken directly: PostgreSQL startup and SCRAM, MySQL
  handshake, TDS pre-login, Redis RESP, MongoDB OP_MSG, Elasticsearch/CouchDB HTTP.
  No drivers, and no login unless you supply a credential.
- **Attack threads**: findings are joined into multi-stage paths, each with the one
  control that breaks it.
- **Local host audit**: SUID/SGID, capabilities, sudo rules, container sockets,
  listening ports, kernel advisory pass — read-only.
- **External tool wrappers** for `nmap`, `nuclei`, `nikto` when installed — fixed
  argument templates, no shell interpolation.
- **8 AI providers + offline**: Ollama, LM Studio, llama.cpp and any OpenAI-compatible
  gateway (local, no data leaves the box), OpenAI, Anthropic, OpenRouter and Groq
  (cloud), plus a deterministic rule engine.
- **Desktop application** for Windows and Linux: native window when available,
  browser otherwise, loopback-only and token-gated.
- **Audit trail**: every authorisation decision, module run and AI call lands in an
  append-only JSONL log plus a per-run JSON artefact.

## Quickstart

The one-line Linux install (checksum-verified, no Python needed):

```bash
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh
relift attack --target https://lab.example.com --depth 2
```

From source, with nothing outside the standard library at runtime:

```bash
cd relift

# 1. Install (editable)
python -m pip install -e .

# 2. See every attack the tool knows about
relift list

# 3. Attack a host you own: authors a 24-hour scope for it, then runs
relift attack --target https://lab.example.com --depth 2

# 4. Read the threads
relift chains
```

`--depth` is how far the run goes: `1` passive, `2` safe (default), `3` standard
(adds nmap/nuclei when installed), `4` intrusive, `5` full. `attack` is the same
gate as `scan` — it writes a real scope file under `~/.relift/scopes/`, prints it,
and logs the authorisation; it just saves you writing that file by hand.

If you want a wider engagement (several hosts, a CIDR, a shorter expiry), use the
explicit two-step form:

```bash
relift init-scope --engagement homelab --host 127.0.0.1 --host 192.168.1.0/24
relift scan --target http://127.0.0.1:8080 --scope scope.json          # dry run
relift scan --target http://127.0.0.1:8080 --scope scope.json --execute
```

Without installing, use `python -m relift` from inside `src/`:

```bash
cd src && python -m relift list
```

## Databases

Database targets are first-class. The scheme picks the protocol and the default
port, and the plan is filtered to techniques that make sense for it.

```
postgres://127.0.0.1:5432/appdb        postgresql://
mysql://10.10.10.20:3306/appdb         mariadb://
redis://10.10.10.20:6379               rediss://
mongodb://10.10.10.20:27017
mssql://10.10.10.20:1433               sqlserver://  tds://
elasticsearch://10.10.10.20:9200       opensearch://  es://
couchdb://10.10.10.20:5984
```

Two tiers exist for databases, and they answer different questions:

| Tier | Technique | Question |
|---|---|---|
| safe | `db.fingerprint`, `db.security_config` | What is this listener, does it demand authentication, which method, is TLS possible, is the build still supported? |
| intrusive (`--profile lab`) | `db.credential_verify` | Does this credential I already hold still work, and how powerful is it? |

The safe tier speaks the protocol and reads only what the protocol hands out before
authentication. The intrusive tier makes **exactly one login attempt per supplied
credential** — no wordlist, no spray, no retry loop — then reads that account's
privilege level. It cannot lock an account out on its own.

```bash
# what does this listener look like?
relift scan --target postgres://127.0.0.1:5432/appdb \
  --scope scope.json --execute

# does this credential from the leaked .env still work?
cat > creds.json <<'JSON'
{"credentials":[
  {"engine":"postgres","host":"127.0.0.1","port":5432,
   "username":"app","password":"from-the-backup","database":"appdb"}
]}
JSON
chmod 600 creds.json

relift scan --target postgres://127.0.0.1:5432/appdb \
  --scope scope.json --profile lab --execute --db-creds creds.json
```

A listener that answers without authentication is critical, not a hardening note. So
is a credential that still works with superuser rights. Both produce an attack
thread, not just a finding.

Full reference — protocols, privilege grading, the end-of-life table, and what the
tool refuses to do: [`docs/07-DATABASE-AUDIT.md`](docs/07-DATABASE-AUDIT.md).

## Attack threads

A finding says what is true. A thread says what it is worth.

After the modules run, `analysis.attack_chains` joins the findings into multi-stage
paths — reconnaissance, initial access, discovery, credential access, pivot,
collection, escalation, impact — and names the stage that carries the chain plus the
single control that breaks it. It only uses findings from the run: a stage with no
evidence behind it is never invented.

```
 CRIT Unauthenticated redis reachable: full datastore read path
  path   reconnaissance -> initial access -> collection
  break  Enable authentication and bind the listener to the loopback or an
         internal interface. Fix order: bind address first, then auth.
```

Ten rules ship: unauthenticated datastore, application-to-datastore (injectable
parameter plus a reachable database), held credential, container socket, cleartext
datastore auth, end-of-life datastore, plaintext session, writable admin surface,
certificate trust, and local privilege escalation.

```bash
relift chains                              # latest run, text
relift chains --run <id> --format json     # machine-readable
```

## Desktop application

`relift desktop` starts one loopback server and points a window at it. It is the
same process, the same scope file and the same engine functions as the CLI — there
is no second path around the gate.

```bash
# native window when pywebview is installed (WebView2 / WebKitGTK)
python -m pip install -e ".[desktop]"
relift desktop

# or serve only and open the URL yourself
relift desktop --no-window --port 8765

# the same launcher as a console script
relift-desktop
```

The server binds `127.0.0.1` only, generates a one-time token at launch, and
requires it in an `X-Relift-Token` header on every `/api` call. No CORS headers are
ever sent, request logging is disabled so a token cannot reach a terminal, and only
three static files are served from a fixed whitelist. If the native window cannot
start, the same URL opens in the default browser.

Architecture, API table and PyInstaller build commands:
[`docs/08-DESKTOP.md`](docs/08-DESKTOP.md).

## Releases

Every `v*` tag publishes prebuilt assets to
[Releases](https://github.com/jaylukdevelopment/relift/releases):

| Asset | Platform | Needs Python |
|---|---|---|
| `relift-windows-x64.exe` | Windows 10/11 x64, CLI | no |
| `relift-linux-x64` | Linux x86_64, glibc 2.35+, CLI | no |
| `relift-desktop-windows-x64.exe` | Windows 10/11 x64, desktop window | no |
| `relift-desktop-linux-x64` | Linux x86_64, desktop window | no |
| `relift.pyz` | any OS | 3.9+ |
| `relift-0.2.0-py3-none-any.whl` | any OS | 3.9+ |

Each executable ships with a `.sha256` sidecar; verify before running:

```bash
sha256sum -c relift-linux-x64.sha256
```

The desktop binaries bundle PyGObject and the UI assets, so they do not need a
Python install. They deliberately leave GLib, GTK and libstdc++ to the host: a
build-image copy shadows newer system libraries and stops WebKitGTK from loading.
On Linux the window needs WebKitGTK 4.1 (`gir1.2-webkit2-4.1` on Debian/Ubuntu);
on Windows 10/11 it needs the WebView2 Evergreen Runtime, which ships with the
system. The CLI binaries have neither requirement.

Linux builds are published to GitHub and mirrored at
[pixelcity.dev/lab/relift/downloads](https://pixelcity.dev/lab/relift/downloads),
so `install.sh` does not need a GitHub account. The Windows executables are **not
code-signed**, so SmartScreen will warn on first launch (More info → Run anyway).
The Linux binaries are built on Ubuntu 22.04; on an older glibc, use the wheel or
the `.pyz` instead. Nothing in any build phones home.

## Commands

```
relift list        [--category C] [--implemented-only] [--json]   Catalogue dump
relift providers   [--json]                                      AI provider matrix
relift attack      --target T [--depth 1-5]                      One command: scope + run
relift init-scope  --engagement NAME --host H [--host H ...]      Write a scope file
relift plan        --target T [--profile P]                      Ordered run plan
relift scan        --target T --scope S [--execute]              Run it
relift chains      [--run ID] [--format text|json]                Attack threads
relift report      --run RUN_ID [--format md|json|text]          Render a run
relift desktop     [--port N] [--no-window]                      Desktop application
```

Profiles: `passive`, `safe` (default), `standard`, `lab`. Database credentials
(`--db-creds`) and injection probes (`--sqli-url` / `--sqli-param`) are intrusive
and only run under `--profile lab` with an intrusive scope.

Targets: any `http(s)://` origin, a database scheme from the table above,
`ssh://host:22`, or `local://` for the host audit.

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
| [`docs/06-CLI-REFERENCE.md`](docs/06-CLI-REFERENCE.md) | Full flag reference, target forms, output shapes |
| [`docs/07-DATABASE-AUDIT.md`](docs/07-DATABASE-AUDIT.md) | Database protocols, credential file, privilege grading, lab recipes |
| [`docs/08-DESKTOP.md`](docs/08-DESKTOP.md) | Desktop architecture, API, security model, build commands |
| [`docs/09-SITE.md`](docs/09-SITE.md) | The public page and how it relates to the tool |
| [`docs/10-RELEASES.md`](docs/10-RELEASES.md) | Versioning, tag flow, assets, installer, checksums |

Also: [`docs/README.md`](docs/README.md) (index and reading order),
[`SECURITY.md`](SECURITY.md) (private reporting and safe harbour),
[`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md).

## Status

`v0.2.0` — public and **source-available**, not open source. The repository is
readable and issues are open, while the [licence](LICENSE) stays all rights
reserved until the authorisation model and the catalogue have been hardened. The
intent is to relicense once that bar is met; until then, running it against your
own infrastructure is welcome, redistributing it is not.

## Credits

- **Developer:** Jay — architecture, engine, modules, AI layer
- **Company:** Pixelcity
- **License:** Proprietary (see `LICENSE`)

Built for people who would rather know what their own servers look like from the
outside than find out from someone else.
