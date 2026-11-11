# Relift — CLI Reference

```
relift [--version] [--no-color] [--config PATH] <command> [target] [flags]
```

`plan`, `scan` and `attack` take the target as a positional argument or as
`--target`; both are the same value and neither changes the scope gate.

```
relift attack pixelcity.dev
relift attack pixelcity.dev --depth 3 --dry-run
relift scan https://lab.internal --scope scope.json --execute
```

| Exit code | Meaning |
|---|---|
| `0` | success |
| `1` | a module errored during a scan (the run is still written and reportable) |
| `2` | refused by the scope gate — nothing was sent |
| `3` | bad input that got past argparse: unknown category, missing run, bad credential file, unreadable config |
| `130` | interrupted (Ctrl+C) |

A malformed command line — unknown flag, missing `--target`/`--scope`, a `--format`
value that does not exist — is rejected by argparse with `2` before Relift sees it,
so the usage line is what tells the two `2`s apart.

Running `relift` with no command prints the banner and the help text and exits `0`.

Two global flags apply to every command:

| Flag | Meaning |
|---|---|
| `--config PATH` | read `relift.config.json` from here instead of the default locations |
| `--no-color` | plain output for files, CI logs and pipes |

---

## Targets

The target (positional or `--target`) accepts an origin, a database endpoint, an
SSH listener or the local host:

| Form | Example | Families planned |
|---|---|---|
| HTTP/HTTPS | `https://lab.internal:8443` | `http` |
| PostgreSQL | `postgres://10.10.10.20:5432/appdb` (alias `postgresql`) | `db` |
| MySQL/MariaDB | `mysql://10.10.10.20:3306/appdb` (alias `mariadb`) | `db` |
| Redis | `redis://10.10.10.20:6379` (alias `rediss`) | `db` |
| MongoDB | `mongodb://10.10.10.20:27017` | `db` |
| MSSQL | `mssql://10.10.10.20:1433` (aliases `sqlserver`, `tds`) | `db` |
| Elasticsearch | `elasticsearch://10.10.10.20:9200` (aliases `opensearch`, `es`) | `http` + `db` |
| CouchDB | `couchdb://10.10.10.20:5984` | `http` + `db` |
| SSH | `ssh://10.10.10.20:22` | `ssh` |
| Local host | `local://` | `host` |
| Directory | `./src` (only with `relift code`) | `code` |

Omitting the port uses the scheme default. Omitting the scheme means `https://`.
The path segment is the database name for engines that need one.

`local://` audits the machine Relift is running on. It still needs `127.0.0.1`
(or the local hostname) in the scope file and still writes an audit line; it does
not bypass the gate.

A directory is not a host: `relift code PATH` audits files on this machine and
needs no scope file, because it contacts nothing. It writes its own audit line
saying exactly that.

---

## `relift list`

Prints the attack catalogue — every technique the tool knows, its tier and its
status. A technique that needs an external binary says so in the status column
(`ext: nmap`); design-only entries are dimmed.

```bash
relift list
relift list --category db
relift list --implemented-only
relift list --search cors
relift list --json
```

| Flag | Meaning |
|---|---|
| `--category C` | one of `recon`, `tls`, `web`, `db`, `system`, `code`, `auth`, `analysis`, `report` |
| `--implemented-only` | hide design-only entries |
| `--search TEXT` | only entries whose id, name or summary contains `TEXT` |
| `--json` | machine-readable array |

An unknown `--category`, or a `--search` with no match, exits `3`.

The banner and the count line come first, then the table:

```
RELIFT · Pixelcity Red Team Orchestrator · v0.4.0
32 techniques · 26 ready · 3 external · 3 design-only / excluded

ID                        TECHNIQUE                              TIER      STATUS
recon.dns                 DNS resolution & address inventory      passive   ready
recon.http_fingerprint    HTTP fingerprint                        passive   ready
recon.port_scan           TCP connect sweep                       safe      ready
recon.service_scan        Service/version detection               safe      ext: nmap
...
```

## `relift explain`

One technique in full: tier, families, which profiles plan it, whether a module is
wired up, what it produces, the MITRE mapping and the note that says what it will
not do. This is the reference the catalogue table in `list` is too small to hold.

```bash
relift explain web.cors_policy
relift explain tls.cipher_preference --json
```

An unknown id exits `3` and suggests `relift list --search <id>`.

## `relift doctor`

Read-only environment check, meant as the first command on a new machine. It reads
paths and runs no traffic against a target.

```bash
relift doctor
relift doctor pixelcity.dev      # also check that the name resolves
relift doctor --json
```

It reports the interpreter, the config file in use, whether the scope/run/audit
paths are writable (or will be created), which external binaries are installed,
which AI provider would be selected, and — given a target — what it resolves to.
Exit `0` when nothing fails, `1` when a required path is not writable.

```
STATUS  CHECK           DETAIL
ok      python          3.14.9 (needs 3.9+)
ok      scope dir       /root/.relift/scopes (will be created on the first run)
warn    external tools  nmap, nuclei (missing), nikto (missing), sslscan (missing)
ok      ai analyst      offline/rule-engine
ok      target          127.0.0.1 -> 127.0.0.1

ready — 4 warning(s), nothing blocking
```

## `relift providers`

Shows each AI provider, whether it is reachable right now, and which one would be
selected.

```bash
relift providers
relift providers --json
```

## `relift init-scope`

Writes a scope file. Refuses to overwrite without `--force`.

```bash
relift init-scope --engagement homelab --host 127.0.0.1 --host 10.10.10.0/24
relift init-scope --engagement db-lab --host 127.0.0.1 \
  --ports 5432,6379 --out scope.json --allow-intrusive
```

| Flag | Default | Meaning |
|---|---|---|
| `--engagement NAME` | required | engagement name, appears in every audit line |
| `--host H` | `127.0.0.1` and `::1` | repeatable; host, wildcard or CIDR |
| `--deny H` | — | repeatable deny entry |
| `--out PATH` | `scope.json` | output path |
| `--max-risk R` | `safe` | `passive` or `safe` |
| `--expires ISO` | +30 days | expiry timestamp |
| `--ports LIST` | common set | comma-separated ports |
| `--allow-intrusive` | off | sets `max_risk: intrusive` and `allow_intrusive: true` together |
| `--authorized-by` | `Jay` | who signed off |
| `--organization` | `Pixelcity` | organisation |
| `--notes` | — | free text copied into the scope |
| `--force` | off | overwrite an existing file |

Choosing `--allow-intrusive` still does nothing without `--profile lab` at scan
time. Both switches are required.

## `relift plan`

Builds the ordered run plan without executing it. Always safe: no packets beyond the
DNS lookups the scope check performs.

```bash
relift plan http://127.0.0.1:8080 --scope scope.json
relift plan postgres://127.0.0.1:5432/appdb --scope scope.json --no-ai
relift plan 10.10.10.20 --profile lab --scope scope.json --no-ai
```

| Flag | Default | Meaning |
|---|---|---|
| `T` / `--target T` | required | any form from the target table |
| `--scope S` | required | scope file path |
| `--profile P` | from config, else `safe` | `passive` \| `safe` \| `standard` \| `lab` |
| `--ai ID` | auto | provider id; `none` = rule engine |
| `--no-ai` | off | force the rule engine |
| `--json` | off | emit the plan as JSON |

## `relift attack`

The one-command form: author a scope for exactly this target, then run the plan.
The scope is a real file with a 24-hour expiry under `~/.relift/scopes/` (override
the directory with `RELIFT_SCOPE_DIR`), so the authorisation record and audit line
still exist — the shortcut removes the setup step, not the gate.

```bash
# the default: safe tier, logs look like browsing
relift attack lab.example.com

# authorise and plan, send nothing
relift attack lab.example.com --dry-run

# depth 3 adds external tools (nmap, nuclei) when they are installed
relift attack lab.example.com --depth 3

# depth 4-5: intrusive tier, your own infrastructure only
relift attack http://10.10.10.20 --depth 4

# reuse a scope you already wrote (depth then only lowers the ceiling)
relift attack http://127.0.0.1:8080 --scope scope.json --depth 2
```

| Depth | Name | Profile | Ceiling | Adds |
|---|---|---|---|---|
| `1` | passive | `passive` | passive | DNS, headers, certificate, disclosure |
| `2` | safe (default) | `safe` | safe | port sweep, methods, TLS versions |
| `3` | standard | `standard` | safe | external templates (`nmap`, `nuclei`) |
| `4` | intrusive | `lab` | intrusive | bounded path probe, bounded SQLi, credential verify |
| `5` | full | `lab` | intrusive | everything, including the external binaries (nmap, nuclei, nikto) |

Depth `4` deliberately excludes external tools, so the nikto server audit and the
nmap/nuclei scans need depth `5`. Names work too: `--depth quiet`, `passive`,
`safe`, `standard`, `intrusive`, `deep`, `full`, `max`.

| Flag | Default | Meaning |
|---|---|---|
| `T` / `--target T` | required | any form from the target table |
| `--depth N` | `2` | `1`-`5` or a name from the table |
| `--dry-run` | off | authorise and print the plan, then stop without a request |
| `--scope S` | — | use this scope instead of authoring one |
| `--expires ISO` | +24 hours | expiry written into the authored scope |
| `--authorized-by` | `Jay` | who signed off |
| `--organization` | `Pixelcity` | organisation |
| `--ports LIST` | common set + the target's port | port set for the sweep and the scope |
| `--db-creds FILE` | — | credentials you already hold (depth 4+) |
| `--sqli-url` / `--sqli-param` (aliases `--param-url` / `--param`) | — | the one parameter the injection, traversal and redirect probes may touch (depth 4+) |
| `--ai ID` / `--no-ai` | auto | analyst selection |
| `--timeout`, `--insecure`, `--json` | — | as for `scan` |

Intrusive techniques still require both an intrusive scope and the `lab` profile;
`--depth 4` sets both. Depth 3/5 only include external binaries that are actually
on `PATH`; when they are missing, the plan skips them and says so.

`--sqli-url` and `--sqli-param` name a single parameter, and the three parameter
techniques use it: `web.sql_injection_check` detects injection and then proves it
by making the engine return its own version, `web.path_traversal` proves file read
by finding a `/etc/passwd`-style marker, `web.open_redirect` proves the parameter
can leave the site. Proof stops at a marker or version string; no table, file or
row is read out.

The target's own port is added to the default sweep, so `attack http://host:8099`
probes 8099 even though it is not in the common set. `--ports` replaces the set
entirely.

```bash
# detection, then proof of impact, on one parameter
relift attack http://127.0.0.1:8099 --depth 4 \
  --sqli-url "http://127.0.0.1:8099/search?q=test" --sqli-param q

# the same parameter point, for file read and off-site redirects
relift attack http://127.0.0.1:8099 --depth 4 \
  --sqli-url "http://127.0.0.1:8099/download?file=report.pdf" --sqli-param file
```

## `relift scan`

Executes the plan. **Dry-run unless `--execute` is given.**

```bash
# shows what would run, sends nothing
relift scan --target http://127.0.0.1:8080 --scope scope.json

# actually does it
relift scan --target http://127.0.0.1:8080 --scope scope.json --execute

# a database, safe tier
relift scan --target postgres://127.0.0.1:5432/appdb \
  --scope scope.json --execute

# credentials you already hold, lab only
relift scan --target mysql://10.10.10.20:3306/appdb \
  --scope scope.json --profile lab --execute --db-creds creds.json

# bounded injection probe on one parameter, lab only
relift scan --target http://127.0.0.1:8080 \
  --scope scope.json --profile lab --execute \
  --sqli-url "http://127.0.0.1:8080/product?id=1" --sqli-param id

# the machine you are on
relift scan --target local:// --scope scope.json --execute
```

| Flag | Default | Meaning |
|---|---|---|
| `--target T` | required | as above |
| `--scope S` | required | scope file path |
| `--profile P` | from config, else `safe` | as above |
| `--execute` | off | send real traffic |
| `--ai ID` / `--no-ai` | auto | analyst selection |
| `--ports LIST` | from scope | override the port set |
| `--timeout S` | `6` | per-operation socket timeout |
| `--insecure` | off | skip TLS verification (lab self-signed certs) |
| `--db-creds FILE` | — | JSON file of credentials you already hold; one attempt each |
| `--sqli-url URL` | — | URL containing the parameter to probe; must be on the target host |
| `--sqli-param NAME` | — | the parameter in that URL |
| `--json` | off | print the run record as JSON |

`--sqli-url` and `--sqli-param` must be given together. `--db-creds` and the
injection probe only run under `--profile lab` with an intrusive scope; otherwise
they are not planned at all and the run says so.

Sample output:

```
target   postgres://127.0.0.1:55433/postgres   engagement: relift-lab
scope    6c1d7b74c272   profile: lab   analyst: offline/rule-engine
run      20261107-141726-4106   2026-11-07T14:17:26+00:00

   TECHNIQUE             RESULT  TIME    NOTE
─  ────────────────────  ──────  ──────  ──────────────────────────────
✓  recon.dns             ok      0.00s   1 finding(s)
✓  recon.port_scan       ok      10.21s  1 finding(s)
–  recon.service_scan    skipped 0.00s   missing tool: nmap
✓  db.fingerprint        ok      0.00s   1 finding(s)
✓  db.security_config    ok      0.20s   3 finding(s)
✓  db.credential_verify  ok      0.20s   1 finding(s)

FINDINGS

 CRIT Credential for postgres accepted on postgres  [db.credential_verify]
 ...
ATTACK THREADS

 CRIT Held postgres credential still works and is superuser
  path   credential access -> privilege escalation -> collection
  break  Rotate the credential, then find its source: config file, CI secret,
         backup, or an application default. ...

5 executed · 1 skipped · 7 finding(s) (2 critical · 1 high) · 2 thread(s)
run saved to .relift-runs/20261107-141726-4106/run.json   audit: ~/.relift/audit.jsonl
```

## `relift code`

Audits a directory instead of a host: hardcoded secrets, dangerous sinks and known
vulnerable dependency versions. Reads local files only — no scope file, no socket to
the target — and writes an audit line recording that. The one outbound request is
the OSV advisory lookup, disabled with `--no-osv`.

```bash
relift code .
relift code /srv/app --profile passive
relift code . --no-osv          # inventory versions, contact nothing
relift code . --json
```

| Flag | Default | Meaning |
|---|---|---|
| `PATH` | required | directory to audit |
| `--profile P` | `safe` | ceiling; the code techniques are passive, so this changes nothing about what they do |
| `--no-osv` | off | skip the advisory lookup |
| `--ai ID` / `--no-ai` | auto | analyst selection |
| `--json` | off | print the run record as JSON |
| `--timeout` | `6` | per-request timeout for the OSV calls |

```
RELIFT · Pixelcity Red Team Orchestrator · v0.4.0

FINDINGS

 CRIT lodash 4.17.4: 9 known vulnerability(ies)  [code.dependencies]
        GHSA-29mw-wpgm-hmr9 -> 4.17.21: Regular Expression Denial of Service (ReDoS) in lodash | …
 HIGH AWS access key id in app.py  [code.secrets]
        1 match(es), first at line 3 (AKIA…LE). The value is redacted here and in the run
        artefact; rotate it and remove it from the tree.
 HIGH SQL statement built by concatenation or f-string in app.py:7  [code.dangerous_sinks]
        cursor.execute("SELECT * FROM users WHERE id = " + user_id) — a sink, not a proven
        vulnerability: it is where a flaw would matter. Review the data flow into it.

3 executed · 6 finding(s) (1 critical · 2 high · 1 medium)
run saved to .relift-runs/…/run.json   audit: ~/.relift/audit.jsonl
```

A secret is redacted before it reaches the terminal, the artefact or the report; the
run keeps the file and line so it can be rotated and removed. A sink is labelled as
a sink, not as an exploit. A CVE match is exact-version against OSV, with the fixed
version where the advisory names one. Vendored and generated trees, binaries and
files over 512 KiB are skipped, and the run says how many files were read.

The run ends with the same coverage block as a host scan — including which host
techniques were not applicable to a directory, so a short report cannot be mistaken
for a clean one.

## `relift report`

Re-renders a stored run. Works offline; the AI narrative is optional and regenerated
only if asked.

```bash
relift report --run 20261107-120501-4f2a
relift report --run 20261107-120501-4f2a --format md
relift report --run 20261107-120501-4f2a --format json
relift report --run <id> --ai openai      # regenerate the narrative
relift report --run <id> --no-ai          # rule engine narrative
relift report --run <id> --format md --out report.md
```

| Flag | Default | Meaning |
|---|---|---|
| `--run ID` | latest | run id under `.relift-runs/`, or a path to a `run.json` |
| `--format F` | `text` | `text` \| `md` \| `json` |
| `--ai ID` / `--no-ai` | auto | narrative source |
| `--out PATH` | stdout | write instead of printing |

Markdown output contains the findings table, an attack-threads section with one
stage table per thread, and the coverage table.

## `relift chains`

Prints the correlated attack threads for a stored run. Recomputes them from the
findings when the artefact predates the correlation engine, so it works on old
runs.

```bash
relift chains                       # latest run
relift chains --run 20261107-141726-4106
relift chains --format json
relift chains --out threads.json --format json
```

| Flag | Default | Meaning |
|---|---|---|
| `--run ID` | latest | run id or path to `run.json` |
| `--format F` | `text` | `text` \| `json` |
| `--out PATH` | stdout | write instead of printing |

```
ATTACK THREADS

 CRIT Unauthenticated redis reachable: full datastore read path
  path   reconnaissance -> initial access -> collection
  The redis listener on port 6379 answered the protocol probe without demanding
  credentials. ...
  break  Enable authentication and bind the listener to the loopback or an
         internal interface. Fix order: bind address first, then auth.
```

`--format json` returns `{run_id, target, headline, chains[]}`; each chain carries
`id`, `title`, `severity`, `summary`, `stages[]` (`stage`, `attack_id`, `title`,
`detail`), `break_at` and `confidence`.

## `relift desktop`

Starts the desktop application: one loopback server, a native window when
`pywebview` is installed, the default browser otherwise. Same engine, same scope
gate. The same program is installed as `relift-desktop`.

```bash
relift desktop
relift desktop --no-window --port 8765
```

| Flag | Default | Meaning |
|---|---|---|
| `--port N` | `0` | `0` picks a free ephemeral port |
| `--no-window` | off | serve only; print the URL instead of opening a window |

```
RELIFT · Pixelcity Red Team Orchestrator · v0.4.0
  desktop   http://127.0.0.1:43719/
  window    native
  scope gate: same engine, same scope file, no bypass
  press Ctrl+C to stop
```

`Ctrl+C` stops the server; closing the native window does the same. Architecture,
API and build instructions: [`08-DESKTOP.md`](08-DESKTOP.md).

## Run artefacts

```
.relift-runs/20261107-120501-4f2a/run.json
~/.relift/audit.jsonl
```

`run.json` holds the target, scope hash, profile, provider, every execution, every
finding and every correlated thread. `audit.jsonl` holds the authorisation
decisions and a `chains` event per run. Both are gitignored by default because they
describe your internal network.

Paths can be redirected with `RELIFT_RUNS_DIR` and `RELIFT_AUDIT_FILE`.
