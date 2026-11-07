# Relift — CLI Reference

```
relift [--version] [--no-color] [--config PATH] <command> [flags]
```

| Exit code | Meaning |
|---|---|
| `0` | success |
| `1` | a module errored during a scan (the run is still written and reportable) |
| `2` | refused by the scope gate — nothing was sent |
| `3` | bad usage, bad input, unknown category, missing run, bad credential file |
| `130` | interrupted (Ctrl+C) |

Running `relift` with no command prints the banner and the help text and exits `0`.

---

## Targets

`--target` accepts an origin, a database endpoint, an SSH listener or the local
host:

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

Omitting the port uses the scheme default. Omitting the scheme means `https://`.
The path segment is the database name for engines that need one.

`local://` audits the machine Relift is running on. It still needs `127.0.0.1`
(or the local hostname) in the scope file and still writes an audit line; it does
not bypass the gate.

---

## `relift list`

Prints the attack catalogue — every technique the tool knows, its tier, whether it is
implemented, and what it needs.

```bash
relift list
relift list --category db
relift list --implemented-only
relift list --json
```

| Flag | Meaning |
|---|---|
| `--category C` | one of `recon`, `tls`, `web`, `db`, `system`, `auth`, `analysis`, `report` |
| `--implemented-only` | hide design-only entries |
| `--json` | machine-readable array |

An unknown `--category` exits `3` and lists the valid ones.

```
ID                        TECHNIQUE                              TIER      STATUS
recon.dns                 DNS resolution & address inventory      passive   ready
recon.http_fingerprint    HTTP fingerprint                        passive   ready
recon.port_scan           TCP connect sweep                       safe      ready
recon.service_scan        Service/version detection               safe      ext: nmap
...
24 techniques · 16 ready · 3 external · 5 design-only / excluded
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
| `--host H` | `127.0.0.1` | repeatable; host, wildcard or CIDR |
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
relift plan --target http://127.0.0.1:8080 --scope scope.json
relift plan --target postgres://127.0.0.1:5432/appdb --scope scope.json --no-ai
relift plan --target 10.10.10.20 --profile lab --scope scope.json --no-ai
```

| Flag | Default | Meaning |
|---|---|---|
| `--target T` | required | any form from the target table |
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
relift attack --target https://lab.example.com

# depth 3 adds external tools (nmap, nuclei) when they are installed
relift attack --target https://lab.example.com --depth 3

# depth 4-5: intrusive tier, your own infrastructure only
relift attack --target http://10.10.10.20 --depth 4

# reuse a scope you already wrote (depth then only lowers the ceiling)
relift attack --target http://127.0.0.1:8080 --scope scope.json --depth 2
```

| Depth | Name | Profile | Ceiling | Adds |
|---|---|---|---|---|
| `1` | passive | `passive` | passive | DNS, headers, certificate, disclosure |
| `2` | safe (default) | `safe` | safe | port sweep, methods, TLS versions |
| `3` | standard | `standard` | safe | external templates (`nmap`, `nuclei`) |
| `4` | intrusive | `lab` | intrusive | server audit, bounded SQLi, credential verify |
| `5` | full | `lab` | intrusive | everything above plus external tools |

Names work too: `--depth safe`, `--depth intrusive`, `--depth full`.

| Flag | Default | Meaning |
|---|---|---|
| `--target T` | required | any form from the target table |
| `--depth N` | `2` | `1`-`5` or a name from the table |
| `--scope S` | — | use this scope instead of authoring one |
| `--expires ISO` | +24 hours | expiry written into the authored scope |
| `--authorized-by` | `Jay` | who signed off |
| `--organization` | `Pixelcity` | organisation |
| `--ports LIST` | common set | port set for the sweep and the scope |
| `--db-creds FILE` | — | credentials you already hold (depth 4+) |
| `--sqli-url` / `--sqli-param` | — | bounded injection probe (depth 4+) |
| `--ai ID` / `--no-ai` | auto | analyst selection |
| `--timeout`, `--insecure`, `--json` | — | as for `scan` |

Intrusive techniques still require both an intrusive scope and the `lab` profile;
`--depth 4` sets both. Depth 3/5 only include external binaries that are actually
on `PATH`; when they are missing, the plan skips them and says so.

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
RELIFT · Pixelcity Red Team Orchestrator · v0.2.0
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
