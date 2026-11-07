# Relift — CLI Reference

```
relift [--version] [--no-color] [--config PATH] [--verbose] <command> [...]
```

Exit codes: `0` success · `1` a module errored (run still produced) · `2` refused by
the scope gate · `3` bad usage.

---

## `relift list`

Prints the attack catalogue — every technique the tool knows, its tier, whether it is
implemented, and what it needs.

```bash
relift list
relift list --category web
relift list --implemented-only
relift list --json
```

| Flag | Meaning |
|---|---|
| `--category C` | one of `recon`, `tls`, `web`, `auth`, `report` |
| `--implemented-only` | hide design-only entries |
| `--json` | machine-readable array |

```
ID                        TECHNIQUE                            TIER      STATUS
recon.dns                 DNS resolution & address inventory   passive   ready
recon.http_fingerprint    HTTP fingerprint                     passive   ready
recon.port_scan           TCP connect sweep                    safe      ready
recon.service_scan        Service/version detection            safe      ext: nmap
...
18 techniques · 9 ready · 3 external · 6 design-only / excluded
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
| `--authorized-by` | `Jay` | who signed off |
| `--force` | off | overwrite an existing file |

## `relift plan`

Builds the ordered run plan without executing it. Always safe: no packets beyond the
DNS lookups the scope check performs.

```bash
relift plan --target http://127.0.0.1:8080 --scope scope.json
relift plan --target 10.10.10.20 --profile lab --scope scope.json --no-ai
```

| Flag | Default | Meaning |
|---|---|---|
| `--target T` | required | `host`, `host:port`, or a full URL |
| `--scope S` | required | scope file path |
| `--profile P` | `safe` | `passive` \| `safe` \| `standard` \| `lab` |
| `--ai ID` | auto | provider id; `none` = rule engine |
| `--no-ai` | off | force the rule engine |
| `--json` | off | emit the plan as JSON |

## `relift scan`

Executes the plan. **Dry-run unless `--execute` is given.**

```bash
# shows what would run, sends nothing
relift scan --target http://127.0.0.1:8080 --scope scope.json

# actually does it
relift scan --target http://127.0.0.1:8080 --scope scope.json --execute
```

| Flag | Default | Meaning |
|---|---|---|
| `--target T` | required | as above |
| `--scope S` | required | scope file path |
| `--profile P` | `safe` | as above |
| `--execute` | off | send real traffic |
| `--ai ID` / `--no-ai` | auto | analyst selection |
| `--ports LIST` | from scope | override the port set |
| `--timeout S` | `6` | per-operation socket timeout |
| `--insecure` | off | skip TLS verification (lab self-signed certs) |
| `--json` | off | print the run record as JSON |

Sample output:

```
RELIFT · Pixelcity · engagement: homelab
target  http://127.0.0.1:8080   scope: 9f2c8a1e   profile: safe   analyst: ollama/qwen2.5-coder:7b

  ✓ recon.dns               ok      0.02s   → 3 addrs (127.0.0.1)
  ✓ recon.http_fingerprint  ok      0.11s   → Server: Werkzeug/3.0.1
  ✓ recon.port_scan         ok      0.43s   → 2 open / 5 closed
  – recon.service_scan      skipped          nmap not installed
  ✓ tls.certificate         ok      0.08s
  ✓ web.headers             ok      0.12s   → 4 findings
  ...

9 executed · 1 skipped · 12 findings (2 medium, 10 info)
run id: 20261107-120501-4f2a
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
```

| Flag | Default | Meaning |
|---|---|---|
| `--run ID` | latest | run id under `.relift-runs/`, or a path to a `run.json` |
| `--format F` | `text` | `text` \| `md` \| `json` |
| `--ai ID` / `--no-ai` | auto | narrative source |
| `--out PATH` | stdout | write instead of printing |

## Run artefacts

```
.relift-runs/20261107-120501-4f2a/run.json
~/.relift/audit.jsonl
```

`run.json` holds the target, scope hash, profile, provider, every execution and every
finding. `audit.jsonl` holds the authorisation decisions. Both are gitignored by
default because they describe your internal network.
