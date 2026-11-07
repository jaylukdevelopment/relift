# FAQ and troubleshooting

Short answers to the things that go wrong first. Everything here is a symptom of a
deliberate design decision, so the fix is usually one flag, not one patch.

---

## Install

### `install.sh` says it could not download the binary

The installer tries `https://pixelcity.dev/lab/relift/downloads` first, then
`https://github.com/jaylukdevelopment/relift/releases/latest/download`. If both
fail, it prints both URLs and installs nothing.

- Check that the release exists: <https://github.com/jaylukdevelopment/relift/releases>
- Behind a proxy or a firewall, fetch an asset by hand and point the installer at
  a mirror you control:

  ```bash
  RELIFT_DOWNLOAD_BASE=https://mirror.example.com/relift \
    sh install.sh --cli --bin "$HOME/bin"
  ```

- If GitHub is blocked but the site is reachable, the site mirror is enough — the
  installer stays on it and never falls back.

### `checksum mismatch, nothing was installed`

The file served by the mirror does not match the `.sha256` next to it. That is
either a truncated download or a mirror built from a different commit. Retry once;
if it fails again, install from the GitHub release instead and report it through
[`SECURITY.md`](../SECURITY.md) — an installer that ships mismatched bytes is a
supply-chain bug, not a nuisance.

### The desktop binary will not start on Linux

The window needs WebKitGTK 4.1 and the GTK stack from the host:

```bash
sudo apt install gir1.2-webkit2-4.1        # Debian/Ubuntu
sudo dnf install webkit2gtk4.1            # Fedora
sudo pacman -S webkit2gtk-4.1             # Arch
```

No display (SSH, container, CI) means no native window; the launcher opens the same
UI in your browser instead. If nothing opens either, run
`relift desktop --no-window --port 8765` and open the printed URL yourself.

### Windows says the app is unsafe

The executables are not code-signed, so SmartScreen warns on first launch:
**More info → Run anyway**. Verify the download first with
`certutil -hashfile relift-windows-x64.exe SHA256` against the `.sha256` asset.

### `relift: command not found`

`pip install --user` and the installer put binaries in `~/.local/bin`, which is not
always on `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add that line to your shell profile to make it permanent.

---

## Running a scan

### `... is not in allowed_hosts`

The scope file does not cover the target. This is the gate doing its job. Two ways
forward:

```bash
# write a scope that covers it
relift init-scope --engagement my-lab --host lab.example.com

# or let `attack` author a one-host scope for you
relift attack --target https://lab.example.com --depth 2
```

A wildcard covers exactly one label (`*.example.com` matches `a.example.com`, not
`a.b.example.com`), and a deny rule always wins over an allow rule.

### `... does not resolve`

A name is authorised by what it resolves to *now*. If DNS returns nothing, or
returns an address that is not in `allowed_hosts`, the run is refused. Add the
address or its CIDR, or fix the resolver. `127.0.0.1` and `::1` are separate
entries — the default scope carries both because `localhost` resolves to either.

### `scope ... expired`

Scope files have an expiry (30 days for `init-scope`, 24 hours for `attack`). Edit
the file and extend `expires`, or write a new one. Expiry exists so last month's
authorisation cannot silently become this month's.

### `dry run` — nothing happened

`scan` prints the plan and sends nothing unless `--execute` is given:

```bash
relift scan --target https://lab.example.com --scope scope.json --execute
```

`attack` is the exception: it runs.

### The plan is missing half the catalogue

Profiles and depth raise a ceiling; they never lower it below what the scope
allows.

- `--profile safe` (the default) drops every intrusive technique.
- Database credentials and the injection probe need **both** an intrusive scope and
  `--profile lab`.
- Depth `4` excludes external binaries on purpose, so `nmap`, `nuclei` and `nikto`
  only appear at depth `5`. A missing binary is reported as skipped with a reason,
  never silently.

### `db.credential_verify` was skipped

Either no `--db-creds` file was given, the profile is not `lab`, the scope is not
intrusive, or the engine is MSSQL (not attempted). A skipped technique always
carries its reason in the run output.

---

## Output and data

### Where are the results?

| Path | Holds |
|---|---|
| `./.relift-runs/<run-id>/run.json` | every finding, the plan and the analysis for one run (override: `RELIFT_RUNS_DIR`) |
| `~/.relift/audit.jsonl` | append-only record of authorisations, module runs and AI calls (override: `RELIFT_AUDIT_FILE`) |
| `~/.relift/scopes/` | scope files authored by `attack` (override: `RELIFT_SCOPE_DIR`) |
| `~/.relift/desktop-window.json` | remembered window size and position (override: `RELIFT_HOME`) |

`relift report --run latest` renders the newest run; `relift chains` reads the same
artefact.

### The report has no narrative

The narrative comes from the analyst. With `--no-ai` or the `offline` provider you
get the deterministic rule engine instead — same structure, blunter prose. Check
`relift providers` to see what would be selected.

### My password is in the output

It should not be, anywhere. Findings, evidence, the audit log and reports are all
redacted by key name, and provider errors are scrubbed. If you can demonstrate a
credential reaching disk or a terminal, that is a security report: use
[`SECURITY.md`](../SECURITY.md), not a public issue.

### Can I delete what it wrote?

Yes, it is your data: `rm -rf .relift-runs ~/.relift`. Nothing is sent anywhere, so
there is no server-side copy to clear.

---

## Capability questions

### Does it brute-force, spray or exploit?

No, by construction. Credentials are one attempt each from a file you supply; there
is no wordlist, no default-credential list and no retry loop. The injection module
is detection only, capped at eight requests, with no payload input. Nothing writes,
deletes or changes a target. See
[`03-RULES-OF-ENGAGEMENT.md`](03-RULES-OF-ENGAGEMENT.md).

### Why is a technique "design-only"?

The catalogue lists techniques the tool knows about, including ones deliberately not
implemented (subdomain brute-force, directory brute-force, cipher-preference
probing). A design-only row documents a decision, not a promise. `relift list
--implemented-only` hides them.

### Does it phone home?

No telemetry, no update check, no license server. The only outbound traffic is what
a planned technique sends to the target, plus whatever an AI provider you configured
receives — and every provider is opt-in.

### Can I run it against a client's infrastructure?

Only with written authorisation, and only within the scope file you write for that
engagement. The scope file is the record: it carries `authorized_by`, `expires` and
`acknowledge_authorization`. Unauthorised scanning is a criminal offence in most
jurisdictions. When in doubt, do not.

---

## Contributing and reporting

Bug reports and feature requests: [Issues](https://github.com/jaylukdevelopment/relift/issues).
Security issues: [`SECURITY.md`](../SECURITY.md), never a public issue. How to build
and add a technique: [`CONTRIBUTING.md`](../CONTRIBUTING.md).
