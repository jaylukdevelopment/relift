# Relift — Desktop Application

`relift desktop` starts one loopback HTTP server and points a window at it. The
server is the same Python process, on the same machine, calling the same engine
functions as the CLI: `load_scope`, `scope.authorize`, `make_plan`, `execute`,
`write_run`. There is no desktop-specific scan path, and therefore no
desktop-specific way around the scope gate.

It is not an Electron app. The UI is four static assets — three served over HTTP
plus the splash the launcher renders itself — the backend is the standard library,
and the native window is provided by `pywebview` (WebView2 on Windows, WebKitGTK on
Linux) when it is installed. When it is not installed, or when there is no display,
the same URL opens in the default browser and nothing else changes.

---

## 1. Architecture

```
relift desktop
      |
      +-- ThreadingHTTPServer on 127.0.0.1:<ephemeral port>
      |        |
      |        +-- GET  /            app.html  (+ injected bootstrap)
      |        +-- GET  /app.css     app.css
      |        +-- GET  /app.js      app.js
      |        +-- /api/*            JSON, token required
      |
      +-- pywebview window  ---or---  webbrowser.open(url)
```

| File | Role |
|---|---|
| `src/relift/api.py` | server, router, job runner, static asset serving |
| `src/relift/desktop.py` | launcher: bind port, start server, open window or browser |
| `src/relift/desktop/app.html` | single page |
| `src/relift/desktop/app.css` | styles |
| `src/relift/desktop/app.js` | UI logic, calls `/api/*` with the token |
| `src/relift/desktop/splash.html` | startup animation, inlined and shown while the server boots |

Only the three HTTP assets are served, from a fixed whitelist keyed by exact path.
There is no path joining, no directory listing and no template rendering of user
input. `favicon.ico` returns `204`. The splash is read from the package by the
launcher and injected into its own frameless window, so it is never a route.

The HTML is served with a small script injected immediately before `</head>`:

```html
<script>window.RELIFT_BOOT={token:"…",version:"0.4.0"};</script>
```

`app.js` reads `window.RELIFT_BOOT.token` and sends it on every call.

---

## 2. Security model

The desktop app holds the same line as the CLI, plus a few local-interface
precautions.

**Same gate.** A scan is only started after `load_scope(path)` parses and
validates the file and `scope.authorize(target.host)` accepts the target. A
refusal is returned as HTTP `403` with the same `ScopeError` text the CLI prints.
The UI has no field that can widen a scope; the only way to change one is to
edit the file. `POST /api/init-scope` writes a scope with `allow_intrusive:
false` and refuses to create an intrusive one from the app at all — that stays a
hand edit.

**Loopback only.** The server binds `127.0.0.1`. It is not reachable from the
network, including from another container on the same host unless that container
shares the host network namespace.

**One-time token.** A `secrets.token_urlsafe(24)` value is generated at launch
and required in the `X-Relift-Token` header on every `/api/*` request
(`secrets.compare_digest`). A request without it gets `401`. The token is never
placed in a URL, never logged and never written to disk.

**No CORS.** No `Access-Control-Allow-*` header is ever sent, and `OPTIONS`
returns `405`. A page on another origin cannot read the token or the responses.
When an `Origin` header is present it must match the request's own `Host`, which
blocks a form-post style CSRF attempt even with a guessed token.

**No request logging.** `Handler.log_message` is a no-op so a token or a run id
cannot end up in a terminal, a log file or a syslog collector.

**Response hardening.** `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. JSON request
bodies are capped at 256 KiB.

**No credential persistence.** `POST /api/scan` accepts credentials in the
request body for a single run (the same one-attempt verification the CLI does
with `--db-creds`). They are held in memory for that job, never written to
`run.json`, the audit log or the UI's storage.

**Loopback job state.** Up to 20 jobs are kept in memory; run artefacts still go
to `.relift-runs/<run_id>/run.json` like any CLI run, and the audit log is the
same `~/.relift/audit.jsonl`.

---

## 3. API

All `/api` responses are JSON. Errors are `{"error": "..."}` with a status code
(`400` bad input, `401` token, `403` scope refusal, `404` unknown run/job,
`413` body too large, `500` unexpected).

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/meta` | — | version, banner, catalogue counts, categories, profiles, provider matrix, `runs_root`, `audit_path`, `cwd` |
| GET | `/api/catalog` | — | `{ "techniques": [ … ] }` — the same objects as `relift list --json` |
| GET | `/api/providers` | — | `{ "selected": "offline", "providers": [ … ] }` |
| GET | `/api/runs` | — | `{ "runs_root": "…", "runs": [ {run_id, target, started, profile, engagement, findings, chains, severities} ] }` (50 newest) |
| GET | `/api/audit` | — | `{ "path": "…", "lines": [ … ] }` — last 120 audit lines |
| POST | `/api/scope` | `{ "path": "scope.json" }` | the parsed scope document (`to_dict()`) |
| POST | `/api/init-scope` | `{ "engagement", "hosts": [], "denied": [], "path", "authorized_by", "organization", "expires_in_days", "max_risk", "ports": [], "notes" }` | `{ "path": "…", "scope": { … } }` |
| POST | `/api/plan` | `{ "target", "scope", "profile" }` | the plan (`make_plan(...).to_dict()`), no traffic beyond DNS |
| POST | `/api/scan` | `{ "target", "scope", "profile", "ports", "timeout", "insecure", "db_creds": [], "sqli_url", "sqli_param" }` | `{ "job_id": "…" }` |
| GET | `/api/jobs/<id>` | — | job state: `id`, `status` (`queued`/`running`/`done`/`refused`/`error`), `lines`, `run_id`, `error`, `run` (the full run payload when finished) |
| GET | `/api/runs/<id>` | — | the stored run payload, with `chains` recomputed if the artefact predates them |
| GET or POST | `/api/runs/<id>/report` | `{ "format": "md" \| "text" \| "json" }` | `{ "format", "text", "run_id" }` |
| POST | `/api/runs/<id>/narrative` | `{}` | `{ "run_id", "narrative", "provider", "notes" }` — re-runs the analyst against the stored run; the UI's **Regenerate narrative** button uses it |

Notes:

- `db_creds` in `/api/scan` is the **list of credential objects**, not a path.
  Same shape as the `credentials` array in a CLI credentials file
  (`engine`, `host`, `port`, `username`, `password`, `database`).
- `profile: "lab"` is rejected unless the scope itself allows intrusive work, so
  the UI cannot talk its way past the tier ceiling.
- Narrative regeneration is a read of the stored run plus a model call: it never
  re-scans, so it cannot send traffic. With `--no-ai` or an offline provider it is
  deterministic (the rule engine), and the same text can be produced from the CLI
  with `relift report --run <id> --no-ai`.

### Example

The token is handed to the page (`window.RELIFT_BOOT.token`) and is never printed to
a terminal, so a second shell cannot scrape it. To poke the API by hand, start the
app with `--debug`, open the WebView devtools, read the token from
`window.RELIFT_BOOT.token`, and use it in the header:

```bash
# start headless on a chosen port
relift desktop --no-window --port 8765

# the request shape the UI itself uses
curl -s -H "X-Relift-Token: $TOKEN" http://127.0.0.1:8765/api/meta | jq .
```

```bash
curl -s -X POST http://127.0.0.1:8765/api/plan \
  -H "X-Relift-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"postgres://127.0.0.1:5432/appdb","scope":"scope.json","profile":"safe"}' | jq '.techniques[].id'
```

---

## 4. Running it

```bash
# native window when pywebview is available, browser otherwise
relift desktop

# the console-script alias installed by pip
relift-desktop

# serve only, print the URL, no window (useful over SSH)
relift desktop --no-window --port 8765
```

| Flag | Default | Meaning |
|---|---|---|
| `--port N` | `0` | `0` picks a free ephemeral port |
| `--no-window` | off | serve only; print the URL instead of opening a window |
| `--browser` | off | open the console in the default browser instead of a native window |
| `--no-splash` | off | skip the startup animation and show the console immediately |
| `--debug` | off | enable the WebView devtools (and the token, above) |

`Ctrl+C` stops the server. If a native window is used, closing the window stops
the server.

### One-line install (Linux x86-64)

```bash
# latest release, checksum verified, into ~/.local/bin
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh

# the engine without the window
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh -s -- --cli

# choose the directory
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh -s -- --bin "$HOME/bin"
```

The script resolves the newest release asset, compares it with the published
`.sha256`, and installs one binary (`relift-desktop` or `relift`). Windows has
no shell installer; download the `.exe` from the release page.

### Native window

```bash
python -m pip install -e ".[desktop]"
```

That pulls in `pywebview`. The window is created at 1280×880 (minimum 1000×700)
and loads the same loopback URL. Position and size are remembered in
`~/.relift/desktop-window.json` (override the directory with `RELIFT_HOME`), so a
window moved to a second monitor comes back there; a window that would open
entirely off-screen is pulled back onto the visible area.

A frameless 420×268 splash runs while the server starts and stays for at least
1.35 s, so the animation is never cut off. `--no-splash` skips it.

If importing or starting `pywebview` fails for any reason — missing GTK, missing
WebView2, headless session — the launcher falls back to the default browser
instead of failing.

| Platform | Window runtime | Package |
|---|---|---|
| Windows 10/11 | WebView2 (Evergreen) | preinstalled on 11; install the Evergreen Runtime on 10 |
| Debian/Ubuntu | WebKitGTK | `sudo apt install python3-gi gir1.2-webkit2-4.1` |
| Fedora | WebKitGTK | `sudo dnf install python3-gobject webkit2gtk4.1` |
| Arch | WebKitGTK | `sudo pacman -S python-gobject webkit2gtk-4.1` |

None of this is required for the CLI, and none of it changes what the tool is
allowed to do.

---

## 5. Building the desktop binaries

The release pipeline builds two windowed executables from the same source:

| Asset | Platform |
|---|---|
| `relift-desktop-windows-x64.exe` | Windows 10/11 x64 |
| `relift-desktop-linux-x64` | Linux x86_64 (built on Ubuntu 22.04) |

Local build, Linux (PyInstaller's `--add-data` separator is `:`):

```bash
python -m pip install --upgrade pyinstaller "pywebview>=4"
python -m PyInstaller --onefile --windowed --clean --noconfirm \
  --name relift-desktop \
  --paths src \
  --add-data "src/relift/desktop:relift/desktop" \
  packaging/desktop_entry.py
./dist/relift-desktop --no-window --port 8765
```

Windows (separator is `;`):

```bat
python -m PyInstaller --onefile --windowed --clean --noconfirm ^
  --name relift-desktop ^
  --paths src ^
  --add-data "src\relift\desktop;relift\desktop" ^
  packaging\desktop_entry.py
```

`relift.desktop.static_root()` looks for the assets under
`sys._MEIPASS/relift/desktop` first, which is why the `--add-data` target is
`relift/desktop`. Without it the window loads and every asset request 500s with
`UI asset missing`.

The CLI binaries (`relift-windows-x64.exe`, `relift-linux-x64`) are built the
same way without `--windowed` or `--add-data`. Both are unsigned: SmartScreen
will warn on first launch on Windows.

---

## 6. What the desktop app does not add

It does not add capability, only a second front end. Everything it can do, the
CLI can do — and the CLI is the reference for flags, tiers and output. If the
two ever disagree, the CLI is correct and the API is the bug.
