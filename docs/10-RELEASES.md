# Releases and distribution

The canonical release is a GitHub Release. The Linux builds are mirrored on the
project site so the one-line installer works without a GitHub account.

## Cutting a release

1. Bump `version` in [`pyproject.toml`](../pyproject.toml).
2. Move the changelog entries under the new version in
   [`CHANGELOG.md`](../CHANGELOG.md).
3. Run the suite and the linter:

   ```bash
   pytest -q
   ruff check src tests packaging
   ```

4. Commit, tag, push:

   ```bash
   git commit -am "Release 0.2.0"
   git tag -a v0.2.0 -m "Relift 0.2.0"
   git push origin main --tags
   ```

The tag starts [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which has four jobs:

| Job | Produces |
|---|---|
| `dist` | sdist, wheel and the portable `relift.pyz`; installs the wheel and runs `relift list` |
| `binary` | `relift-linux-x64` (Ubuntu 22.04, glibc 2.35+) and `relift-windows-x64.exe` |
| `desktop` | `relift-desktop-linux-x64` and `relift-desktop-windows-x64.exe` from `packaging/relift-desktop.spec` |
| `publish` | one GitHub Release with every asset, each next to its `.sha256`, plus generated notes |

The desktop job smoke-tests the binary before publishing: it starts the server
with `--no-window`, fetches `/` for `RELIFT_BOOT`, fetches `/app.js`, and asserts
the bundled archive contains `splash.html`. A binary that cannot serve its own UI
never reaches a release.

## Assets

| Asset | Platform | Runtime needs |
|---|---|---|
| `relift-linux-x64` | Linux x86-64 | glibc 2.35 or newer |
| `relift-windows-x64.exe` | Windows 10/11 x64 | none |
| `relift-desktop-linux-x64` | Linux x86-64 | WebKitGTK 4.1 (`gir1.2-webkit2-4.1`) for the window; falls back to a browser |
| `relift-desktop-windows-x64.exe` | Windows 10/11 x64 | WebView2 (ships with Windows 10/11); falls back to Edge |
| `relift.pyz` | any OS | Python 3.9+ |
| `relift-<version>-py3-none-any.whl` | any OS | Python 3.9+ |

The desktop binaries bundle PyGObject and the UI assets, but **not** GLib, GTK or
libstdc++: those come from the host, because a 22.04 copy shadows the newer
libraries on a current distribution and WebKitGTK refuses to load. See the top of
[`packaging/relift-desktop.spec`](../packaging/relift-desktop.spec).

Nothing is code-signed. Windows SmartScreen warns on first launch
(**More info → Run anyway**); Linux has no signature story beyond the published
checksum.

## Checksums

Every asset has a `<asset>.sha256` sidecar in the release. Verify before running:

```bash
sha256sum -c relift-linux-x64.sha256
```

## The installer and the site mirror

```bash
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh -s -- --cli
curl -fsSL https://pixelcity.dev/lab/relift/install.sh | sh -s -- --bin "$HOME/bin"
```

The script tries `https://pixelcity.dev/lab/relift/downloads` first, then
`https://github.com/jaylukdevelopment/relift/releases/latest/download`, verifies
the checksum and installs one binary. Override the mirror with
`RELIFT_DOWNLOAD_BASE` when testing a staging build.

The mirror is updated by copying the freshly built Linux binaries and their
`.sha256` files into the site's `public/downloads/` directory and redeploying the
site container. Keep the mirror in step with the tag; the installer and the
download page both point at it.

## Manual build

The release workflow is the supported path. For a local build matching it:

```bash
docker build -f /dev/stdin -t relift-builder . <<'EOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dev python3-venv python3-pip build-essential \
    libgirepository1.0-dev libcairo2-dev pkg-config \
    libgtk-3-0 libwebkit2gtk-4.1-0 gir1.2-webkit2-4.1
RUN python3 -m venv /venv && /venv/bin/pip install pyinstaller pywebview "pygobject==3.50.0"
EOF

docker run --rm -v "$PWD:/src" -w /src relift-builder \
  bash -lc 'pip install -e . && python -m PyInstaller --clean --noconfirm \
    --distpath dist packaging/relift-desktop.spec'
```

## If a release is wrong

Publish a patch release. Do not move or delete a tag that users may already have
downloaded; the checksum in the release notes is the audit trail. If an asset is
actively dangerous, delete that asset (not the tag), publish an advisory through
`SECURITY.md`, and ship the fix in the next patch.
