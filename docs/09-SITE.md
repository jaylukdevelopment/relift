# The public site and download mirror

The page is maintained separately from this repository. This document records
what is public, where it is served from, and the two things the site reads out of
this repository.

| URL | Serves |
|---|---|
| <https://pixelcity.dev/lab/relift> | Landing page, scroll scenes, scope-gate demo |
| <https://pixelcity.dev/lab/relift/download> | Download cards, install command, checksums |
| <https://pixelcity.dev/lab/relift/docs> | This `docs/` directory, rendered at image build |
| <https://pixelcity.dev/lab/relift/install.sh> | The checksum-verifying installer |
| <https://pixelcity.dev/lab/relift/downloads/> | Linux binary mirror used by the installer |

`relift.pixelcity.dev` redirects to the lab path. `pixelcity.top` and
`www.pixelcity.top` serve the same container.

## Serving

The site is a Next.js container, `relift-site`, attached to the external
`pixelcity_net` network. Caddy (`/opt/caddy/Caddyfile`) terminates TLS and routes
`/lab/relift*` to `relift-site:3000`; everything else on `pixelcity.dev` goes to
the main site. The container listens on 3000, binds no host port, and runs as a
non-root user.

```bash
# on the server
cd /opt/relift-site/src
docker build -f site/Dockerfile -t relift-site:latest .
cd /opt/relift-site && docker compose up -d
```

Caddy validates a new config before reloading:

```bash
docker exec caddy caddy validate --config /etc/caddy/Caddyfile
docker exec caddy caddy reload  --config /etc/caddy/Caddyfile
```

Back up the Caddyfile first: `cp Caddyfile Caddyfile.bak-$(date +%F-%H%M)`.

## What the site takes from this repository

1. **Documentation.** At image build, `docs/` is copied in and the docs pages are
   generated from the Markdown. A doc fix reaches the site only on redeploy.
2. **The Linux mirror.** The binaries in `/lab/relift/downloads` are the same
   files published on the GitHub release, plus their `.sha256` sidecars. The
   installer tries this mirror first and falls back to the GitHub release.

The Windows executables are not mirrored; the download page links the GitHub
release for those. See [`10-RELEASES.md`](10-RELEASES.md) for the asset matrix.

## Checks

The site repository owns its own gates (type check, production build, design
inspection). For this repository, the only relevant check is that every internal
documentation link resolves and that a release keeps the docs accurate.
