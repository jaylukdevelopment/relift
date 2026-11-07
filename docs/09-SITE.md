# The Relift site

The product site lives in `site/`: Next.js 15 (App Router, React 19), TypeScript,
plain CSS tokens, and one Three.js scene. No CSS framework, no animation library,
no analytics.

- **Landing** — `/` — split hero with a working scope gate, a scroll-driven
  Three.js "descent" through the four layers the tool walks, three states of a
  real finding, the thread panel with margin notes, a plan/execute example, four
  measured marks, FAQ and a closing call to action.
- **Download** — `/download` — binaries per platform from the GitHub release,
  with checksums, plus the package and from-source routes.
- **Docs** — `/docs` and `/docs/<slug>` — the repository's own `docs/*.md`,
  copied in at build time by `site/scripts/sync-docs.mjs`.

## Run it locally

```bash
cd site
npm install
npm run sync-docs      # refresh content/docs from ../docs
npm run dev            # http://localhost:3000
```

The scope gate, the scene and the state toggle are client components; everything
else is rendered on the server. The reveal animation only moves content — nothing
is hidden when the script fails.

## Build the image

The build context is the repository root, because the docs are part of the image:

```bash
docker build -f site/Dockerfile -t relift-site:latest .
docker run -d --rm -p 3000:3000 --name relift-site relift-site:latest
```

The image is a three-stage build (deps / build / runner) and runs `next start`'s
standalone server as a non-root user on port 3000.

## Deploy

The site runs on `pixelcity.dev` as the container `relift-site`, attached to the
external `pixelcity_net` network, and is published by the Caddy container in
`/opt/caddy`.

```bash
# on the build machine
docker build -f site/Dockerfile -t relift-site:latest .
docker save relift-site:latest | gzip -1 | ssh root@pixelcity.dev 'gunzip | docker load'

# on the server (compose file is in the repository at site/docker-compose.yml)
ssh root@pixelcity.dev 'mkdir -p /opt/relift-site'
scp site/docker-compose.yml root@pixelcity.dev:/opt/relift-site/
ssh root@pixelcity.dev 'cd /opt/relift-site && docker compose up -d'
```

Caddy block (already in `/opt/caddy/Caddyfile`):

```
http://relift.pixelcity.dev {
	redir https://relift.pixelcity.dev{uri} permanent
}

relift.pixelcity.dev {
	encode zstd gzip
	import accesslog
	reverse_proxy relift-site:3000 {
		header_down -Via
		header_down -Server
	}
}
```

Reload Caddy after editing (it validates first):

```bash
docker exec caddy caddy validate --config /etc/caddy/Caddyfile
docker exec caddy caddy reload  --config /etc/caddy/Caddyfile
```

Back up the Caddyfile before any edit: `cp Caddyfile Caddyfile.bak-$(date +%F-%H%M)`.

## Checks

```bash
npx tsc --noEmit                 # types
npm run build                    # production build, all routes pre-rendered
node <taste-skill>/scripts/lint.mjs app components
node <taste-skill>/scripts/inspect.mjs http://127.0.0.1:3000
```

The last two are the design gates described in the skill; the inspector reports
0 FAIL at 1440, 768 and 390. Its two remaining warnings are deliberate: there is
no footage (the WebGL scene is the moving image) and the closing panel is a
left-aligned statement over a full field of colour.

Screenshots in `site/public/shots/` are real captures of the desktop application
from a lab run (`node site/scripts/shoot.mjs http://127.0.0.1:8796`), not mock-ups.
