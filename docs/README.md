# Relift documentation

Start with the README if you only want to run the tool. This directory is the
long form: what it refuses to do, how each layer is built, and how a release is
cut.

| Document | Read it when you want to know |
|---|---|
| [`00-PROJECT-PLAN.md`](00-PROJECT-PLAN.md) | Why the project exists, what is in scope, milestones and acceptance criteria |
| [`01-ARCHITECTURE.md`](01-ARCHITECTURE.md) | How the layers fit: scope → plan → modules → findings → threads → report |
| [`02-ATTACK-CATALOG.md`](02-ATTACK-CATALOG.md) | What each technique touches and what tier it runs at |
| [`03-RULES-OF-ENGAGEMENT.md`](03-RULES-OF-ENGAGEMENT.md) | The scope schema, the gate, deny rules, expiry, and the excluded classes |
| [`04-AI-PROVIDERS.md`](04-AI-PROVIDERS.md) | Provider matrix, environment variables, prompt contract, guardrails |
| [`05-ROADMAP.md`](05-ROADMAP.md) | Phases to `1.0`, release gates, and what is deliberately not planned |
| [`06-CLI-REFERENCE.md`](06-CLI-REFERENCE.md) | Every command and flag, target forms, exit codes, output shapes |
| [`07-DATABASE-AUDIT.md`](07-DATABASE-AUDIT.md) | Wire protocols, credential file, privilege grading, lab recipes |
| [`08-DESKTOP.md`](08-DESKTOP.md) | Desktop architecture, API table, security model, build commands |
| [`09-SITE.md`](09-SITE.md) | The public page and how it relates to the tool |
| [`10-RELEASES.md`](10-RELEASES.md) | Versioning, tag flow, release assets, installer, checksum verification |
| [`11-FAQ.md`](11-FAQ.md) | Install failures, scope refusals, missing techniques, where the data lives |

## Reading order

1. **Operator:** [`03-RULES-OF-ENGAGEMENT.md`](03-RULES-OF-ENGAGEMENT.md), then
   [`06-CLI-REFERENCE.md`](06-CLI-REFERENCE.md). Stuck on the first run?
   [`11-FAQ.md`](11-FAQ.md).
2. **Reviewer or new contributor:** [`01-ARCHITECTURE.md`](01-ARCHITECTURE.md),
   [`02-ATTACK-CATALOG.md`](02-ATTACK-CATALOG.md), then
   [`CONTRIBUTING.md`](../CONTRIBUTING.md).
3. **Packager:** [`08-DESKTOP.md`](08-DESKTOP.md) and
   [`10-RELEASES.md`](10-RELEASES.md).

## Documentation rules

- If a document disagrees with the code, the code is right and the document is a
  bug. CI checks the catalogue and the command surface; prose is reviewed by
  humans.
- New technique → a row in the catalogue document, in the same pull request.
- New command or flag → `06-CLI-REFERENCE.md`, in the same pull request.
- Never paste real hostnames, credentials, tokens or customer data into an
  example. Use `example.com`, RFC 5737 addresses or `127.0.0.1`.
