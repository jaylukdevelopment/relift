# Security policy

Relift is a security tool. Bugs in it are security bugs by definition, and the
ones below matter most.

## Supported versions

| Version | Supported |
|---|---|
| `0.2.x` | yes |
| older | no |

While the project is pre-`1.0`, only the latest minor receives fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository:

**Security → Advisories → Report a vulnerability**
(<https://github.com/jaylukdevelopment/relift/security/advisories/new>)

Do not open a public issue, and do not include working exploit details in a
pull request. Please include:

- affected version (`relift --version`) and platform,
- the command line or API request that triggers it,
- what you expected versus what happened,
- the smallest reproduction you can build, ideally against `127.0.0.1`,
- whether the issue is reachable without a scope file.

You get an acknowledgement within 72 hours. A fix or a written explanation why
the behaviour is intended follows within 30 days for high-severity reports.
Credit is given in the advisory and the changelog unless you ask otherwise.

## What is in scope

- **Scope-gate bypass.** Any way to make a technique run against a host that the
  loaded scope does not allow, to ignore a deny rule, to use an expired scope, or
  to skip the `acknowledge_authorization` check.
- **Authorisation or privilege escalation in the desktop API.** Reaching `/api`
  without the per-launch token, reading another process's token, DNS rebinding
  against the loopback server, or escaping the three-file static whitelist.
- **Credential exposure.** A password, token or API key reaching the audit log,
  a run artefact, a terminal line, an AI provider, or an error message.
- **Command injection.** Shell metacharacters surviving into an `nmap`, `nuclei`
  or `nikto` invocation, or into any subprocess argument.
- **SSRF or arbitrary file access** through target parsing, the credential file
  loader, report paths, or the run store.
- **Crash or memory-safety issue** in a stdlib protocol parser reachable from a
  hostile server response (banners, certificates, TDS, Redis, Mongo, PostgreSQL).

## What is out of scope

- Findings reported by Relift against a target. Those describe the target, not
  Relift; report them to the target's owner.
- Missing security headers, TLS configuration or open ports on the project's own
  websites, unless they expose user data.
- Denial of service, volumetric testing, or anything requiring a compromised
  operator machine.
- Social engineering, phishing, or physical access.
- The absence of a feature (for example "no brute-force mode"). That is a design
  decision, documented in [`docs/03-RULES-OF-ENGAGEMENT.md`](docs/03-RULES-OF-ENGAGEMENT.md).

## Safe harbour

Testing Relift against infrastructure you own, or against a local instance you
started for the purpose, is authorised. Testing against Pixelcity infrastructure
is not authorised unless you have written permission. If in doubt, ask first.
