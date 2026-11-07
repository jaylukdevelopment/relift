# Relift — Rules of Engagement

This document is the reason the tool is safe to own. Read it before the first run
against anything that is not `127.0.0.1`.

## 1. The one rule

**Only targets listed in an active scope file, for an engagement you are authorised
to perform.**

Relift enforces this mechanically:

- No scope file → the `scan` command exits `2` before sending a packet.
- Target host not matched by `allowed_hosts` → exit `2`.
- Target matched by `denied_hosts` → exit `2`, even if also allowed.
- Scope file expired → exit `2`.
- `acknowledge_authorization` not `true` → exit `2`.

There is no `--force`, no `--yes-i-know`, no environment variable that bypasses the
gate. The only way to widen the scope is to edit the scope file, whose SHA-256 is
recorded in every run artefact and every audit line.

## 2. Scope file schema

`relift init-scope` writes a starting point; edit it by hand afterwards.

```json
{
  "engagement": "homelab-2026-11",
  "authorized_by": "Jay",
  "organization": "Pixelcity",
  "acknowledge_authorization": true,
  "expires": "2026-12-31T23:59:59Z",
  "allowed_hosts": [
    "127.0.0.1",
    "localhost",
    "10.10.10.0/24",
    "*.lab.pixelcity.dev"
  ],
  "denied_hosts": ["10.10.10.1"],
  "max_risk": "safe",
  "allow_intrusive": false,
  "allow_wide_ranges": false,
  "rate_limit_rps": 5,
  "ports": [22, 80, 443, 8000, 8080, 8443],
  "notes": "Own lab. Router and NAS excluded."
}
```

| Field | Required | Meaning |
|---|---|---|
| `engagement` | yes | Name that appears in the audit log and every report |
| `authorized_by` | yes | Human who owns the decision |
| `organization` | no | Company or household the infrastructure belongs to |
| `acknowledge_authorization` | yes | Must be exactly `true` |
| `expires` | yes | ISO-8601 UTC. Expired scope = no scope. |
| `allowed_hosts` | yes | Hostnames, `*.suffix` wildcards, IPv4/IPv6 literals, CIDRs |
| `denied_hosts` | no | Same syntax. **Always wins** over the allow list. |
| `max_risk` | no | `passive` \| `safe`. Caps the profile. Default `safe`. |
| `allow_intrusive` | no | Must be `true` *and* `--profile lab` for tier-3 modules |
| `allow_wide_ranges` | no | Permits CIDRs broader than /22. Off by default. |
| `rate_limit_rps` | no | Requests/connections per second, global. Default `5`. |
| `ports` | no | Port set for sweeps. Defaults to the common web/ssh set. |
| `notes` | no | Free text, copied into the audit line |

### Matching semantics

| Pattern | Matches |
|---|---|
| `example.com` | exactly `example.com` (case-insensitive) |
| `*.example.com` | any subdomain, **not** the apex |
| `10.10.10.0/24` | any address inside the CIDR |
| `::1` | the IPv6 literal, normalised |

Hostnames are resolved **before** matching, and the resolved address is also checked
against the scope. A hostname in `allowed_hosts` that resolves to an out-of-scope
address is refused — this is what stops a stale DNS record or a hosts-file trick
from turning a lab scan into a scan of a stranger's VPS.

### The wide-range guard

`0.0.0.0/0`, `10.0.0.0/8`, a stray `192.168.0.0/16` for "just the router": all of
these are one typo away from a very bad afternoon. CIDRs broader than `/22`
(1022 hosts) are refused unless the scope file sets `allow_wide_ranges: true`.

## 3. Tiers and consent

| Tier | Runs when |
|---|---|
| `passive` | always (profile ≥ passive) |
| `safe` | profile `safe`, `standard` or `lab`, and `max_risk` ≥ safe |
| `intrusive` | `max_risk: intrusive` **and** `allow_intrusive: true` **and** `--profile lab` |
| `destructive` | never — not implemented |

Two independent switches for tier 3 is deliberate. A tired operator at 2 a.m. should
not be one flag away from a path brute-force against a client's production site.

## 4. Rate limiting

`rate_limit_rps` is a global budget, not per module. Every network operation in every
module calls `ctx.throttle()` first. The default of 5 is chosen to be slow enough that
a small service does not notice and fast enough that a /24 sweep is not an all-nighter.

If you need to go faster, you are probably scanning something you should not be.

## 5. Audit trail

Every run appends to `~/.relift/audit.jsonl`:

```json
{"ts":"2026-11-07T12:00:01+00:00","event":"authorize","engagement":"homelab-2026-11",
 "target":"http://127.0.0.1:8080","decision":"allow","scope_sha256":"9f2c…",
 "authorized_by":"Jay"}
```

Recorded: engagement, target, decision, scope hash, profile, module executions,
AI provider used, run ID. **Never recorded:** credentials, response bodies, API keys.

Keep this file. It is your evidence that a scan was in scope, and it is the first
thing you want if a network admin asks what that traffic was.

## 6. Operational hygiene

- **Announce your own sweeps.** Tell whoever watches the network, or you will be the
  incident. Include the engagement name and a time window.
- **Snapshot before, restore after.** For anything with a stateful auth module in the
  plan, take a VM snapshot. Cheap insurance.
- **Never run from a network you do not control into one you do not own**, even
  with a scope file — your source address becomes part of someone else's problem.
- **Read the findings before the report.** The AI narrative is a convenience; the
  `evidence` fields are the truth.
- **Stop on the first unexpected service.** If a port you did not know about answers,
  that is a conversation with the owner, not a module to add.

## 7. Excluded by design

These are not "not yet implemented". They are rejected.

| Class | Why |
|---|---|
| Denial of service, resource exhaustion | Availability is the one thing you cannot un-break from a terminal |
| Exploit delivery / payload staging | Turns an assessment into an intrusion |
| Credential brute-force and password spraying | Lockouts harm real users; success crosses into unauthorised access |
| Default/vendor credential checks | One step from actual break-in; excluded in every profile |
| Persistence, lateral movement, C2 | Out of scope for an assessment tool by definition |
| Data exfiltration or tampering | Destroys the evidence you were asked to produce |
| Wireless / physical / social engineering | Different discipline, different consent model |

If the roadmap ever needs one of these, the answer is a different tool with a
different name, a different review and a signed contract — not a flag on this one.

## 8. Legal notes (non-exhaustive)

| Jurisdiction | Statute |
|---|---|
| Germany | StGB §202a (data espionage), §202b (interception), §202c (preparation), §303a (data manipulation) |
| EU | Directive 2013/40/EU on attacks against information systems |
| UK | Computer Misuse Act 1990, ss. 1–3ZA |
| US | Computer Fraud and Abuse Act, 18 U.S.C. §1030 |

Port scanning alone has been prosecuted. "I was only scanning" is not a defence you
want to test. Written authorisation naming the hosts is.

## 9. If something goes wrong

1. Stop the run (`Ctrl+C`; the runner records the partial run before exiting).
2. Note the run ID from the terminal.
3. Tell the target's owner immediately, with the run artefact, not a paraphrase.
4. Preserve `~/.relift/audit.jsonl` and `.relift-runs/<id>/`.
5. Do not delete anything, including the evidence that you were in scope.
