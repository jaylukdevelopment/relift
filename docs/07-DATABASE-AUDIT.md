# Relift — Database Audit Reference

Relift talks to databases twice: once without credentials, to describe the
listener and its security posture, and once with credentials **you already
hold**, to confirm they still work. There is no third mode. Nothing here writes,
extracts, enumerates or guesses.

The short version:

| Question | Technique | Tier | Needs a credential |
|---|---|---|---|
| What is this listener, which version, is TLS possible? | `db.fingerprint` | safe | no |
| Does it require auth, which method, is the build still supported? | `db.security_config` | safe | no |
| Does this credential I found still work, and how powerful is it? | `db.credential_verify` | intrusive | yes, yours |

---

## 1. Target forms

A database target is a scheme, host, optional port and optional database name:

```
postgres://127.0.0.1:5432/appdb
mysql://10.10.10.20:3306/appdb
redis://10.10.10.20:6379
mongodb://10.10.10.20:27017
mssql://10.10.10.20:1433
elasticsearch://10.10.10.20:9200
couchdb://10.10.10.20:5984
```

Accepted aliases: `postgresql`, `mariadb`, `rediss`, `sqlserver`, `tds`,
`opensearch`, `es`. Default ports come from the scheme, so the port is optional.
The path segment becomes the database name for engines that need one.

Scope matching is unchanged: the **host** must be in `allowed_hosts`, deny rules
win, and a hostname is resolved before it is authorised. The scheme is not part
of the scope decision — the same host you are allowed to scan over HTTPS is the
host you are allowed to audit over TCP/5432, if the scope says so.

The plan is filtered by target family. A wire-protocol database target gets
`recon.*`, `db.*`, `analysis.*` and the narrative; it does not get `web.*` or
`tls.*`. Elasticsearch and CouchDB are the exception: they speak HTTP, so their
targets carry both families, which means the web header/method checks **and** the
TLS checks run against them too.

```bash
relift plan --target postgres://127.0.0.1:5432/appdb --scope scope.json
```

---

## 2. What is spoken, engine by engine

There are no database drivers in this repository. Every engine is spoken to
over a small, bounded implementation of its wire protocol in
`src/relift/modules/dbproto.py`. That is deliberate: a driver hides exactly the
facts an audit needs — whether the listener negotiates TLS, which auth method it
asks for, and whether it answers without credentials at all.

| Engine | Protocol work | Read before authentication |
|---|---|---|
| PostgreSQL | SSLRequest (`S`/`N`), then StartupMessage v3 | TLS capability, auth type (trust / cleartext / md5 / SCRAM), SASL mechanism list, and on trust: `server_version`, encoding, timezone from ParameterStatus |
| MySQL / MariaDB | Reads the server handshake, then `COM_QUIT` | Version, protocol version, capability flags, auth plugin name, connection id, TLS bit, `CLIENT_SECURE_CONNECTION` |
| MSSQL | TDS pre-login request/response | Build number, encryption setting (`off`/`on`/`not-supported`), instance name |
| Redis | `PING`, then `INFO server` | Whether a reply arrives at all (i.e. whether auth is required), `redis_version`, mode, config file, git sha |
| MongoDB | OP_MSG `hello` (falls back to `isMaster`) | Version, max wire version, advertised SASL mechanisms |
| Elasticsearch | one `GET /` | Version, cluster name, tagline; a 401 is itself the answer |
| CouchDB | one `GET /` | Version, vendor, whether the root is open |

### Why reading before authentication is legitimate

Everything in that column is what the protocol hands to *any* connecting client
before a credential is presented, or what the vendor documents as
unauthenticated metadata. It is the same information `nmap -sV`, `psql`'s
startup banner or a replica's handshake would reveal. It is not application
data, and no query touches a table.

MongoDB is the case worth stating explicitly: `hello` succeeds without
credentials by design. A reachable `hello` therefore proves reachability and
nothing else, so the finding for an unauthenticated MongoDB is **medium** and
says so. It only becomes a critical exposure when `db.credential_verify` proves
an actual account works (or when the operator proves data access another way).

### PostgreSQL auth type codes

| Code | Meaning | What Relift does with it |
|---|---|---|
| 0 | AuthenticationOk (trust) | Reports `auth_required: false` — critical on a reachable listener |
| 3 | Cleartext password | `cleartext_auth: true`, medium |
| 5 | MD5 password | `cleartext_auth: true` (a single-round hash is replayable), medium |
| 10/11/12 | SASL / SCRAM-SHA-256 | Reported as `scram-sha-256`, informational |

`tls_capable` is the answer to SSLRequest, not a TLS handshake: Relift records
whether the server *offers* TLS. `db.security_config` is where that becomes a
finding.

### Redis, honestly

`PING` returning `+PONG` means the listener answers commands without a
credential. That is the classic whole-datastore exposure and it is reported
critical, with the consequence stated (keys now, configuration endpoints on many
builds next). A `-NOAUTH` reply is a normal, healthy result and is reported as
informational.

---

## 3. `db.security_config` — how the posture is decided

Each finding carries the same evidence block so the correlation engine can read
it without guessing:

```json
{
  "engine": "postgres",
  "version": "16.15",
  "build": "",
  "port": 5432,
  "auth_required": true,
  "auth_method": "scram-sha-256",
  "cleartext_auth": false,
  "tls_capable": true,
  "eol": false
}
```

The severities:

| Observation | Severity |
|---|---|
| No authentication demanded — PG trust, open Redis, open MSSQL, open MySQL | critical |
| No authentication demanded — Elasticsearch or CouchDB over HTTP | high |
| MongoDB `hello` reachable | medium, with an explicit "this is reachability, not exposure" |
| Replayable credential exchange (cleartext or md5) | medium |
| Replayable credential exchange **plus** no TLS | high (the separate no-TLS finding) |
| Build past end of life, listener reachable | high |
| No TLS offered by a database listener | medium (postgres/mysql/mssql), low (redis/mongo); ES/CouchDB report it through `tls.*` instead |
| Authentication required, modern method | informational |

### End-of-life table

A version below the line no longer receives security fixes from its vendor:

| Engine | Supported from |
|---|---|
| PostgreSQL | 13.0 |
| MySQL | 8.0 |
| MariaDB | 10.6 |
| Redis | 6.2 |
| MongoDB | 5.0 |
| Elasticsearch | 7.17 |
| CouchDB | 3.0 |

The comparison is on the first numeric triple in the version string, so
`8.0.36-0ubuntu0.22.04.1` and `5.15.0-91-generic` parse correctly. A hit means
"compare the build against the vendor advisory", not "this host is exploitable".
Distributions backport fixes without changing the upstream version.

---

## 4. `db.credential_verify` — verification, not discovery

This is the only module in the tree that presents a credential, and it is
constrained by shape rather than by flags:

- **One attempt per credential.** There is no retry loop, no wordlist, no
  candidate generator, no spray mode and no rate ramp anywhere in
  `dbauth.py`. If a login is rejected, that is the result.
- **Deduplicated** by `(engine, username)`, so the same account listed twice is
  checked once.
- **One protocol-shape retry exists**, and only for Redis: Redis 5 rejects
  `AUTH <user> <pass>` with a syntax error because ACL users do not exist there,
  so the same password is re-sent as `AUTH <pass>`. That is a reply to a
  malformed command, not a second guess at the secret.
- **The password never leaves the process.** It is not written to the finding,
  the evidence, the detail, an exception message or the audit log, and server
  errors are scrubbed before they are reported because some engines echo a
  fragment of the supplied secret.

### Credential file

```json
{
  "credentials": [
    {
      "engine": "postgres",
      "host": "10.10.10.20",
      "port": 5432,
      "username": "app",
      "password": "found-in-dotenv",
      "database": "appdb",
      "note": "from the leaked .env in /srv/backup"
    }
  ]
}
```

A bare JSON array of the same objects is also accepted. Entries whose `engine`
or `host` do not match the target are ignored, not dialled. The file is checked
for group/other read permission and a warning is printed if it is too open:

```bash
chmod 600 creds.json
relift scan --target postgres://10.10.10.20:5432/appdb \
  --scope scope.json --profile lab --execute \
  --db-creds creds.json
```

Requires `--profile lab` **and** a scope with `allow_intrusive: true` and
`max_risk: "intrusive"`. The scope ceiling is applied before the module is
planned, so neither switch alone is enough.

### Engines supported

| Engine | Auth flows implemented | Privilege read |
|---|---|---|
| PostgreSQL | trust (no credential needed), cleartext, MD5, SCRAM-SHA-256 with server-signature verification | `current_user`, `current_setting('is_superuser')`, `version()` |
| MySQL / MariaDB | `mysql_native_password` | `CURRENT_USER()`, `@@version`, `SHOW GRANTS FOR CURRENT_USER()` |
| Redis | `AUTH user pass`, then `AUTH pass` for pre-ACL servers | `INFO server`, then `CONFIG GET maxmemory` |
| MongoDB | SCRAM-SHA-256 (RFC 5802, PBKDF2-HMAC-SHA256) | `connectionStatus` roles |

MSSQL is not supported for credential verification: the TDS login packet needs
an NTLM/RSA exchange that has not been implemented, so the module reports that
rather than pretending. `caching_sha2_password` on MySQL over a plaintext
connection is reported as "needs TLS or an RSA exchange; not attempted" — it is
never faked.

### Privilege levels

| Level | PostgreSQL | MySQL | Redis | MongoDB |
|---|---|---|---|---|
| `superuser` | `is_superuser` is `on`, or role is `superuser` | a global grant (`ON *.*` with `WITH GRANT OPTION`) containing `SUPER`, `SYSTEM_USER`, `FILE` or `CREATE USER`, or any grant containing `ALL PRIVILEGES` | — | role `root`, `__system` or `clusterAdmin` |
| `admin` | — | global grant with `WITH GRANT OPTION` | `CONFIG GET` succeeds | any role containing `AnyDatabase` |
| `authenticated` | login works, not superuser | login works, no global grant | login works, `CONFIG` refused | login works, no admin role |
| `unknown` | check did not complete | same | same | same |

A working `superuser` credential is reported critical and adds `CWE-798`. A
working non-superuser credential is high. A rejected credential is informational
— a rejection is not a finding about the target, it is a finding about the
credential you brought.

---

## 5. What this never does

Not a limitation to be fixed later — the boundary of the tool:

- No writes. No `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CONFIG SET`, no index or
  key creation, no `FLUSHALL`.
- No data extraction. No `SELECT` against application tables, no dump, no
  `COPY ... TO`, no `mongodump`.
- No `listDatabases` / `_cat/indices` / `KEYS *`. The only metadata commands are
  the ones in the table in §2 and the privilege reads in §4.
- No brute force, spray, wordlist, default-credential list or lockout testing.
  The excluded classes in `03-RULES-OF-ENGAGEMENT.md` §7 are still excluded.
- No payload input into the database modules. The only SQL strings are constants
  in the source and are all reads.
- No persistence, no user creation, no privilege grants.

---

## 6. Worked lab example

Two containers, the smallest thing that exercises both tiers:

```bash
docker run -d --name relift-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55432:5432 postgres:16-alpine

docker run -d --name relift-redis -p 127.0.0.1:56379:6379 redis:7-alpine
```

Scope for the lab:

```bash
relift init-scope --engagement db-lab --host 127.0.0.1 \
  --ports 55432,56379 --out scope.json --allow-intrusive
```

That writes `max_risk: "intrusive"` with `allow_intrusive: true`. Keep it that
wide only for the lab.

First pass, safe tier only, no credential file:

```bash
relift scan --target postgres://127.0.0.1:55432/postgres \
  --scope scope.json --profile safe --execute
```

Expected shape of the result:

```
 CRIT postgres accepts connections without authentication  [db.security_config]
        negotiated auth method: trust. The listener handed out a usable
        session without a credential.
 MED  postgres listener offers no TLS  [db.security_config]
 INFO postgres listener fingerprinted  [db.fingerprint]

ATTACK THREADS

 CRIT Unauthenticated postgres reachable: full datastore read path
  path   reconnaissance -> initial access -> collection
  break  Enable authentication and bind the listener to the loopback or an
         internal interface. Fix order: bind address first, then auth.
```

Redis, which is the same story with a different protocol:

```bash
relift scan --target redis://127.0.0.1:56379 \
  --scope scope.json --profile safe --execute
```

Second pass, with a credential you already hold (lab account, lab password):

```bash
cat > creds.json <<'JSON'
{"credentials":[
  {"engine":"postgres","host":"127.0.0.1","port":55432,
   "username":"postgres","password":"relift-lab","database":"postgres"}
]}
JSON
chmod 600 creds.json

relift scan --target postgres://127.0.0.1:55432/postgres \
  --scope scope.json --profile lab --execute --db-creds creds.json
```

Then the threads, on their own:

```bash
relift chains
relift chains --format json
```

---

## 7. Verifying it yourself

The modules were built and verified against real servers, not mocks. The
cheapest reproduction is the two containers above plus one authenticated
engine:

```bash
# a PostgreSQL that requires a password (SCRAM by default on 16)
docker run -d --name relift-pg-scram \
  -e POSTGRES_PASSWORD=relift-lab \
  -p 127.0.0.1:55433:5432 postgres:16-alpine

# a Redis that requires one
docker run -d --name relift-redis-auth \
  -p 127.0.0.1:56380:6379 redis:7-alpine redis-server --requirepass relift-lab
```

```bash
relift scan --target postgres://127.0.0.1:55433/postgres \
  --scope scope.json --profile lab --execute --db-creds creds.json

relift scan --target redis://127.0.0.1:56380 \
  --scope scope.json --profile lab --execute --db-creds creds.json
```

What to look for:

- the safe pass says `auth_required: true` and a method of `scram-sha-256` or
  `requirepass/acl`;
- the intrusive pass reports the credential accepted with a privilege level;
- a deliberately wrong password reports "rejected", not an error, and the
  password never appears in `relift report --format json`;
- `relift report --format json` contains no `password` key anywhere: the audit
  log redacts the field class and the modules never put it there.

Clean up with `docker rm -f relift-pg relift-pg-scram relift-redis relift-redis-auth`.
