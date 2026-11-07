"""Credential verification for datastores — one attempt, operator's own secrets.

This is deliberately *not* a brute-force or spray module, and the shape of the
code is the control: there is no password list, no candidate generator, no retry
loop and no rate ramp. Every credential handed in is tried exactly once, on one
connection, and then the module moves on. If a login is rejected, that is the
result — a lockout caused by an assessment is an outage the operator has to
explain, so the tool refuses to be able to cause one.

The single exception is a *protocol-shape* fallback in the Redis branch: Redis 5
rejects `AUTH <user> <pass>` with a syntax error because ACL users do not exist
there, so the same password is sent once more as `AUTH <pass>`. That is a reply
to a malformed command, not a second guess at the secret, and it is the only
place in this module that can send a credential twice.

What it does produce is the thing a pentest actually needs: whether a credential
found in a config file, a backup or a CI secret still works, and what level of
privilege it holds once it does.

Passwords are never written to a finding, an evidence dictionary, an exception
message or the audit log. Server errors are scrubbed before they leave this
module because some engines echo a fragment of the supplied secret back.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Any

from ..models import Severity
from . import dbproto
from .base import MissingInput, Module, ScanContext, finding

SUPPORTED = ("postgres", "mysql", "redis", "mongodb")

# PostgreSQL AuthenticationRequest codes.
PG_OK = 0
PG_CLEARTEXT = 3
PG_MD5 = 5
PG_SASL = 10
PG_SASL_CONTINUE = 11
PG_SASL_FINAL = 12

# MySQL capability flags we need in HandshakeResponse41.
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000


@dataclass
class AuthResult:
    """Outcome of one login attempt. Never holds the secret."""

    ok: bool = False
    privilege: str = "unknown"
    roles: list[str] = field(default_factory=list)
    detail: str = ""
    version: str = ""


# -- small helpers -----------------------------------------------------------
def _scrub(text: Any, secret: str) -> str:
    """Remove anything that could be the password from a message we report."""
    message = str(text or "")
    if secret:
        message = message.replace(secret, "[redacted]")
        encoded = base64.b64encode(secret.encode("utf-8", "replace")).decode()
        if encoded:
            message = message.replace(encoded, "[redacted]")
    return message[:300]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _digest(name: str, data: bytes):
    """Hash for protocol use, which FIPS builds must still permit."""
    try:
        return hashlib.new(name, data, usedforsecurity=False)
    except TypeError:  # pragma: no cover - very old/alternate builds
        return hashlib.new(name, data)


def _scram_client_proof(
    password: str,
    salt: bytes,
    iterations: int,
    client_first_bare: str,
    server_first: str,
    client_final_without_proof: str,
) -> tuple[str, str]:
    """RFC 5802/7677 client proof and the server signature we expect back.

    The same maths serves PostgreSQL SCRAM-SHA-256 and MongoDB SCRAM-SHA-256;
    they differ only in how the messages are framed.
    """
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, max(1, iterations), 32
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    auth_message = (
        client_first_bare + "," + server_first + "," + client_final_without_proof
    ).encode("utf-8")
    client_signature = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    server_signature = hmac.new(server_key, auth_message, hashlib.sha256).digest()
    return _b64(proof), _b64(server_signature)


def _parse_scram_attributes(message: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for chunk in (message or "").split(","):
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            attributes[key.strip()] = value
    return attributes


def _mysql_native_token(password: str, scramble: bytes) -> bytes:
    """mysql_native_password: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw)))."""
    stage1 = _digest("sha1", password.encode("utf-8")).digest()
    stage2 = _digest("sha1", stage1).digest()
    mixed = _digest("sha1", scramble[:20] + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, mixed))


def _lenenc(data: bytes, position: int) -> tuple[int | None, int]:
    """Read a MySQL length-encoded integer; (value, new_position)."""
    if position >= len(data):
        return None, position
    first = data[position]
    if first < 0xFB:
        return first, position + 1
    if first == 0xFB:
        return None, position + 1  # NULL
    if first == 0xFC:
        return int.from_bytes(data[position + 1:position + 3], "little"), position + 3
    if first == 0xFD:
        return int.from_bytes(data[position + 1:position + 4], "little"), position + 4
    if first == 0xFE:
        return int.from_bytes(data[position + 1:position + 9], "little"), position + 9
    return None, position + 1


def _lenenc_string(data: bytes, position: int) -> tuple[str, int]:
    length, position = _lenenc(data, position)
    if length is None:
        return "", position
    return data[position:position + length].decode("utf-8", "replace"), position + length


# -- PostgreSQL --------------------------------------------------------------
def _pg_error_text(body: bytes) -> str:
    parts: list[str] = []
    position = 0
    while position < len(body):
        code = body[position:position + 1]
        position += 1
        if code == b"\x00":
            break
        end = body.find(b"\x00", position)
        if end < 0:
            break
        value = body[position:end].decode("utf-8", "replace")
        position = end + 1
        if code in (b"M", b"S"):
            parts.append(value)
    return " / ".join(parts)


def _pg_read_until_ready(conn: Any) -> str:
    """Drain messages until ReadyForQuery ('Z'), returning any error text."""
    for _ in range(40):
        kind, body = dbproto.pg_read_message(conn)
        if kind == b"E":
            return _pg_error_text(body) or "server refused the connection"
        if kind == b"Z":
            return ""
        if kind == b"R":
            if len(body) < 4:
                return ""
            if struct.unpack(">I", body[:4])[0] == PG_OK:
                continue
    return "no ReadyForQuery within 40 messages"


def _pg_login(conn: Any, username: str, password: str, database: str) -> AuthResult:
    """Plaintext startup, then whichever auth method the server demands.

    We deliberately do not send SSLRequest here: if the server answers 'S' to
    it, the next bytes must be a TLS ClientHello, and this module does not
    negotiate TLS. Connecting in the clear and reporting the server's refusal is
    honest; pretending to start TLS would just hang the connection.
    """
    conn.send(dbproto.pg_startup_payload(username, database or "postgres"))
    scram_state: dict[str, Any] | None = None
    client_first_bare = ""

    for _ in range(20):
        kind, body = dbproto.pg_read_message(conn)

        if kind == b"E":
            return AuthResult(detail=_pg_error_text(body) or "login refused")

        if kind == b"R":
            if len(body) < 4:
                return AuthResult(detail="malformed authentication request")
            code = struct.unpack(">I", body[:4])[0]

            if code == PG_OK:
                error = _pg_read_until_ready(conn)
                if error:
                    return AuthResult(detail=error)
                return _pg_privileges(conn)

            if code == PG_CLEARTEXT:
                dbproto.pg_send_message(
                    conn, b"p", password.encode("utf-8") + b"\x00"
                )
                continue

            if code == PG_MD5:
                salt = body[4:8]
                inner = _digest(
                    "md5", (password + username).encode("utf-8")
                ).hexdigest()
                outer = _digest("md5", inner.encode("ascii") + salt).hexdigest()
                dbproto.pg_send_message(
                    conn, b"p", ("md5" + outer).encode("ascii") + b"\x00"
                )
                continue

            if code == PG_SASL:
                mechanisms = [
                    item.decode("utf-8", "replace")
                    for item in body[4:].split(b"\x00")
                    if item
                ]
                if "SCRAM-SHA-256" not in mechanisms:
                    return AuthResult(
                        detail="server offered only "
                        + ", ".join(mechanisms or ["no SASL mechanism"])
                    )
                nonce = _b64(os.urandom(18))
                client_first_bare = f"n=,r={nonce}"
                client_first = "n,," + client_first_bare
                scram_state = {"nonce": nonce, "bare": client_first_bare}
                payload = (
                    b"SCRAM-SHA-256\x00"
                    + struct.pack(">I", len(client_first))
                    + client_first.encode("utf-8")
                )
                dbproto.pg_send_message(conn, b"p", payload)
                continue

            if code == PG_SASL_CONTINUE and scram_state is not None:
                server_first = body[4:].decode("utf-8", "replace")
                attributes = _parse_scram_attributes(server_first)
                try:
                    salt = base64.b64decode(attributes.get("s", ""))
                    iterations = int(attributes.get("i", "4096"))
                except (ValueError, TypeError):
                    return AuthResult(detail="malformed SCRAM challenge")
                combined = attributes.get("r", "")
                if not combined.startswith(str(scram_state["nonce"])):
                    return AuthResult(detail="SCRAM nonce mismatch")
                final_without_proof = f"c=biws,r={combined}"
                proof, expected = _scram_client_proof(
                    password,
                    salt,
                    iterations,
                    str(scram_state["bare"]),
                    server_first,
                    final_without_proof,
                )
                scram_state["expected"] = expected
                client_final = f"{final_without_proof},p={proof}"
                dbproto.pg_send_message(conn, b"p", client_final.encode("utf-8"))
                continue

            if code == PG_SASL_FINAL and scram_state is not None:
                server_final = body[4:].decode("utf-8", "replace")
                attributes = _parse_scram_attributes(server_final)
                expected = str(scram_state.get("expected") or "")
                if attributes.get("v") and expected and attributes["v"] != expected:
                    return AuthResult(detail="SCRAM server signature did not verify")
                continue

            return AuthResult(detail=f"unsupported PostgreSQL auth method {code}")

        # ParameterStatus / BackendKeyData / NoticeResponse: ignore.

    return AuthResult(detail="authentication did not complete")


def _pg_privileges(conn: Any) -> AuthResult:
    result = AuthResult(ok=True, privilege="authenticated")
    try:
        rows = dbproto.pg_simple_query(
            conn,
            "SELECT current_user, current_setting('is_superuser'), version()",
        )
    except (OSError, ValueError, KeyError) as exc:
        result.detail = _scrub(exc, "")
        return result
    try:
        dbproto.pg_terminate(conn)
    except OSError:
        pass
    if rows and rows[0]:
        user = rows[0][0]
        is_super = str(rows[0][1]).lower() in ("on", "true", "1")
        version = str(rows[0][2]) if len(rows[0]) > 2 else ""
        result.detail = f"authenticated as {user}"
        result.version = version.replace("PostgreSQL ", "")[:40]
        if is_super:
            result.privilege = "superuser"
            result.roles = ["superuser"]
    return result


# -- MySQL -------------------------------------------------------------------
def _mysql_login(conn: Any, username: str, password: str, database: str) -> AuthResult:
    greeting = dbproto.mysql_greeting(conn)
    plugin = str(getattr(greeting, "auth_plugin", "") or "").lower()

    # caching_sha2_password and sha256_password need either TLS or an RSA key
    # exchange to send the password. Pretending otherwise would either leak the
    # password or fail confusingly, so we do not attempt it.
    if plugin in ("caching_sha2_password", "sha256_password"):
        return AuthResult(
            detail=(
                f"{plugin} needs TLS or an RSA exchange; not attempted over a "
                "plaintext connection"
            )
        )

    scramble = bytes(getattr(greeting, "scramble", b"") or b"")[:20]
    capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    if database:
        capabilities |= CLIENT_CONNECT_WITH_DB

    token = _mysql_native_token(password, scramble)
    header = struct.pack("<IIB", capabilities, 16 * 1024 * 1024, 33) + b"\x00" * 23
    body = header + username.encode("utf-8") + b"\x00"
    body += bytes([len(token)]) + token
    if database:
        body += database.encode("utf-8") + b"\x00"
    body += (plugin or "mysql_native_password").encode("ascii") + b"\x00"

    dbproto.mysql_write_packet(conn, body, 1)
    _sequence, payload = dbproto.mysql_read_packet(conn)

    if not payload:
        return AuthResult(detail="empty handshake response")
    if payload[0] == 0xFF:
        return AuthResult(detail=dbproto.mysql_error_text(payload))
    if payload[0] != 0x00:
        return AuthResult(
            detail=f"unexpected handshake reply 0x{payload[0]:02x}"
        )

    result = AuthResult(ok=True, privilege="authenticated")
    version, comment = _mysql_identity(conn)
    if version:
        result.version = version[:40]
    if comment:
        result.detail = f"authenticated; {comment[:80]}"
    grants = [grant.upper() for grant in _mysql_grants(conn)]
    # MySQL 8 expands ALL PRIVILEGES into the explicit list, so match the shape
    # of the grant rather than the legacy wording: every-privilege grants carry
    # `ON *.* TO ... WITH GRANT OPTION`.
    global_grant = [
        grant for grant in grants
        if "ON *.*" in grant and "WITH GRANT OPTION" in grant
    ]
    if any("ALL PRIVILEGES" in grant for grant in grants) or any(
        marker in grant
        for grant in global_grant
        for marker in ("SUPER", "SYSTEM_USER", "FILE", "CREATE USER")
    ):
        result.privilege = "superuser"
        result.roles = ["all-on-all", "grant-option"]
    elif global_grant:
        result.privilege = "admin"
        result.roles = ["all-on-all"]
    if grants and not result.roles:
        result.roles = ["granted"]
    try:
        dbproto.mysql_quit(conn)
    except OSError:
        pass
    return result


def _mysql_query(conn: Any, sql: str) -> list[list[str]]:
    """Run one COM_QUERY and read a text result set without a driver."""
    dbproto.mysql_write_packet(conn, b"\x03" + sql.encode("utf-8"), 0)
    rows: list[list[str]] = []
    _sequence, first = dbproto.mysql_read_packet(conn)
    if not first:
        return rows
    if first[0] == 0xFF:
        raise ValueError(dbproto.mysql_error_text(first))
    if first[0] == 0x00:
        return rows  # OK packet, no result set

    column_count, _ = _lenenc(first, 0)
    if column_count is None:
        return rows

    for _ in range(int(column_count) + 1):  # column definitions + EOF
        _sequence, packet = dbproto.mysql_read_packet(conn)
        if len(packet) < 9 and packet[:1] == b"\xfe":
            break

    for _ in range(200):
        _sequence, packet = dbproto.mysql_read_packet(conn)
        if not packet:
            break
        if packet[:1] == b"\xfe" and len(packet) < 9:
            break
        if packet[:1] == b"\x00":
            break
        row: list[str] = []
        position = 0
        for _column in range(int(column_count)):
            value, position = _lenenc_string(packet, position)
            row.append(value)
        rows.append(row)
    return rows


def _mysql_identity(conn: Any) -> tuple[str, str]:
    try:
        rows = _mysql_query(
            conn, "SELECT CURRENT_USER(), @@version, @@version_comment"
        )
    except (OSError, ValueError, KeyError):
        return "", ""
    if not rows or not rows[0]:
        return "", ""
    version = str(rows[0][1]) if len(rows[0]) > 1 else ""
    comment = str(rows[0][2]) if len(rows[0]) > 2 else ""
    return version, comment


def _mysql_grants(conn: Any) -> list[str]:
    try:
        rows = _mysql_query(conn, "SHOW GRANTS FOR CURRENT_USER()")
    except (OSError, ValueError, KeyError):
        return []
    grants: list[str] = []
    for row in rows:
        if row:
            grants.append(row[0])
    return grants[:40]


# -- Redis -------------------------------------------------------------------
def _redis_login(conn: Any, username: str, password: str) -> AuthResult:
    reply = dbproto.redis_command(conn, "AUTH", username, password)
    message = str(getattr(reply, "value", "") or "")

    # Redis 5 has no ACL users: `AUTH user pass` is a syntax error there. This
    # retries the *protocol shape* with the password alone — it is not a second
    # password attempt, and it is the only branch that can re-send anything.
    lowered = message.lower()
    if not getattr(reply, "ok", False) and (
        "wrong number of arguments" in lowered or "syntax error" in lowered
    ):
        reply = dbproto.redis_command(conn, "AUTH", password)
        message = str(getattr(reply, "value", "") or "")

    if not getattr(reply, "ok", False):
        return AuthResult(detail=message or "AUTH refused")

    result = AuthResult(ok=True, privilege="authenticated", detail="AUTH accepted")
    info = dbproto.redis_command(conn, "INFO", "server")
    text = str(getattr(info, "value", "") or "")
    for line in text.splitlines():
        if line.startswith("redis_version:"):
            result.version = line.split(":", 1)[1].strip()[:40]
            break

    # CONFIG is an administrative command on every supported version; being
    # able to run it means the account is not read-only.
    config = dbproto.redis_command(conn, "CONFIG", "GET", "maxmemory")
    if getattr(config, "kind", "") in ("status", "bulk", "array"):
        result.privilege = "admin"
        result.roles = ["config-write"]
    return result


# -- MongoDB -----------------------------------------------------------------
def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("latin-1", "replace")
    if isinstance(value, dict):
        if isinstance(value.get("$binary"), str):
            try:
                return base64.b64decode(value["$binary"])
            except (ValueError, TypeError):
                return b""
        if isinstance(value.get("base64"), str):
            try:
                return base64.b64decode(value["base64"])
            except (ValueError, TypeError):
                return b""
    return b""


def _mongo_login(
    conn: Any, username: str, password: str, database: str
) -> AuthResult:
    auth_db = database or "admin"
    nonce = _b64(os.urandom(18))
    bare = f"n={username},r={nonce}"
    client_first = f"n,,{bare}"

    # SCRAM payloads are BSON binary, so dbproto.bson_encode must map `bytes`
    # to subtype 0x00. If a future encoder does not, the server rejects this and
    # the caller reports the refusal instead of crashing.
    start = dbproto.mongo_command(
        conn,
        {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-256",
            "payload": client_first.encode("utf-8"),
            "autoAuthorize": 1,
            "$db": auth_db,
        },
    )
    if not start.get("ok"):
        return AuthResult(detail=str(start.get("errmsg") or "saslStart refused"))

    conversation = start.get("conversationId")
    server_first = _as_bytes(start.get("payload")).decode("utf-8", "replace")
    attributes = _parse_scram_attributes(server_first)
    try:
        salt = base64.b64decode(attributes.get("s", ""))
        iterations = int(attributes.get("i", "15000"))
    except (ValueError, TypeError):
        return AuthResult(detail="malformed SCRAM challenge")

    combined = attributes.get("r", "")
    if not combined.startswith(nonce):
        return AuthResult(detail="SCRAM nonce mismatch")

    final_without_proof = f"c=biws,r={combined}"
    proof, expected = _scram_client_proof(
        password, salt, iterations, bare, server_first, final_without_proof
    )
    client_final = f"{final_without_proof},p={proof}"

    reply = dbproto.mongo_command(
        conn,
        {
            "saslContinue": 1,
            "conversationId": conversation,
            "payload": client_final.encode("utf-8"),
            "$db": auth_db,
        },
    )
    if not reply.get("ok"):
        return AuthResult(detail=str(reply.get("errmsg") or "saslContinue refused"))

    server_final = _as_bytes(reply.get("payload")).decode("utf-8", "replace")
    attributes = _parse_scram_attributes(server_final)
    if attributes.get("v") and attributes["v"] != expected:
        return AuthResult(detail="SCRAM server signature did not verify")

    if reply.get("done") is False:
        finish = dbproto.mongo_command(
            conn,
            {
                "saslContinue": 1,
                "conversationId": conversation,
                "payload": b"",
                "$db": auth_db,
            },
        )
        if not finish.get("ok"):
            return AuthResult(
                detail=str(finish.get("errmsg") or "final SASL round refused")
            )

    result = AuthResult(ok=True, privilege="authenticated", detail="authenticated")
    status = dbproto.mongo_command(
        conn, {"connectionStatus": 1, "$db": auth_db}
    )
    auth_info = status.get("authInfo") or {}
    users = auth_info.get("authenticatedUsers") or []
    if users and isinstance(users[0], dict):
        result.detail = f"authenticated as {users[0].get('user')}@{users[0].get('db')}"
    roles = auth_info.get("authenticatedUserRoles") or []
    role_names = []
    for role in roles:
        if isinstance(role, dict) and role.get("role"):
            role_names.append(str(role["role"]))
    result.roles = role_names[:20]
    if any(name in ("root", "__system", "clusterAdmin") for name in role_names):
        result.privilege = "superuser"
    elif any("AnyDatabase" in name for name in role_names):
        result.privilege = "admin"

    hello = dbproto.mongo_command(conn, {"hello": 1, "$db": auth_db})
    if hello.get("version"):
        result.version = str(hello["version"])[:40]
    return result


# -- module ------------------------------------------------------------------
class CredentialVerifyModule(Module):
    """Verify held credentials once each. No discovery, no retry, no spray."""

    attack_id = "db.credential_verify"

    def run(self, ctx: ScanContext) -> list[Any]:
        if not ctx.db_creds:
            raise MissingInput(
                "no credentials supplied: pass --db-creds FILE with credentials "
                "you already hold"
            )
        engine = ctx.target.engine
        if engine not in SUPPORTED:
            raise MissingInput(
                f"credential verification does not cover {engine or 'this target'}; "
                f"supported: {', '.join(SUPPORTED)}"
            )

        entries = [
            entry
            for entry in ctx.db_creds
            if str(entry.get("engine") or engine).lower() == engine
        ]
        if not entries:
            raise MissingInput(
                f"the credential file has no entry for {engine}"
            )

        seen: set[tuple[str, str]] = set()
        findings: list[Any] = []
        for entry in entries:
            username = str(entry.get("username") or "").strip()
            password = str(entry.get("password") or "")
            if not username or not password:
                continue
            key = (engine, username)
            if key in seen:
                continue
            seen.add(key)
            database = str(entry.get("database") or ctx.target.database_name or "")
            findings.append(self._check(ctx, engine, username, password, database))
        return findings

    def _check(
        self,
        ctx: ScanContext,
        engine: str,
        username: str,
        password: str,
        database: str,
    ) -> Any:
        result: AuthResult
        connection = None
        try:
            connection = ctx.db_connect()
            if engine == "postgres":
                result = _pg_login(connection, username, password, database)
            elif engine == "mysql":
                result = _mysql_login(connection, username, password, database)
            elif engine == "redis":
                result = _redis_login(connection, username, password)
            else:
                result = _mongo_login(connection, username, password, database)
        except (OSError, ValueError, KeyError, struct.error) as exc:
            result = AuthResult(
                detail=_scrub(f"{type(exc).__name__}: {exc}", password)
            )
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass

        if not result.ok:
            completed = bool(result.detail) and "not attempted" not in result.detail
            return finding(
                ctx,
                self.attack_id,
                (
                    f"Credential for {username} rejected by {engine}"
                    if completed
                    else f"Credential check for {username} could not complete"
                ),
                Severity.INFO,
                detail=_scrub(result.detail, password),
                evidence={
                    "engine": engine,
                    "username": username,
                    "login_ok": False,
                    "privilege_level": "unknown",
                    "roles": [],
                    "detail": _scrub(result.detail, password),
                    "port": ctx.target.port,
                },
                confidence="high" if completed else "low",
            )

        superuser = result.privilege == "superuser"
        return finding(
            ctx,
            self.attack_id,
            f"Credential for {username} accepted on {engine}",
            Severity.CRITICAL if superuser else Severity.HIGH,
            detail=_scrub(
                result.detail
                or f"login succeeded; privilege level {result.privilege}",
                password,
            ),
            evidence={
                "engine": engine,
                "username": username,
                "login_ok": True,
                "privilege_level": result.privilege,
                "roles": list(result.roles),
                "detail": _scrub(result.detail, password),
                "version": result.version,
                "port": ctx.target.port,
            },
            references=["CWE-798"] if superuser else [],
        )
