"""Raw wire-protocol frames for the database engines Relift can audit.

These are the frames a database answers *before* anyone authenticates. That is
the whole point of the module: an authorised assessment needs to know what a
listener says about itself — its version, whether it demands a credential at
all, and which credential exchange it would accept — without ever sending a
password or reading a row of data.

Everything here is byte-level and dependency-free: no drivers, no ORMs, no
third-party protocol libraries. Every reader is bounded by ``TCPConn``'s caps
and lets socket errors propagate, so callers can turn "the port closed on us"
into a finding rather than a traceback.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .base import TCPConn

POSTGRES_PROTOCOL = 196608  # 3.0
SSL_REQUEST_CODE = 80877103
POSTGRES_AUTH_OK = 0
POSTGRES_AUTH_CLEARTEXT = 3
POSTGRES_AUTH_MD5 = 5
POSTGRES_AUTH_SASL = 10

MYSQL_CLIENT_SSL = 0x00000800
MYSQL_CLIENT_SECURE_CONNECTION = 0x00008000
MYSQL_CLIENT_PLUGIN_AUTH = 0x00080000

TDS_PRELOGIN = 0x12
TDS_REPLY = 0x04

MAX_PACKET = 16 * 1024 * 1024


# --------------------------------------------------------------------------
# generic helpers
# --------------------------------------------------------------------------
def pack_int32(value: int) -> bytes:
    """Signed 32-bit big-endian, the framing unit of several protocols."""
    return struct.pack(">i", int(value))


def pack_int16(value: int) -> bytes:
    return struct.pack(">h", int(value))


def unpack_int32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from(">i", data, offset)[0]


def unpack_int16(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from(">h", data, offset)[0]


def _cstring(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Read a NUL-terminated string; return (text, offset after the NUL)."""
    end = data.find(b"\x00", offset)
    if end < 0:
        return data[offset:].decode("utf-8", "replace"), len(data)
    return data[offset:end].decode("utf-8", "replace"), end + 1


def _cstrings(data: bytes) -> list[str]:
    return [chunk.decode("utf-8", "replace") for chunk in data.split(b"\x00") if chunk]


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------
@dataclass
class PgGreeting:
    """What a PostgreSQL listener says before it learns who you are."""

    tls_capable: bool = False
    auth_type: int = -1
    auth_mechanisms: list[str] = field(default_factory=list)
    params: dict[str, str] = field(default_factory=dict)
    error: str = ""
    negotiated: bool = False

    @property
    def auth_label(self) -> str:
        labels = {
            POSTGRES_AUTH_OK: "trust",
            POSTGRES_AUTH_CLEARTEXT: "password (cleartext)",
            POSTGRES_AUTH_MD5: "md5",
            2: "kerberos",
            6: "scm",
            7: "gss",
            8: "gss-continue",
            9: "sspi",
            POSTGRES_AUTH_SASL: "scram-sha-256",
            11: "sasl-continue",
            12: "sasl-final",
        }
        if self.auth_type < 0:
            return "unknown"
        return labels.get(self.auth_type, f"auth-type-{self.auth_type}")

    @property
    def version(self) -> str:
        return self.params.get("server_version", "")


def pg_startup_payload(
    user: str, database: str, application_name: str = "relift_probe"
) -> bytes:
    """StartupMessage: length, protocol 3.0, then key/value pairs."""
    body = (
        pack_int32(POSTGRES_PROTOCOL)
        + b"user\x00" + user.encode("utf-8") + b"\x00"
        + b"database\x00" + database.encode("utf-8") + b"\x00"
        + b"application_name\x00" + application_name.encode("utf-8") + b"\x00"
        + b"\x00"
    )
    return pack_int32(len(body) + 4) + body


def pg_ssl_request() -> bytes:
    """SSLRequest: a length-8 packet with the magic code. Answer 'S' or 'N'."""
    return pack_int32(8) + pack_int32(SSL_REQUEST_CODE)


def pg_read_message(conn: TCPConn) -> tuple[bytes, bytes]:
    """Read one backend message. Returns (type byte, body)."""
    kind = conn.recv_exact(1)
    length = unpack_int32(conn.recv_exact(4), 0)
    if length < 4 or length > MAX_PACKET:
        raise OSError(f"implausible PostgreSQL frame length {length}")
    body = conn.recv_exact(length - 4) if length > 4 else b""
    return kind, body


def pg_send_message(conn: TCPConn, type_byte: bytes, body: bytes) -> None:
    """Frontend message: the type byte comes *first*, then the length.

    Only the StartupMessage is length-first; every typed message is
    ``type, int32 length, body`` and the length excludes the type byte. Getting
    this order wrong makes the server read the length's leading zero as the
    message type, which produces a very confusing "message type 0" error.
    """
    kind = type_byte if isinstance(type_byte, bytes) else str(type_byte).encode("ascii")
    conn.send(kind + pack_int32(len(body) + 4) + body)


def _pg_error_text(body: bytes) -> str:
    """ErrorResponse fields: type byte + NUL-terminated text, terminated by 0."""
    message = ""
    code = ""
    offset = 0
    while offset < len(body):
        marker = body[offset]
        if marker == 0:
            break
        text, offset = _cstring(body, offset + 1)
        if marker == ord("M"):
            message = text
        elif marker == ord("C"):
            code = text
    if message and code:
        return f"{code}: {message}"
    return message or code or "server returned an error response"


def pg_greeting(
    conn: TCPConn,
    user: str = "relift_probe",
    database: str = "postgres",
) -> PgGreeting:
    """Learn the transport, auth method and (when offered) server parameters.

    The SSLRequest goes first so ``tls_capable`` is recorded even on a server
    that will demand a password. If the server asks for one, this function
    returns immediately: sending it is the credential module's job, with a
    credential the operator supplied.
    """
    greeting = PgGreeting()
    conn.send(pg_ssl_request())
    try:
        answer = conn.recv_exact(1)
    except OSError as exc:
        greeting.error = str(exc) or "no answer to SSLRequest"
        return greeting
    greeting.tls_capable = answer == b"S"

    conn.send(pg_startup_payload(user, database))
    while True:
        try:
            kind, body = pg_read_message(conn)
        except OSError as exc:
            if not greeting.error:
                greeting.error = str(exc) or "connection closed during startup"
            break

        if kind == b"R":
            greeting.auth_type = unpack_int32(body, 0) if len(body) >= 4 else -1
            if greeting.auth_type == POSTGRES_AUTH_SASL and len(body) > 4:
                greeting.auth_mechanisms = _cstrings(body[4:])
            greeting.negotiated = True
            if greeting.auth_type != POSTGRES_AUTH_OK:
                # The reply is the answer; we do not authenticate in an audit.
                break
            continue
        if kind == b"S":
            key, offset = _cstring(body, 0)
            value, _ = _cstring(body, offset)
            if key:
                greeting.params[key] = value
            continue
        if kind == b"E":
            greeting.error = _pg_error_text(body)
            break
        if kind == b"Z":
            greeting.negotiated = True
            break
        # 'N' notice, 'K' backend key, 'A' notification: nothing to record.

    return greeting


def pg_simple_query(conn: TCPConn, sql: str) -> list[list[str]]:
    """Run one statement on an *already authenticated* connection.

    Only used after a credential the operator supplied has been accepted. Rows
    are returned as strings; NULL becomes an empty string.
    """
    pg_send_message(conn, b"Q", sql.encode("utf-8") + b"\x00")
    rows: list[list[str]] = []
    while True:
        kind, body = pg_read_message(conn)
        if kind == b"D":
            count = unpack_int16(body, 0)
            offset = 2
            row: list[str] = []
            for _ in range(count):
                size = unpack_int32(body, offset)
                offset += 4
                if size < 0:
                    row.append("")
                    continue
                if offset + size > len(body):
                    raise OSError("truncated DataRow")
                row.append(body[offset:offset + size].decode("utf-8", "replace"))
                offset += size
            rows.append(row)
        elif kind == b"E":
            raise OSError(_pg_error_text(body))
        elif kind == b"Z":
            return rows


def pg_terminate(conn: TCPConn) -> None:
    """Best-effort Terminate so the server's log shows a clean session end."""
    try:
        pg_send_message(conn, b"X", b"")
    except OSError:
        pass


def pg_escape(text: str) -> str:
    return str(text).replace("'", "''")


# --------------------------------------------------------------------------
# MySQL / MariaDB
# --------------------------------------------------------------------------
@dataclass
class MysqlGreeting:
    """The protocol handshake MySQL sends unprompted on connect."""

    version: str = ""
    protocol: int = 0
    connection_id: int = 0
    capability: int = 0
    auth_plugin: str = ""
    scramble: bytes = b""
    error: str = ""
    status: int = 0

    @property
    def tls_capable(self) -> bool:
        return bool(self.capability & MYSQL_CLIENT_SSL)

    @property
    def secure_connection(self) -> bool:
        return bool(self.capability & MYSQL_CLIENT_SECURE_CONNECTION)

    @property
    def plugin_auth(self) -> bool:
        return bool(self.capability & MYSQL_CLIENT_PLUGIN_AUTH)


def mysql_read_packet(conn: TCPConn) -> tuple[int, bytes]:
    """3-byte little-endian length, 1-byte sequence id, then the payload."""
    header = conn.recv_exact(4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    if length > MAX_PACKET:
        raise OSError(f"implausible MySQL frame length {length}")
    body = conn.recv_exact(length) if length else b""
    return header[3], body


def mysql_write_packet(conn: TCPConn, payload: bytes, sequence: int) -> None:
    length = len(payload)
    if length > MAX_PACKET:
        raise OSError("refusing to send an oversized MySQL frame")
    header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, sequence & 0xFF])
    conn.send(header + payload)


def mysql_greeting(conn: TCPConn) -> MysqlGreeting:
    """Parse the initial handshake packet (or an ERR packet)."""
    greeting = MysqlGreeting()
    _sequence, payload = mysql_read_packet(conn)
    if not payload:
        greeting.error = "empty handshake packet"
        return greeting
    if payload[0] == 0xFF:
        greeting.error = mysql_error_text(payload)
        return greeting

    offset = 1
    greeting.protocol = payload[0]
    greeting.version, offset = _cstring(payload, offset)
    if offset + 4 > len(payload):
        greeting.error = "truncated handshake: thread id"
        return greeting
    greeting.connection_id = struct.unpack_from("<I", payload, offset)[0]
    offset += 4

    if offset + 8 > len(payload):
        greeting.error = "truncated handshake: scramble part 1"
        return greeting
    part1 = payload[offset:offset + 8]
    offset += 8 + 1  # scramble part 1 plus the filler byte

    if offset + 2 > len(payload):
        # Ancient protocol that stops after the filler.
        greeting.scramble = part1
        return greeting
    cap_lower = struct.unpack_from("<H", payload, offset)[0]
    offset += 2

    if offset >= len(payload):
        greeting.capability = cap_lower
        greeting.scramble = part1
        return greeting

    offset += 1  # character set
    if offset + 2 > len(payload):
        greeting.capability = cap_lower
        greeting.scramble = part1
        return greeting
    greeting.status = struct.unpack_from("<H", payload, offset)[0]
    offset += 2

    cap_upper = 0
    if offset + 2 <= len(payload):
        cap_upper = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
    greeting.capability = (cap_upper << 16) | cap_lower

    part2 = b""
    if offset < len(payload):
        plugin_len = payload[offset]
        offset += 1
        offset += 10  # reserved
        if offset < len(payload):
            # The declared length covers the whole scramble (8 + part 2).
            # Never strip NULs out of the middle: the nonce is binary and may
            # legitimately contain 0x00.
            wanted = max(13, plugin_len - 8) if plugin_len else 13
            take = min(wanted, len(payload) - offset)
            part2 = payload[offset:offset + take]
            offset += take

    # Both mysql_native_password and caching_sha2_password use a 20-byte nonce:
    # eight bytes in the first part, twelve in the second, then a NUL pad byte.
    greeting.scramble = (part1 + part2)[:20]

    if greeting.plugin_auth and offset < len(payload):
        greeting.auth_plugin, _ = _cstring(payload, offset)
    return greeting


def mysql_quit(conn: TCPConn, sequence: int = 0) -> None:
    """COM_QUIT. Best-effort: the connection is going away either way."""
    try:
        mysql_write_packet(conn, b"\x01", sequence)
    except OSError:
        pass


def mysql_error_text(payload: bytes) -> str:
    """ERR packet: 0xFF, int16 code, '#', 5-byte SQLSTATE, message."""
    if len(payload) < 3:
        return "malformed error packet"
    payload = payload if payload[0] == 0xFF else b"\xff" + payload
    code = struct.unpack_from("<H", payload, 1)[0]
    message = payload[3:]
    state = ""
    if message[:1] == b"#" and len(message) >= 6:
        state = message[1:6].decode("ascii", "replace")
        message = message[6:]
    text = message.decode("utf-8", "replace").strip()
    return f"{state} ({code}): {text}" if state else f"({code}): {text}"


# --------------------------------------------------------------------------
# MSSQL / TDS
# --------------------------------------------------------------------------
@dataclass
class TdsPrelogin:
    """The pre-login reply: server build and whether encryption is demanded."""

    version: str = ""
    encryption: int = -1
    instance: str = ""
    error: str = ""

    @property
    def encryption_label(self) -> str:
        return {
            0: "off",
            1: "on",
            2: "not-supported",
        }.get(self.encryption, "unknown")


def tds_prelogin(conn: TCPConn) -> TdsPrelogin:
    """Send a TDS 7.x PRELOGIN and parse the option table that comes back.

    The option table is five bytes per token (token, offset, length) followed by
    a 0xFF terminator and then the data. Offsets are computed from the real
    table size so the frame stays correct if an option is added.
    """
    result = TdsPrelogin()
    version_data = b"\x0f\x00\x00\x00\x00\x00"
    encryption_data = b"\x00"  # ENCRYPT_OFF: ask for a plaintext answer

    table_size = (5 * 2) + 1
    version_offset = table_size
    encryption_offset = version_offset + len(version_data)
    payload = (
        b"\x00" + pack_int16(version_offset) + pack_int16(len(version_data))
        + b"\x01" + pack_int16(encryption_offset) + pack_int16(len(encryption_data))
        + b"\xff"
        + version_data
        + encryption_data
    )
    total = 8 + len(payload)
    header = (
        bytes([TDS_PRELOGIN, 0x01])
        + struct.pack(">H", total)
        + b"\x00\x00"
        + b"\x01"
        + b"\x00"
    )
    conn.send(header + payload)

    reply_header = conn.recv_exact(8)
    length = struct.unpack_from(">H", reply_header, 2)[0]
    if length < 8 or length > MAX_PACKET:
        result.error = f"implausible TDS frame length {length}"
        return result
    body = conn.recv_exact(length - 8)
    if reply_header[0] not in (TDS_REPLY, 0x04):
        result.error = f"unexpected TDS message type 0x{reply_header[0]:02x}"
        return result

    offset = 0
    while offset + 1 <= len(body):
        token = body[offset]
        if token == 0xFF:
            return result
        if offset + 5 > len(body):
            result.error = "truncated TDS option table"
            return result
        data_offset = struct.unpack_from(">H", body, offset + 1)[0]
        data_length = struct.unpack_from(">H", body, offset + 3)[0]
        offset += 5
        chunk = body[data_offset:data_offset + data_length]
        if token == 0x00 and len(chunk) >= 6:
            major, minor = chunk[0], chunk[1]
            build = (chunk[2] << 8) | chunk[3]
            result.version = f"{major}.{minor}.{build}"
        elif token == 0x01 and chunk:
            result.encryption = chunk[0]
        elif token == 0x02:
            result.instance = chunk.split(b"\x00")[0].decode("utf-8", "replace")
    return result


# --------------------------------------------------------------------------
# Redis
# --------------------------------------------------------------------------
@dataclass
class RedisReply:
    """One RESP2 reply. An error reply is data, never an exception."""

    kind: str = ""
    value: str = ""
    raw: bytes = b""

    @property
    def ok(self) -> bool:
        return self.kind == "status" and self.value.upper().startswith("OK")

    @property
    def error(self) -> str:
        return self.value if self.kind == "error" else ""


def _redis_line(conn: TCPConn, cap: int = 65536) -> bytes:
    buffer = b""
    while not buffer.endswith(b"\r\n"):
        if len(buffer) > cap:
            raise OSError("Redis reply line exceeded the cap")
        chunk = conn.recv_some(1)
        if not chunk:
            raise OSError("connection closed mid-reply")
        buffer += chunk
    return buffer[:-2]


def redis_command(conn: TCPConn, *args: str) -> RedisReply:
    """RESP2 array command. Values are sent verbatim; no shell, no quoting."""
    parts = [b"*" + str(len(args)).encode() + b"\r\n"]
    for argument in args:
        encoded = str(argument).encode("utf-8")
        parts.append(b"$" + str(len(encoded)).encode() + b"\r\n" + encoded + b"\r\n")
    conn.send(b"".join(parts))
    # A server *error reply* (-NOAUTH, -WRONGPASS) is data and is returned as
    # kind="error". A transport failure is not, and is left for the caller.
    return _redis_parse(conn)


def _redis_parse(conn: TCPConn) -> RedisReply:
    marker = conn.recv_exact(1)
    if marker == b"+":
        text = _redis_line(conn)
        return RedisReply(kind="status", value=text.decode("utf-8", "replace"), raw=text)
    if marker == b"-":
        text = _redis_line(conn)
        return RedisReply(kind="error", value=text.decode("utf-8", "replace"), raw=text)
    if marker == b":":
        text = _redis_line(conn)
        return RedisReply(kind="integer", value=text.decode("ascii", "replace"), raw=text)
    if marker == b"$":
        length = int(_redis_line(conn) or b"-1")
        if length < 0:
            return RedisReply(kind="nil")
        if length > 1024 * 1024:
            raise OSError("Redis bulk reply exceeded 1 MiB")
        body = conn.recv_exact(length)
        conn.recv_exact(2)  # trailing CRLF
        return RedisReply(kind="bulk", value=body.decode("utf-8", "replace"), raw=body)
    if marker == b"*":
        count = int(_redis_line(conn) or b"-1")
        if count < 0:
            return RedisReply(kind="nil")
        values: list[str] = []
        for _ in range(count):
            item = _redis_parse(conn)
            values.append(item.value)
        return RedisReply(kind="array", value=", ".join(values))
    raise OSError(f"unrecognised RESP marker {marker!r}")


def redis_ping(conn: TCPConn) -> RedisReply:
    return redis_command(conn, "PING")


def redis_info(conn: TCPConn, section: str = "server") -> RedisReply:
    return redis_command(conn, "INFO", section)


# --------------------------------------------------------------------------
# MongoDB / BSON
# --------------------------------------------------------------------------
@dataclass
class MongoHello:
    """The ``hello`` reply: an unauthenticated, spec-mandated version reveal."""

    ok: bool = False
    version: str = ""
    max_wire_version: int = 0
    mechanisms: list[str] = field(default_factory=list)
    error: str = ""
    document: dict = field(default_factory=dict)


def _bson_cstring(text: str) -> bytes:
    return str(text).encode("utf-8") + b"\x00"


def bson_encode(document: dict) -> bytes:
    """Encode the subset of BSON the audit needs. Order follows the dict."""
    elements = bytearray()
    for key, value in document.items():
        name = _bson_cstring(key)
        if isinstance(value, bool):
            elements += b"\x08" + name + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            if -2147483648 <= value <= 2147483647:
                elements += b"\x10" + name + struct.pack("<i", value)
            else:
                elements += b"\x12" + name + struct.pack("<q", value)
        elif isinstance(value, float):
            elements += b"\x01" + name + struct.pack("<d", value)
        elif isinstance(value, str):
            raw = value.encode("utf-8")
            elements += b"\x02" + name + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
        elif isinstance(value, (bytes, bytearray)):
            # Binary subtype 0x00 (generic). SCRAM payloads in the Mongo auth
            # exchange are binary, not UTF-8 strings, so this path matters.
            raw = bytes(value)
            elements += (
                b"\x05"
                + name
                + struct.pack("<i", len(raw))
                + b"\x00"
                + raw
            )
        elif isinstance(value, dict):
            elements += b"\x03" + name + bson_encode(value)
        elif isinstance(value, (list, tuple)):
            array: dict = {}
            for index, item in enumerate(value):
                array[str(index)] = item
            elements += b"\x04" + name + bson_encode(array)
        elif value is None:
            elements += b"\x0a" + name
        else:
            raw = str(value).encode("utf-8")
            elements += b"\x02" + name + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
    body = bytes(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


_BSON_FIXED = {
    0x01: 8,   # double
    0x06: 0,   # undefined
    0x08: 1,   # bool
    0x09: 8,   # UTC datetime
    0x0A: 0,   # null
    0x11: 8,   # timestamp
    0x12: 8,   # int64
    0x13: 16,  # decimal128
    0x7F: 0,   # max key
    0xFF: 0,   # min key
}


def bson_decode(data: bytes) -> tuple[dict, int]:
    """Decode one document. Tolerant: unknown types stop parsing, not the caller."""
    document: dict = {}
    if len(data) < 5:
        return document, 0
    length = struct.unpack_from("<i", data, 0)[0]
    if length < 5 or length > len(data):
        return document, 0
    offset = 4
    end = length - 1  # last byte is the terminator
    while offset < end:
        marker = data[offset]
        if marker == 0:
            break
        offset += 1
        key, offset = _cstring(data, offset)
        try:
            value, offset = _bson_value(marker, data, offset)
        except (OSError, ValueError, struct.error):
            break
        document[key] = value
    return document, length


def _bson_value(marker: int, data: bytes, offset: int):
    if marker == 0x01:
        return struct.unpack_from("<d", data, offset)[0], offset + 8
    if marker == 0x10:
        # int32. Mongo's `hello` reply is full of these (maxWireVersion,
        # connectionId, ...), so a decoder that stops here loses the document.
        return struct.unpack_from("<i", data, offset)[0], offset + 4
    if marker in _BSON_FIXED:
        size = _BSON_FIXED[marker]
        if marker == 0x08:
            return data[offset] != 0, offset + 1
        if marker in (0x09, 0x11, 0x12):
            return struct.unpack_from("<q", data, offset)[0], offset + size
        return None, offset + size
    if marker == 0x02:
        size = struct.unpack_from("<i", data, offset)[0]
        start = offset + 4
        return data[start:start + size - 1].decode("utf-8", "replace"), start + size
    if marker == 0x03:
        nested, consumed = bson_decode(data[offset:])
        return nested, offset + consumed
    if marker == 0x04:
        nested, consumed = bson_decode(data[offset:])
        return list(nested.values()), offset + consumed
    if marker == 0x05:
        size = struct.unpack_from("<i", data, offset)[0]
        start = offset + 5  # length + subtype byte
        return data[start:start + size], start + size
    if marker == 0x07:
        return data[offset:offset + 12].hex(), offset + 12
    raise OSError(f"unsupported BSON type 0x{marker:02x}")


def mongo_command(conn: TCPConn, document: dict, request_id: int = 1) -> dict:
    """OP_MSG round trip. Returns the decoded reply body ({} on failure)."""
    body = bson_encode(document)
    payload = struct.pack("<i", 0) + b"\x00" + body
    message_length = 16 + len(payload)
    frame = (
        struct.pack("<iiii", message_length, request_id, 0, 2013)
        + payload
    )
    conn.send(frame)

    header = conn.recv_exact(16)
    reply_length = struct.unpack_from("<i", header, 0)[0]
    if reply_length < 21 or reply_length > MAX_PACKET:
        return {}
    rest = conn.recv_exact(reply_length - 16)

    offset = 4  # skip flagBits
    document_reply: dict = {}
    while offset < len(rest):
        kind = rest[offset]
        offset += 1
        if kind == 0x00:
            decoded, consumed = bson_decode(rest[offset:])
            document_reply = decoded or document_reply
            if consumed <= 0:
                break
            offset += consumed
        elif kind == 0x01:
            # Document sequence: int32 size, identifier cstring, then documents.
            if offset + 4 > len(rest):
                break
            section_size = struct.unpack_from("<i", rest, offset)[0]
            if section_size <= 4:
                break
            offset += section_size
        else:
            break
    return document_reply


def mongo_hello(conn: TCPConn) -> MongoHello:
    """Ask for the handshake document, falling back to the legacy name."""
    hello = MongoHello()
    for command in ("hello", "isMaster"):
        try:
            document = mongo_command(conn, {command: 1, "$db": "admin"})
        except OSError as exc:
            hello.error = f"transport: {exc}"
            return hello
        if not document:
            hello.error = "empty handshake reply"
            continue
        ok = document.get("ok")
        hello.document = document
        hello.ok = bool(ok) or ok == 1.0
        hello.version = str(document.get("version") or "")
        wire = document.get("maxWireVersion")
        if isinstance(wire, int):
            hello.max_wire_version = wire
        mechanisms = document.get("saslSupportedMechs")
        if isinstance(mechanisms, list):
            hello.mechanisms = [str(item) for item in mechanisms]
        hello.error = str(document.get("errmsg") or "")
        if hello.ok and hello.version:
            return hello
    return hello
