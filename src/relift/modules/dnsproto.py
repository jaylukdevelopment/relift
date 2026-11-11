"""A minimal DNS client: TXT and MX over UDP, standard library only.

``socket.getaddrinfo`` answers the only two questions the address inventory
needs (A and AAAA) and nothing else. Mail posture — SPF, DMARC, what accepts
mail for the name — lives in TXT and MX records, and the engine is stdlib-only
on purpose, so the smallest client that can ask those two questions lives here.

Deliberately absent: EDNS, DNSSEC, TCP fallback, recursion beyond one CNAME
hop, and any retry loop. One question, one answer, a hard timeout. A name
server that does not answer is a fact to report, not something to hammer.
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field

TYPE_A = 1
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16
TYPE_CODES = {"A": TYPE_A, "CNAME": TYPE_CNAME, "MX": TYPE_MX, "TXT": TYPE_TXT}

MAX_PACKET = 1400
DEFAULT_NAMESERVERS = ("1.1.1.1", "9.9.9.9")


@dataclass
class DnsResult:
    """What one question returned. ``error`` is set instead of raising."""

    data: list[bytes] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    mx: list[tuple[int, str]] = field(default_factory=list)
    rcode: int = -1
    server: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.rcode == 0

    @property
    def negative(self) -> bool:
        """NXDOMAIN or NOERROR with no records: the name and type do not exist."""
        return (
            not self.error
            and self.rcode in (0, 3)
            and not self.data
            and not self.names
            and not self.mx
        )


def nameservers() -> tuple[str, ...]:
    """Resolvers from ``/etc/resolv.conf``, with a public fallback.

    The fallback only matters on a host with no resolver configured at all; it
    is never used to bypass a resolver that answered.
    """
    found: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == "nameserver":
                    found.append(parts[1])
    except OSError:
        pass
    return tuple(found) or DEFAULT_NAMESERVERS


def encode_name(name: str) -> bytes:
    """Wire-format a domain name: length-prefixed labels, terminating NUL."""
    labels = [label for label in str(name).strip().rstrip(".").split(".") if label]
    if not labels:
        raise ValueError("empty DNS name")
    encoded = b""
    for label in labels:
        try:
            raw = label.encode("idna")
        except UnicodeError:
            raw = label.encode("ascii", "replace")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def encode_query(name: str, rtype: str, query_id: int | None = None) -> bytes:
    """One question, recursion desired. Deterministic when ``query_id`` is given."""
    code = TYPE_CODES.get(str(rtype).upper())
    if code is None:
        raise ValueError(f"unsupported record type {rtype!r}")
    ident = random.randrange(0, 65536) if query_id is None else query_id & 0xFFFF
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", code, 1)


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a name, following compression pointers (with a loop guard)."""
    labels: list[str] = []
    cursor = offset
    after = offset
    jumps = 0
    while True:
        if cursor >= len(packet):
            raise ValueError("name runs past the end of the packet")
        length = packet[cursor]
        if length == 0:
            cursor += 1
            # The terminating root label is part of the name: without this the
            # caller resumes one byte early and every later field shifts.
            if jumps == 0:
                after = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if jumps == 0:
                after = cursor + 2
            jumps += 1
            if jumps > 16:
                raise ValueError("compression pointer loop")
            cursor = pointer
            continue
        label = packet[cursor + 1 : cursor + 1 + length]
        if len(label) != length:
            raise ValueError("truncated label")
        labels.append(label.decode("ascii", "replace"))
        cursor += 1 + length
        if jumps == 0:
            after = cursor
    return ".".join(labels), after


def parse_response(packet: bytes, query_id: int | None = None) -> DnsResult:
    """Parse one response into TXT strings, MX pairs or CNAME names.

    Anything malformed comes back as ``error`` rather than as an exception:
    a response is attacker-controlled input, and a scanner must not die on it.
    """
    if len(packet) < 12:
        return DnsResult(error="short DNS response")
    ident, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if query_id is not None and ident != query_id & 0xFFFF:
        return DnsResult(error="DNS response id does not match the query")
    rcode = flags & 0x000F
    result = DnsResult(rcode=rcode)
    if rcode != 0:
        return result

    try:
        offset = 12
        for _ in range(qdcount):
            _name, offset = read_name(packet, offset)
            offset += 4  # qtype + qclass
        for _ in range(ancount):
            _owner, offset = read_name(packet, offset)
            if offset + 10 > len(packet):
                raise ValueError("truncated resource record")
            rtype, _rclass, _ttl, rdlength = struct.unpack(
                "!HHIH", packet[offset : offset + 10]
            )
            offset += 10
            rdata = packet[offset : offset + rdlength]
            if len(rdata) != rdlength:
                raise ValueError("truncated rdata")
            offset += rdlength
            if rtype == TYPE_TXT:
                result.data.append(rdata)
            elif rtype == TYPE_MX:
                # The exchange is read from the whole packet: it may point
                # back into an earlier name for compression.
                start = offset - rdlength
                preference = struct.unpack("!H", packet[start : start + 2])[0]
                exchange, _ = read_name(packet, start + 2)
                result.mx.append((preference, exchange))
            elif rtype == TYPE_CNAME:
                result.names.append(read_name(packet, offset - rdlength)[0])
    except (ValueError, struct.error) as exc:
        return DnsResult(rcode=rcode, error=f"malformed DNS response: {exc}")
    return result


def query(
    name: str,
    rtype: str,
    timeout: float = 4.0,
    servers: tuple[str, ...] | None = None,
) -> DnsResult:
    """Ask the first resolver that answers. One attempt per server, no retries."""
    try:
        payload = encode_query(name, rtype)
        ident = struct.unpack("!H", payload[:2])[0]
    except ValueError as exc:
        return DnsResult(error=str(exc))

    last_error = ""
    for server in servers or nameservers():
        address = server.strip("[]")
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (address, 53))
            packet, _peer = sock.recvfrom(MAX_PACKET)
        except (OSError, ValueError) as exc:
            last_error = f"{server}: {exc}"
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        result = parse_response(packet, ident)
        result.server = server
        if result.error and "id does not match" in result.error:
            last_error = f"{server}: {result.error}"
            continue
        return result
    return DnsResult(error=last_error or "no resolver answered")


def txt_values(result: DnsResult) -> list[str]:
    """Join each TXT record's character-strings into one value per record."""
    values = []
    for rdata in result.data:
        chunks: list[bytes] = []
        index = 0
        while index < len(rdata):
            length = rdata[index]
            piece = rdata[index + 1 : index + 1 + length]
            if len(piece) != length:
                break
            chunks.append(piece)
            index += 1 + length
        values.append(b"".join(chunks).decode("utf-8", "replace"))
    return values


def mx_values(result: DnsResult) -> list[tuple[int, str]]:
    """MX records as (preference, exchange), most-preferred first."""
    return sorted(result.mx)


def lookup_txt(name: str, timeout: float = 4.0) -> tuple[list[str], str]:
    """TXT values for a name plus an error string ('' when the query worked).

    NXDOMAIN is a valid answer — it means the record type does not exist — and
    comes back as an empty list with no error.
    """
    result = query(name, "TXT", timeout)
    if result.error:
        return [], result.error
    return txt_values(result), ""


def lookup_mx(name: str, timeout: float = 4.0) -> tuple[list[tuple[int, str]], str]:
    """MX records for a name plus an error string ('' when the query worked)."""
    result = query(name, "MX", timeout)
    if result.error:
        return [], result.error
    return mx_values(result), ""


def lookup_address(name: str, timeout: float = 4.0) -> tuple[list[str], str]:
    """A records for a name, using the resolver rather than a full packet parse."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return [], str(exc)
    return sorted({info[4][0] for info in infos}), ""
