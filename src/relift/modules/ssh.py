"""SSH algorithm audit: exactly what ``ssh -vv`` shows before authentication.

The module reads the server identification string and the KEXINIT name-lists,
then reports algorithms that are deprecated or broken. That is the whole
exchange: no key exchange is completed, no user is named, no password or key is
presented, no channel is opened. There is no code path in this module that can
log in to anything.

Everything reported here is what the *server says it supports*. A name-list is a
claim; it is not proof that a compliant client would pick a weak algorithm.
"""

from __future__ import annotations

import re

from ..models import Severity
from .base import Module, ScanContext, TCPConn, finding

SSH_MSG_KEXINIT = 20
CLIENT_BANNER = b"SSH-2.0-ReliftProbe_0.2\r\n"
MAX_PACKET = 256 * 1024
MAX_BANNER_LINES = 10

# Matching is exact (case-insensitive) unless the entry ends with "-", in which
# case it is a family prefix such as the GSSAPI key-exchange names.
DEPRECATED = {
    "kex": (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-group1-sha1-",
        "ssh-rsa1",
    ),
    "host_key": (
        "ssh-dss",
        "ssh-rsa",
        "ssh-rsa-cert-v01@openssh.com",
    ),
    "cipher": (
        "3des-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "rijndael-cbc@lysator.liu.se",
    ),
    "mac": (
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96",
        "umac-64@openssh.com",
        "hmac-ripemd160",
    ),
}

_OPENSSH_VERSION = re.compile(r"OpenSSH[_-](\d+)\.(\d+)", re.I)


def _read_line(conn: TCPConn, cap: int = 512) -> str:
    """Read one CRLF/LF-terminated line, byte by byte, so nothing over-reads."""
    buffer = b""
    while not buffer.endswith(b"\n"):
        if len(buffer) >= cap:
            break
        buffer += conn.recv_exact(1)
    return buffer.decode("utf-8", "replace").strip()


def _read_banner(conn: TCPConn) -> str:
    for _ in range(MAX_BANNER_LINES):
        line = _read_line(conn)
        if not line:
            continue
        if line.startswith("SSH-"):
            return line[:200]
    return ""


def _read_kexinit(conn: TCPConn) -> bytes:
    """Return the payload of the first SSH_MSG_KEXINIT packet."""
    for _ in range(4):
        length = int.from_bytes(conn.recv_exact(4), "big")
        if length < 5 or length > MAX_PACKET:
            raise ValueError(f"implausible SSH packet length {length}")
        body = conn.recv_exact(length)
        padding_length = body[0]
        payload_end = length - padding_length
        if payload_end < 1 or payload_end > len(body):
            raise ValueError("malformed SSH packet padding")
        payload = body[1:payload_end]
        if payload and payload[0] == SSH_MSG_KEXINIT:
            return payload
    raise ValueError("server did not send a KEXINIT packet")


def _name_lists(payload: bytes) -> list[list[str]]:
    """Parse the ten name-lists that follow the KEXINIT cookie.

    RFC 4253 §7.1: each name-list is a uint32 byte length followed by that many
    bytes of comma-separated names. It is not a count of NUL-terminated strings
    — a list may legitimately be empty (length 0), which is how a server says it
    offers none of that category.
    """
    offset = 17  # message byte + 16-byte cookie
    lists: list[list[str]] = []
    for _ in range(10):
        if offset + 4 > len(payload):
            raise ValueError("KEXINIT truncated before a name-list length")
        length = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        if length > len(payload) - offset:
            raise ValueError("KEXINIT name-list runs past the packet")
        raw = payload[offset:offset + length]
        offset += length
        names = [
            name.strip()
            for name in raw.decode("utf-8", "replace").split(",")
            if name.strip()
        ]
        lists.append(names)
    return lists


def _matches(name: str, table: tuple[str, ...]) -> bool:
    lowered = name.casefold()
    for entry in table:
        if entry.endswith("-"):
            if lowered.startswith(entry):
                return True
        elif lowered == entry:
            return True
    return False


def deprecated_names(lists: dict[str, list[str]]) -> list[str]:
    """Every deprecated algorithm offered, tagged with its family."""
    found: list[str] = []
    for family, table in DEPRECATED.items():
        for name in lists.get(family, []):
            if _matches(name, table) and f"{family}:{name}" not in found:
                found.append(f"{family}:{name}")
    return found


def old_banner_reason(banner: str) -> str:
    """Why the banner looks old, worded as a claim about the banner itself."""
    match = _OPENSSH_VERSION.search(banner or "")
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if (major, minor) < (8, 0):
            return f"banner advertises OpenSSH {major}.{minor}, below 8.0"
        return ""
    if "dropbear" in (banner or "").casefold():
        return "banner advertises Dropbear, which lacks several modern algorithm families"
    return ""


class SshAlgorithmModule(Module):
    attack_id = "auth.ssh_algorithms"

    def run(self, ctx: ScanContext):
        if ctx.dry_run:
            return []

        host = ctx.target.host
        port = ctx.target.port or 22
        try:
            with ctx.db_connect(port) as conn:
                banner = _read_banner(conn)
                if not banner:
                    raise ValueError("no SSH identification string within the timeout")
                conn.send(CLIENT_BANNER)
                payload = _read_kexinit(conn)
        except (OSError, ValueError) as exc:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "SSH listener did not complete a KEXINIT exchange",
                    Severity.INFO,
                    detail=f"{host}:{port}: {exc}",
                    evidence={"host": host, "port": port, "error": str(exc)[:200]},
                    confidence="low",
                )
            ]

        try:
            parsed = _name_lists(payload)
        except ValueError as exc:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "KEXINIT could not be parsed",
                    Severity.INFO,
                    detail=str(exc),
                    evidence={"host": host, "port": port, "banner": banner},
                    confidence="low",
                )
            ]

        labels = (
            "kex",
            "host_key",
            "cipher_c2s",
            "cipher_s2c",
            "mac_c2s",
            "mac_s2c",
            "compression_c2s",
            "compression_s2c",
            "languages_c2s",
            "languages_s2c",
        )
        lists = {label: names for label, names in zip(labels, parsed)}
        ciphers = sorted(set(lists["cipher_c2s"]) | set(lists["cipher_s2c"]))
        macs = sorted(set(lists["mac_c2s"]) | set(lists["mac_s2c"]))
        lists["cipher"] = ciphers
        lists["mac"] = macs

        software = banner.split("-", 2)[2] if banner.count("-") >= 2 else banner
        deprecated = deprecated_names(lists)
        evidence = {
            "banner": banner,
            "software": software,
            "kex": lists["kex"][:40],
            "host_keys": lists["host_key"][:20],
            "ciphers": ciphers[:40],
            "macs": macs[:40],
            "deprecated": deprecated[:40],
            "port": port,
        }

        findings = [
            finding(
                ctx,
                self.attack_id,
                "SSH listener fingerprinted",
                Severity.INFO,
                detail=(
                    f"{software} · {len(lists['kex'])} KEX · "
                    f"{len(lists['host_key'])} host-key · {len(ciphers)} cipher · "
                    f"{len(macs)} MAC algorithm(s)"
                ),
                evidence=evidence,
            )
        ]

        if deprecated:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Deprecated SSH algorithms offered: {len(deprecated)}",
                    Severity.MEDIUM,
                    detail=", ".join(deprecated[:8])
                    + (" …" if len(deprecated) > 8 else ""),
                    evidence=evidence,
                    references=["CWE-327"],
                )
            )
        else:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No deprecated SSH algorithms in the server KEXINIT",
                    Severity.INFO,
                    detail="every offered KEX, host-key, cipher and MAC is current",
                    evidence=evidence,
                )
            )

        reason = old_banner_reason(banner)
        if reason:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SSH banner indicates an old build",
                    Severity.LOW,
                    detail=(
                        f"{reason}. The banner is a claim by the server and can be "
                        "changed or spoofed; confirm the package version locally "
                        "before treating this as a finding about the build."
                    ),
                    evidence={"banner": banner, "software": software, "port": port},
                    confidence="medium",
                )
            )
        return findings
