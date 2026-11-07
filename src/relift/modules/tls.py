"""TLS techniques: certificate inspection and protocol version support."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone

from ..models import Severity
from .base import Module, ScanContext, finding

CERT_TIME_FORMATS = ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ")


def parse_cert_time(value: str) -> datetime | None:
    for fmt in CERT_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def decode_der(der: bytes) -> dict:
    """Parse a DER certificate using the stdlib test helper, if available."""
    if not der:
        return {}
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    path = ""
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
            path = handle.name
        return decoder(path) or {}
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def handshake(host: str, port: int, timeout: float, verified: bool):
    """Return (cert dict, der, protocol version, cipher tuple)."""
    context = ssl.create_default_context()
    if not verified:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return (
                tls.getpeercert(),
                tls.getpeercert(binary_form=True),
                tls.version(),
                tls.cipher(),
            )


def hostname_covered(host: str, sans: list[str]) -> bool:
    name = host.casefold().rstrip(".")
    for pattern in (entry.casefold().rstrip(".") for entry in sans):
        if pattern == name:
            return True
        if pattern.startswith("*.") and name.count(".") == pattern.count("."):
            if name.endswith(pattern[1:]):
                return True
    return False


def san_list(cert: dict) -> list[str]:
    names = []
    for entry in cert.get("subjectAltName") or ():
        try:
            kind, value = entry
        except (TypeError, ValueError):
            continue
        if str(kind).lower() in ("dns", "ip address", "ipaddress"):
            names.append(str(value))
    return names


class CertificateModule(Module):
    attack_id = "tls.certificate"

    def run(self, ctx: ScanContext):
        if ctx.target.scheme != "https":
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Not a TLS target",
                    Severity.INFO,
                    detail="tls.* modules only apply to https:// targets.",
                    evidence={"scheme": ctx.target.scheme},
                )
            ]
        if ctx.dry_run:
            return []

        host, port = ctx.target.host, ctx.target.port
        verification_error = ""
        try:
            cert, der, version, cipher = handshake(
                host, port, ctx.timeout, verified=True
            )
        except ssl.SSLCertVerificationError as exc:
            verification_error = str(exc)
            try:
                cert, der, version, cipher = handshake(
                    host, port, ctx.timeout, verified=False
                )
            except (ssl.SSLError, OSError) as nested:
                return [
                    finding(
                        ctx,
                        self.attack_id,
                        "TLS handshake failed",
                        Severity.INFO,
                        detail=str(nested),
                        evidence={"host": host, "port": port},
                    )
                ]
        except (ssl.SSLError, OSError) as exc:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "TLS handshake failed",
                    Severity.LOW,
                    detail=str(exc),
                    evidence={"host": host, "port": port},
                )
            ]

        if not cert:
            cert = decode_der(der)

        subject = _flatten(cert.get("subject"))
        issuer = _flatten(cert.get("issuer"))
        sans = san_list(cert)
        not_after = parse_cert_time(str(cert.get("notAfter", "")))
        not_before = parse_cert_time(str(cert.get("notBefore", "")))
        days_left = (
            int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
            if not_after
            else None
        )
        self_signed = bool(subject) and subject == issuer

        findings = []
        if verification_error:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Certificate does not verify",
                    Severity.INFO if ctx.insecure else Severity.HIGH,
                    detail=verification_error[:300],
                    evidence={"host": host, "error": verification_error[:300]},
                )
            )
        if days_left is not None and days_left < 0:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Certificate expired {abs(days_left)} day(s) ago",
                    Severity.HIGH,
                    detail=f"notAfter {cert.get('notAfter')}",
                    evidence={"not_after": str(cert.get("notAfter")),
                              "days_left": days_left},
                )
            )
        elif days_left is not None and days_left < 30:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"Certificate expires in {days_left} day(s)",
                    Severity.MEDIUM,
                    detail=f"notAfter {cert.get('notAfter')}",
                    evidence={"not_after": str(cert.get("notAfter")),
                              "days_left": days_left},
                )
            )
        if self_signed:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Certificate is self-signed",
                    Severity.LOW,
                    detail=f"subject and issuer are both {subject}",
                    evidence={"subject": subject, "issuer": issuer},
                )
            )
        if sans and not hostname_covered(host, sans):
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{host} is not covered by the certificate",
                    Severity.MEDIUM,
                    detail=f"SANs: {', '.join(sans[:10])}",
                    evidence={"host": host, "sans": sans},
                )
            )

        findings.append(
            finding(
                ctx,
                self.attack_id,
                f"Certificate read ({version}, {cipher[0] if cipher else 'unknown'})",
                Severity.INFO,
                detail=f"subject {subject or '?'} · issuer {issuer or '?'} "
                       f"· {days_left if days_left is not None else '?'} day(s) left",
                evidence={
                    "protocol": version,
                    "cipher": cipher[0] if cipher else "",
                    "subject": subject,
                    "issuer": issuer,
                    "sans": sans,
                    "not_before": str(not_before) if not_before else "",
                    "not_after": str(not_after) if not_after else "",
                    "days_left": days_left,
                    "self_signed": self_signed,
                },
            )
        )
        return findings


def _flatten(name_tuples) -> str:
    """Turn ssl's ((('commonName','x'),),...) into 'commonName=x'."""
    parts = []
    for rdn in name_tuples or ():
        for pair in rdn or ():
            try:
                key, value = pair
            except (TypeError, ValueError):
                continue
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def supports_version(host: str, port: int, version, timeout: float) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except (AttributeError, ValueError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


class ProtocolSupportModule(Module):
    attack_id = "tls.protocol_support"

    def run(self, ctx: ScanContext):
        if ctx.target.scheme != "https":
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Not a TLS target",
                    Severity.INFO,
                    detail="tls.* modules only apply to https:// targets.",
                    evidence={"scheme": ctx.target.scheme},
                )
            ]
        if ctx.dry_run:
            return []

        host, port = ctx.target.host, ctx.target.port
        results = {
            "tls1.2": supports_version(host, port, ssl.TLSVersion.TLSv1_2, ctx.timeout),
            "tls1.3": supports_version(host, port, ssl.TLSVersion.TLSv1_3, ctx.timeout),
        }
        supported = [label for label, ok in results.items() if ok]

        if not supported:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Neither TLS 1.2 nor TLS 1.3 negotiated",
                    Severity.MEDIUM,
                    detail="The service offered no version this client accepts; "
                           "it may be ancient or require a specific SNI.",
                    evidence=results,
                )
            ]

        severity = Severity.INFO if results["tls1.3"] else Severity.LOW
        return [
            finding(
                ctx,
                self.attack_id,
                f"TLS versions accepted: {', '.join(supported)}",
                severity,
                detail="" if results["tls1.3"] else "TLS 1.3 not offered; 1.2 only.",
                evidence=results,
            )
        ]
