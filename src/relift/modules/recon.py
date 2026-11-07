"""Recon techniques: resolution, HTTP fingerprinting, port sweep, versions."""

from __future__ import annotations

import ipaddress
import re
import socket

from ..models import Severity
from .base import MissingTool, Module, ScanContext, finding, run_tool, tool_path

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_NMAP_LINE = re.compile(r"^(\d+)/(?:tcp|udp)\s+(\S+)\s+(\S+)?\s*(.*)$")


def printable_banner(text: str, limit: int = 120) -> str:
    """Make a service banner safe to print and to store in a report.

    Banners are arbitrary bytes chosen by the target: control sequences, NULs
    and terminal escapes all arrive this way. Collapse them to visible ASCII so
    a report cannot be used to write escape codes to the reader's terminal.
    """
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in str(text))
    collapsed = re.sub(r"\.{3,}", "...", cleaned).strip(". ")
    return collapsed[:limit]


def classify_address(text: str) -> str:
    """How a resolved address sits relative to the public internet."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_unspecified:
        return "unspecified"
    if address.is_private:
        return "private"
    return "public"


class DnsModule(Module):
    attack_id = "recon.dns"

    def run(self, ctx: ScanContext):
        host = ctx.target.host
        try:
            infos = socket.getaddrinfo(
                host, ctx.target.port, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"{host} did not resolve",
                    Severity.INFO,
                    detail=str(exc),
                    evidence={"host": host, "addresses": []},
                )
            ]

        addresses = sorted({info[4][0] for info in infos})
        classes = {address: classify_address(address) for address in addresses}
        kinds = sorted(set(classes.values()))
        return [
            finding(
                ctx,
                self.attack_id,
                f"{host} resolves to {len(addresses)} address(es)",
                Severity.INFO,
                detail=", ".join(f"{a} ({classes[a]})" for a in addresses),
                evidence={
                    "host": host,
                    "addresses": addresses,
                    "address_class": classes,
                    "kinds": kinds,
                },
            )
        ]


class HttpFingerprintModule(Module):
    attack_id = "recon.http_fingerprint"

    def run(self, ctx: ScanContext):
        response = ctx.http_get("/")
        if response.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Root path did not respond",
                    Severity.INFO,
                    detail=response.error,
                    evidence={"url": response.url},
                )
            ]

        match = _TITLE.search(response.text)
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
        server = response.header("server")
        powered = response.header("x-powered-by")

        bits = [f"status {response.status}"]
        if server:
            bits.append(f"Server: {server}")
        if powered:
            bits.append(f"X-Powered-By: {powered}")
        if title:
            bits.append(f"title {title!r}")

        findings = [
            finding(
                ctx,
                self.attack_id,
                "HTTP fingerprint collected",
                Severity.INFO,
                detail=" · ".join(bits),
                evidence={
                    "url": response.url,
                    "status": response.status,
                    "server": server,
                    "powered_by": powered,
                    "title": title,
                },
            )
        ]
        if ctx.target.scheme == "http":
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Service is served over plaintext HTTP",
                    Severity.LOW,
                    detail=f"{response.url} answers without TLS; credentials and "
                           "session tokens cross the wire in the clear.",
                    evidence={"url": response.url},
                )
            )
        return findings


class PortScanModule(Module):
    attack_id = "recon.port_scan"

    def run(self, ctx: ScanContext):
        ports = ctx.ports or (80, 443)
        open_ports: list[int] = []
        banners: dict[int, str] = {}
        for port in ports:
            reachable, banner = ctx.tcp_probe(port)
            if reachable:
                open_ports.append(port)
                if banner:
                    banners[str(port)] = printable_banner(banner)

        if not open_ports:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "No TCP port answered",
                    Severity.INFO,
                    detail=f"probed {len(ports)} port(s): "
                           f"{', '.join(str(p) for p in ports)}",
                    evidence={"probed": list(ports), "open": []},
                )
            ]

        listing = ", ".join(str(p) for p in open_ports)
        return [
            finding(
                ctx,
                self.attack_id,
                f"{len(open_ports)} open port(s): {listing}",
                Severity.INFO,
                detail="; ".join(f"{p}: {b}" for p, b in banners.items())
                or "no service spoke first",
                evidence={
                    "probed": list(ports),
                    "open": open_ports,
                    "banners": banners,
                },
            )
        ]


class ServiceScanModule(Module):
    attack_id = "recon.service_scan"

    def run(self, ctx: ScanContext):
        binary = tool_path("nmap")
        if not binary:
            raise MissingTool("nmap")
        ports = ",".join(str(p) for p in (ctx.ports or (80, 443)))
        argv = [
            binary,
            "-sV",
            "-Pn",
            "--version-light",
            "-p",
            ports,
            ctx.target.host,
        ]
        code, stdout, stderr = run_tool(argv, timeout=max(120.0, ctx.timeout * 20))

        services = []
        for line in stdout.splitlines():
            match = _NMAP_LINE.match(line.strip())
            if not match:
                continue
            services.append(
                {
                    "port": int(match.group(1)),
                    "state": match.group(2),
                    "service": match.group(3) or "",
                    "version": match.group(4).strip(),
                }
            )

        return [
            finding(
                ctx,
                self.attack_id,
                f"{len(services)} service(s) identified",
                Severity.INFO,
                detail=stderr.strip()[:300] if code != 0 else "",
                evidence={"argv": argv, "exit": code, "services": services},
                confidence="high" if services else "low",
            )
        ]
