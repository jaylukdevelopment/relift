"""Recon techniques: resolution, mail posture, fingerprinting, port sweep."""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from ..models import Severity
from . import dnsproto
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


def _spf_qualifier(record: str) -> str:
    """The ``all`` mechanism's qualifier: '-', '~', '?' or '+' (default)."""
    for token in record.split()[1:]:
        lowered = token.strip().lower()
        if lowered == "all":
            return "+"
        if lowered.endswith("all") and lowered[0] in "-~?+" and lowered[1:] == "all":
            return lowered[0]
    return "missing"


def _spf_lookup_count(record: str) -> int:
    """Mechanisms that cost a DNS lookup against SPF's limit of 10.

    ``a``, ``mx`` and ``ptr`` count with or without an argument, which is why
    a bare mechanism is matched separately from its ``name:`` form.
    """
    counting_prefixes = ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")
    bare = ("a", "mx", "ptr")
    total = 0
    for token in record.split()[1:]:
        lowered = token.lower().lstrip("+-~?")
        if lowered in bare or lowered.startswith(counting_prefixes):
            total += 1
    return total


def _dmarc_field(record: str, key: str) -> str:
    for part in record.split(";"):
        name, _, value = part.strip().partition("=")
        if name.strip().lower() == key:
            return value.strip()
    return ""


class MailPostureModule(Module):
    """SPF, DMARC and MX for the target's name — the spoofing surface.

    Every other module asks what this host serves. This one asks whether
    anyone on the internet can send mail *as* this domain, which is the part of
    an attack surface that never appears in a port scan. Read-only DNS: two to
    four queries against the resolver, none against the target.
    """

    attack_id = "recon.mail_posture"

    def run(self, ctx: ScanContext):
        host = ctx.target.host.strip("[]").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Mail posture not applicable to an address",
                    Severity.INFO,
                    detail="SPF and DMARC are properties of a domain name, not an IP.",
                    evidence={"host": host},
                )
            ]
        if ctx.dry_run:
            return []

        timeout = min(4.0, ctx.timeout)
        domain = host
        txt, txt_error = dnsproto.lookup_txt(domain, timeout)
        spf = next((value for value in txt if value.lower().startswith("v=spf1")), "")

        # A https://www.example.com target still has its mail policy on the
        # parent name; ask once more rather than reporting a false absence.
        fallback = ""
        if not spf and domain.startswith("www.") and domain.count(".") >= 2:
            parent = domain[4:]
            parent_txt, parent_error = dnsproto.lookup_txt(parent, timeout)
            parent_spf = next(
                (value for value in parent_txt if value.lower().startswith("v=spf1")),
                "",
            )
            if parent_spf:
                domain, spf, fallback = parent, parent_spf, parent
            txt_error = txt_error or parent_error

        mx, mx_error = dnsproto.lookup_mx(domain, timeout)
        dmarc_txt, dmarc_error = dnsproto.lookup_txt(f"_dmarc.{domain}", timeout)
        dmarc = next(
            (value for value in dmarc_txt if value.lower().startswith("v=dmarc1")), ""
        )

        qualifier = _spf_qualifier(spf) if spf else "missing"
        policy = _dmarc_field(dmarc, "p").lower() if dmarc else "missing"
        rua = _dmarc_field(dmarc, "rua") if dmarc else ""
        spf_ok = qualifier in ("-",)
        dmarc_ok = policy in ("quarantine", "reject")

        errors = [
            text
            for text in (txt_error, mx_error, dmarc_error)
            if text
        ]
        evidence = {
            "domain": domain,
            "queried_host": host,
            "posture_from": fallback or domain,
            "spf": spf,
            "spf_all": qualifier,
            "spf_ok": spf_ok,
            "spf_lookups": _spf_lookup_count(spf) if spf else 0,
            "dmarc": dmarc,
            "dmarc_policy": policy,
            "dmarc_ok": dmarc_ok,
            "dmarc_rua": rua,
            "mx": [exchange for _pref, exchange in mx],
            "accepts_mail": bool(mx),
            "resolver_errors": errors,
            "note": "DKIM needs a selector and was not probed.",
        }

        findings = [
            finding(
                ctx,
                self.attack_id,
                f"Mail posture read for {domain}",
                Severity.INFO,
                detail=(
                    f"SPF {'present' if spf else 'absent'}, DMARC "
                    f"{'present' if dmarc else 'absent'}, "
                    f"{len(mx)} MX record(s)"
                ),
                evidence=evidence,
            )
        ]

        if not mx and not spf:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Domain does not accept mail and publishes no SPF",
                    Severity.INFO,
                    detail=(
                        "No MX and no SPF: a forged sender at this domain is "
                        "likely to bounce rather than be delivered, which lowers "
                        "the severity of the absence."
                    ),
                    evidence=evidence,
                )
            )
        elif not spf:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No SPF record: any host may claim to send as this domain",
                    Severity.MEDIUM,
                    detail=(
                        "Publish 'v=spf1 ... -all' so receivers can reject senders "
                        "that are not yours."
                    ),
                    evidence=evidence,
                )
            )
        elif qualifier == "+":
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SPF ends in +all: every sender is authorised",
                    Severity.HIGH,
                    detail=f"'{spf[:120]}' authorises the whole internet to send as {domain}.",
                    evidence=evidence,
                )
            )
        elif qualifier == "?":
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SPF ends in ?all: the result is neutral",
                    Severity.MEDIUM,
                    detail=(
                        "'?all' tells receivers to decide for themselves, which in "
                        "practice means spoofed mail is delivered. Use '-all'."
                    ),
                    evidence=evidence,
                )
            )
        elif qualifier == "~":
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SPF ends in ~all: soft-fail only",
                    Severity.LOW,
                    detail=(
                        "'~all' marks unauthorised mail but usually still delivers "
                        "it to the inbox. '-all' is the production setting."
                    ),
                    evidence=evidence,
                )
            )

        if spf and _spf_lookup_count(spf) > 10:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "SPF exceeds the 10-lookup limit",
                    Severity.LOW,
                    detail=(
                        f"{_spf_lookup_count(spf)} lookup mechanisms: receivers "
                        "will return permerror and the policy stops protecting you."
                    ),
                    evidence=evidence,
                )
            )

        if not dmarc:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "No DMARC record: nobody is told what to do with a forged sender",
                    Severity.MEDIUM,
                    detail=(
                        "Publish _dmarc.<domain> with at least 'v=DMARC1; p=none; "
                        "rua=mailto:...' so reports arrive before you enforce."
                    ),
                    evidence=evidence,
                )
            )
        elif policy in ("none", ""):
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "DMARC is in monitor mode (p=none)",
                    Severity.MEDIUM,
                    detail=(
                        "Reporting without enforcement: forged mail is still "
                        "delivered. Move to p=quarantine, then p=reject."
                    ),
                    evidence=evidence,
                )
            )
        elif policy == "quarantine":
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "DMARC quarantines forged mail",
                    Severity.LOW,
                    detail=(
                        "p=quarantine is enforced but mail can still reach a "
                        "spam folder; p=reject is stronger."
                    ),
                    evidence=evidence,
                )
            )

        if dmarc and not rua:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "DMARC has no reporting address (rua)",
                    Severity.INFO,
                    detail="Without rua= you cannot see who is spoofing the domain.",
                    evidence=evidence,
                )
            )

        if errors:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Some DNS queries did not complete",
                    Severity.INFO,
                    detail="; ".join(errors)[:300],
                    evidence={"resolver_errors": errors},
                    confidence="low",
                )
            )
        return findings


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

        # A filtered port costs the full timeout, so a serial sweep is only as
        # fast as the slowest closed port times the list. The budget lock in
        # ScanContext keeps the rate limit intact across these threads.
        workers = max(1, min(8, len(ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(ctx.tcp_probe, ports))

        for port, (reachable, banner) in zip(ports, results):
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
