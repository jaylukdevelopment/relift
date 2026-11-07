"""Local host audit: the privilege-escalation surface, read-only.

This module answers one question: if a low-privilege account (a service user, a
build agent, a container) were already on this machine, what would it find? It
enumerates that surface and reports it. It does not exploit anything, does not
shell out, does not run sudo and writes no file — every collector is a stat, a
read of /proc or a read of /etc.

The kernel CVE table is deliberately coarse. A distribution backports fixes
without changing the kernel's upstream version, so a hit here means "compare
this against your distro's advisory", never "this host is exploitable".
"""

from __future__ import annotations

try:
    import grp  # POSIX only; Windows has no group database
    _HAS_GRP = True
except ImportError:  # pragma: no cover - exercised on the Windows CI runner
    grp = None  # type: ignore[assignment]
    _HAS_GRP = False

import os
import platform
import re
import socket
import stat
import struct

from ..models import Severity
from .base import Module, ScanContext, finding

SCAN_DIRS = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/libexec",
    "/opt",
)
MAX_DEPTH = 3          # only /opt is deep enough to matter
MAX_ENTRIES = 400      # per directory
MAX_SUID = 60
MAX_CAPS = 20
MAX_SUDO_RULES = 40

# capability number -> short name, for the bits worth naming in a report
CAPABILITY_NAMES = {
    2: "cap_dac_read_search",
    6: "cap_setgid",
    7: "cap_setuid",
    13: "cap_net_raw",
    16: "cap_sys_module",
    21: "cap_sys_admin",
    39: "cap_bpf",
}

# (cve, label, first upstream release that contains the fix)
KERNEL_FIXES = (
    ("CVE-2016-5195", "dirty-cow", (4, 8, 3)),
    ("CVE-2022-0185", "fs-context", (5, 16, 2)),
    ("CVE-2022-0847", "dirty-pipe", (5, 16, 11)),
    ("CVE-2023-0386", "overlayfs", (6, 2, 0)),
    ("CVE-2023-32233", "nf-tables", (6, 3, 2)),
    ("CVE-2024-1086", "nf-tables", (6, 7, 3)),
)

DOCKER_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
)

STICKY_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

_KERNEL = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _kernel_tuple(release: str) -> tuple[int, ...]:
    match = _KERNEL.match((release or "").strip())
    if not match:
        return ()
    return tuple(int(part) for part in match.groups() if part is not None)


def _read_text(path: str, cap: int = 512 * 1024) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(cap)
    except OSError:
        return ""


def _walk_files(root: str, depth: int = 0):
    """Yield regular file paths under ``root``, bounded in every direction."""
    try:
        entries = os.scandir(root)
    except OSError:
        return
    with entries:
        seen = 0
        for entry in entries:
            seen += 1
            if seen > MAX_ENTRIES:
                return
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < MAX_DEPTH:
                        yield from _walk_files(entry.path, depth + 1)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            yield entry.path


def _capabilities_for(path: str) -> list[str]:
    """Decode security.capability into the capability names it grants."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return []
    try:
        value = getxattr(path, "security.capability", follow_symlinks=False)
    except (OSError, AttributeError, TypeError):
        return []
    if len(value) < 12:
        return []
    # struct vfs_cap_data: magic_etc, data[0].permitted, data[0].inheritable,
    #                      data[1].permitted, data[1].inheritable  (all __le32)
    permitted = struct.unpack_from("<I", value, 4)[0]
    if len(value) >= 20:
        permitted |= struct.unpack_from("<I", value, 12)[0] << 32
    names = [
        CAPABILITY_NAMES[index]
        for index in sorted(CAPABILITY_NAMES)
        if permitted & (1 << index)
    ]
    return names


def _suid_surface() -> tuple[list[str], list[str], list[str]]:
    suid: list[str] = []
    sgid: list[str] = []
    caps: list[str] = []
    for root in SCAN_DIRS:
        if not os.path.isdir(root):
            continue
        for path in _walk_files(root):
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & stat.S_ISUID and len(suid) < MAX_SUID:
                suid.append(path)
            if info.st_mode & stat.S_ISGID and len(sgid) < MAX_SUID:
                sgid.append(path)
            if len(caps) < MAX_CAPS:
                for name in _capabilities_for(path):
                    caps.append(f"{path} {name}")
                    if len(caps) >= MAX_CAPS:
                        break
    return sorted(suid), sorted(sgid), sorted(caps)


def _sudo_rules() -> list[str]:
    rules: list[str] = []
    sources = ["/etc/sudoers"]
    try:
        dropins = sorted(os.listdir("/etc/sudoers.d"))[:10]
    except OSError:
        dropins = []
    for name in dropins:
        if name.startswith(".") or name.endswith("~"):
            continue
        sources.append(os.path.join("/etc/sudoers.d", name))
    for source in sources:
        text = _read_text(source)
        if not text:
            continue
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#") or entry.startswith("Defaults"):
                continue
            if entry.startswith("@include") or entry.startswith("#include"):
                continue
            rules.append(entry[:200])
            if len(rules) >= MAX_SUDO_RULES:
                return rules
    return rules


def _world_writable() -> list[str]:
    found: list[str] = []
    for directory in (os.environ.get("PATH") or "").split(os.pathsep):
        if not directory or directory in found:
            continue
        try:
            info = os.stat(directory)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o002:
            found.append(directory)
    for directory in STICKY_DIRS:
        try:
            info = os.stat(directory)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and not info.st_mode & stat.S_ISVTX:
            # World-writable *without* the sticky bit is the interesting case:
            # any account can replace files it does not own.
            found.append(directory)
    return sorted(set(found))


def _group_name(gid: int) -> str:
    """Resolve a gid, or fall back to its number where there is no group db."""
    if not _HAS_GRP:
        return str(gid)
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _group_names() -> set[str]:
    names: set[str] = set()
    if not _HAS_GRP:
        return names
    try:
        for gid in os.getgroups():
            names.add(_group_name(gid))
    except OSError:
        pass
    return names


def _docker_socket() -> tuple[bool, str]:
    candidates = list(DOCKER_SOCKETS)
    host = os.environ.get("DOCKER_HOST") or ""
    if host.startswith("unix://"):
        candidates.insert(0, host[len("unix://"):])
    groups = _group_names()
    denied: str = ""
    for path in candidates:
        try:
            info = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISSOCK(info.st_mode):
            continue
        mode = stat.S_IMODE(info.st_mode)
        owner_group = _group_name(info.st_gid)
        if mode & 0o006:
            return True, f"{path} mode {mode:04o}: any local account can drive the runtime"
        if owner_group in groups:
            return True, f"{path} mode {mode:04o}: this account is in group {owner_group}"
        denied = (
            f"{path} mode {mode:04o}, owned by group {owner_group}, "
            "which this account is not in"
        )
    return False, denied


def _decode_v4(hex_address: str) -> str:
    try:
        raw = bytes.fromhex(hex_address)
    except ValueError:
        return hex_address
    if len(raw) != 4:
        return hex_address
    return ".".join(str(part) for part in raw[::-1])


def _decode_v6(hex_address: str) -> str:
    try:
        raw = bytes.fromhex(hex_address)
    except ValueError:
        return hex_address
    if len(raw) == 16:
        # /proc stores each 32-bit word little-endian.
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
        text = socket.inet_ntop(socket.AF_INET6, raw)
        return text[7:] if text.startswith("::ffff:") else text
    return hex_address


def _listening() -> list[str]:
    found: list[str] = []
    for path, decoder in (("/proc/net/tcp", _decode_v4), ("/proc/net/tcp6", _decode_v6)):
        text = _read_text(path)
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            local = fields[1]
            if ":" not in local:
                continue
            address, port_hex = local.rsplit(":", 1)
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            found.append(f"{decoder(address)}:{port}")
    return sorted(set(found))[:40]


def _kernel_advisories(kernel: tuple[int, ...]) -> list[str]:
    if not kernel:
        return []
    hits: list[str] = []
    for cve, label, fixed in KERNEL_FIXES:
        if kernel < fixed:
            hits.append(f"{cve} {label} (fixed in {'.'.join(str(p) for p in fixed)})")
    return hits


def _is_loopback(entry: str) -> bool:
    address = entry.rsplit(":", 1)[0]
    return address.startswith("127.") or address in ("::1", "0:0:0:0:0:0:0:1")


class HostAuditModule(Module):
    attack_id = "system.host_audit"

    def run(self, ctx: ScanContext):
        if platform.system() != "Linux":
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Host audit supports Linux only",
                    Severity.INFO,
                    detail=f"this host reports {platform.system()} {platform.release()}; "
                           "the collectors read /proc and /etc and are not portable",
                    evidence={"platform": platform.platform()},
                    confidence="high",
                )
            ]

        os_name = self._os_name()
        kernel_text = platform.release()
        kernel = _kernel_tuple(kernel_text)
        arch = platform.machine()

        suid, sgid, caps = self._safe(_suid_surface, ([], [], []))
        sudo_rules = self._safe(_sudo_rules, [])
        writable = self._safe(_world_writable, [])
        docker, docker_detail = self._safe(_docker_socket, (False, ""))
        listening = self._safe(_listening, [])
        advisories = _kernel_advisories(kernel)

        evidence = {
            "os": os_name,
            "kernel": kernel_text,
            "arch": arch,
            "suid": suid,
            "sgid": sgid,
            "capabilities": caps,
            "sudo_rules": sudo_rules,
            "world_writable_paths": writable,
            "docker_socket": docker,
            "docker_socket_detail": docker_detail,
            "listening": listening,
            "kernel_cves": advisories,
        }

        findings = [
            finding(
                ctx,
                self.attack_id,
                f"Host audit: {os_name} kernel {kernel_text}",
                Severity.INFO,
                detail=(
                    f"{len(suid)} SUID · {len(sgid)} SGID · {len(caps)} capabilities · "
                    f"{len(sudo_rules)} sudo rule(s) readable · "
                    f"{len(writable)} writable path(s) · "
                    f"{len(listening)} listening socket(s)"
                ),
                evidence=evidence,
            )
        ]

        if suid or sgid:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{len(suid) + len(sgid)} SUID/SGID binaries on the host",
                    Severity.MEDIUM,
                    detail=", ".join((suid + sgid)[:8]),
                    evidence={"suid": suid, "sgid": sgid},
                )
            )

        if caps:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "File capabilities grant extra privilege",
                    Severity.MEDIUM,
                    detail=", ".join(caps[:8]),
                    evidence={"capabilities": caps},
                )
            )

        risky_sudo = [
            rule for rule in sudo_rules
            if "NOPASSWD" in rule.upper() or "ALL=(ALL" in rule.upper().replace(" ", "")
        ]
        if risky_sudo:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{len(risky_sudo)} sudo rule(s) grant broad passwordless rights",
                    Severity.MEDIUM,
                    detail=", ".join(risky_sudo[:4]),
                    evidence={"rules": risky_sudo},
                )
            )
        elif sudo_rules:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{len(sudo_rules)} sudo rule(s) readable",
                    Severity.INFO,
                    detail="readable rules are a map of who may become whom",
                    evidence={"rules": sudo_rules},
                )
            )

        if docker:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    "Container runtime socket reachable from this account",
                    Severity.CRITICAL,
                    detail=docker_detail,
                    evidence={"detail": docker_detail},
                )
            )

        if advisories:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{len(advisories)} kernel build(s) below a published fix",
                    Severity.HIGH,
                    detail="advisory only: distro backports may already fix these — "
                           + ", ".join(advisories[:4]),
                    evidence={"kernel": kernel_text, "advisories": advisories},
                    confidence="low",
                )
            )

        exposed = [entry for entry in listening if not _is_loopback(entry)]
        if exposed:
            findings.append(
                finding(
                    ctx,
                    self.attack_id,
                    f"{len(exposed)} listener(s) not bound to loopback",
                    Severity.INFO,
                    detail=", ".join(exposed[:10]),
                    evidence={"listening": exposed},
                )
            )

        return findings

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _os_name() -> str:
        for line in _read_text("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return platform.platform()

    @staticmethod
    def _safe(collector, fallback):
        """A broken collector degrades the audit; it never aborts it."""
        try:
            return collector()
        except (OSError, ValueError, AttributeError):
            return fallback
