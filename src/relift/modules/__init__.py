"""Module registry.

A catalogue entry with no module here is design-only: the runner reports it as
skipped instead of pretending it ran.
"""

from __future__ import annotations

from . import code, db, dbauth, recon, sqlinject, ssh, system, tls, web
from .base import (
    MissingInput,
    MissingTool,
    Module,
    ScanContext,
    TCPConn,
    finding,
    run_tool,
    tool_path,
)

_MODULE_CLASSES = (
    recon.DnsModule,
    recon.MailPostureModule,
    recon.HttpFingerprintModule,
    recon.PortScanModule,
    recon.ServiceScanModule,
    tls.CertificateModule,
    tls.ProtocolSupportModule,
    tls.CipherPreferenceModule,
    web.HeadersModule,
    web.CorsPolicyModule,
    web.CookieFlagsModule,
    web.MethodsModule,
    web.ContentDisclosureModule,
    web.DirectoryProbeModule,
    web.OpenRedirectModule,
    web.PathTraversalModule,
    web.TemplateScanModule,
    web.ServerAuditModule,
    db.DatabaseFingerprintModule,
    db.DatabaseSecurityModule,
    dbauth.CredentialVerifyModule,
    sqlinject.SqlInjectionModule,
    system.HostAuditModule,
    ssh.SshAlgorithmModule,
    code.SecretsModule,
    code.DangerousSinksModule,
    code.DependenciesModule,
)

MODULES: dict[str, Module] = {cls.attack_id: cls() for cls in _MODULE_CLASSES}

__all__ = [
    "MODULES",
    "MissingInput",
    "MissingTool",
    "Module",
    "ScanContext",
    "TCPConn",
    "finding",
    "run_tool",
    "tool_path",
]
