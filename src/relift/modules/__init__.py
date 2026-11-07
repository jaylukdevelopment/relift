"""Module registry.

A catalogue entry with no module here is design-only: the runner reports it as
skipped instead of pretending it ran.
"""

from __future__ import annotations

from . import recon, tls, web
from .base import (
    MissingTool,
    Module,
    ScanContext,
    finding,
    run_tool,
    tool_path,
)

_MODULE_CLASSES = (
    recon.DnsModule,
    recon.HttpFingerprintModule,
    recon.PortScanModule,
    recon.ServiceScanModule,
    tls.CertificateModule,
    tls.ProtocolSupportModule,
    web.HeadersModule,
    web.MethodsModule,
    web.ContentDisclosureModule,
    web.TemplateScanModule,
    web.ServerAuditModule,
)

MODULES: dict[str, Module] = {cls.attack_id: cls() for cls in _MODULE_CLASSES}

__all__ = [
    "MODULES",
    "MissingTool",
    "Module",
    "ScanContext",
    "finding",
    "run_tool",
    "tool_path",
]
