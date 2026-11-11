"""Relift — Pixelcity red-team orchestration CLI.

Author : Jay
Company: Pixelcity
License: Source-available, proprietary; see LICENSE. Public, not open source.

The engine (catalog, scope, modules, runner, report) has no dependency on the
``ai`` package. Removing ``relift.ai`` leaves a fully working scanner.
"""

__version__ = "0.4.0"
__author__ = "Jay"
__company__ = "Pixelcity"
__title__ = "Relift"

BANNER = "RELIFT · Pixelcity Red Team Orchestrator · v" + __version__

__all__ = [
    "__version__",
    "__author__",
    "__company__",
    "__title__",
    "BANNER",
]
