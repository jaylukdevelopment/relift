# -*- mode: python ; coding: utf-8 -*-
"""One-file desktop build for Linux and Windows.

Why a spec instead of the command line: PyInstaller bundles the build image's
``libstdc++``/``libgcc_s`` and puts them ahead of the host's copies at runtime.
Built on Ubuntu 22.04, that bundled libstdc++ is older than the one a current
distribution (for example Arch, glibc 2.4x) uses, so WebKitGTK's typelib load
fails with ``CXXABI_1.3.15 not found`` and the window silently falls back to a
browser. Every Linux desktop ships both libraries; leaving them out makes the
binary use the host's own, which is the ABI it was compiled to talk to.

    python -m PyInstaller --clean --noconfirm packaging/relift-desktop.spec
"""

import os
import sys

from PyInstaller.utils.hooks import collect_all

# Paths in a spec are relative to the spec file, not the working directory.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

datas = [(os.path.join(ROOT, "src/relift/desktop"), "relift/desktop")]
binaries = []
hiddenimports = ["webview.platforms.edgechromium"]

# PyGObject/WebKitGTK only exists on the Linux build. Asking PyInstaller to
# collect it on Windows just emits warnings and pulls nothing in.
_packages = ["webview"]
if sys.platform.startswith("linux"):
    _packages.append("gi")
    hiddenimports.append("webview.platforms.gtk")

for package in _packages:
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

a = Analysis(
    [os.path.join(ROOT, "packaging/desktop_entry.py")],
    pathex=[os.path.join(ROOT, "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# See the module docstring. On Linux no shared system library is bundled:
# the build image's GLib, GTK, libmount, libstdc++ and friends are older than
# the ones on a current distribution, and once they shadow the host's copies
# the mismatches compound (CXXABI_1.3.15, g_once_init_enter_pointer,
# MOUNT_2_40). Python extension modules (``_gi``, ``_ssl``, ...) are kept
# because they are the interpreter's own ABI.
if sys.platform.startswith("linux"):
    _PYTHON_RUNTIME = ("libpython", "libmpdec")

    def _host_provides(path: str) -> bool:
        base = os.path.basename(path)
        return base.startswith("lib") and not base.startswith(_PYTHON_RUNTIME)

    a.binaries = [entry for entry in a.binaries if not _host_provides(entry[0])]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="relift-desktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
