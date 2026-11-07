"""Frozen-build entry point for the desktop application.

PyInstaller cannot execute ``relift/desktop.py`` as ``__main__`` because of the
relative imports, so this module imports the installed package by name. The UI
assets are bundled with ``--add-data src/relift/desktop:<pkg>/desktop``; see
``.github/workflows/release.yml``.
"""

from relift.desktop import main

if __name__ == "__main__":
    main()
