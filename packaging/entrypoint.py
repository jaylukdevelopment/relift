"""Frozen-build entry point.

PyInstaller cannot execute ``relift/__main__.py`` directly because it uses
relative imports. This module imports the installed package by name instead and
is used only by the release build, never by normal installs.
"""

from relift.cli import entry

if __name__ == "__main__":
    entry()
