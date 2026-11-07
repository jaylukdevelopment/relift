"""Desktop launcher: a real native window, with a startup splash.

``relift desktop`` is an application, not a browser tab. It binds a loopback
server, paints a frameless splash while the engine comes up, then reveals the
console inside a WebView2 (Windows) or WebKitGTK (Linux) window. Geometry is
remembered between launches.

``relift desktop --browser`` and a host with no GUI backend are the only paths
that open the default browser. Both paths hit the identical API in
``relift.api``, so the scope gate is not different in the desktop build.

Install ``relift[desktop]`` for the native window. Neither path phones home.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from . import BANNER, __version__
from .api import build_server, static_root

TITLE = f"Relift {__version__}"
DEFAULT_SIZE = (1280, 880)
MIN_SIZE = (1000, 700)
SPLASH_SIZE = (480, 320)
# The splash animation runs for about a second; never flash past it.
SPLASH_MIN_VISIBLE = 1.35


def app_dir() -> Path:
    """Per-user state directory. Honours ``RELIFT_HOME`` for portable installs."""
    base = os.environ.get("RELIFT_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".relift"
    return root


def window_state_path() -> Path:
    return app_dir() / "desktop-window.json"


def _read_state() -> dict[str, int]:
    try:
        raw = json.loads(window_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    clean: dict[str, int] = {}
    for key in ("width", "height", "x", "y"):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            clean[key] = value
    return clean


def _clamp_size(state: dict[str, int]) -> tuple[int, int]:
    width = max(MIN_SIZE[0], min(int(state.get("width", DEFAULT_SIZE[0])), 6000))
    height = max(MIN_SIZE[1], min(int(state.get("height", DEFAULT_SIZE[1])), 4000))
    return width, height


def _write_state(window: Any) -> None:
    try:
        state = {
            "width": int(window.width),
            "height": int(window.height),
            "x": int(window.x),
            "y": int(window.y),
        }
    except Exception:  # noqa: BLE001 - geometry is a nicety, never a failure
        return
    try:
        path = window_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    except OSError:
        return


def _print_banner(url: str, mode: str) -> None:
    print(BANNER)
    print(f"  desktop   {url}")
    print(f"  window    {mode}")
    print("  scope gate: same engine, same scope file, no bypass")
    print("  press Ctrl+C to stop")
    sys.stdout.flush()


def _splash_source() -> str | None:
    """Inline the bundled splash. Returns None if the asset is missing."""
    candidate = static_root() / "splash.html"
    try:
        return candidate.read_text(encoding="utf-8")
    except OSError:
        return None


def _display_available() -> bool:
    if sys.platform.startswith(("win", "darwin")):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _wait_until_serving(url: str, timeout: float = 15.0) -> bool:
    """Poll the loopback root until the handler answers, or give up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.4) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(0.05)
    return False


def _reveal(main: Any, splash: Any, url: str) -> None:
    """Runs inside the GUI loop: wait for the server, then swap windows."""
    started = time.monotonic()
    ready = _wait_until_serving(url)
    if not ready:
        return
    # Let the splash finish its entrance instead of flashing past.
    remaining = SPLASH_MIN_VISIBLE - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)
    try:
        main.show()
        main.restore()
    except Exception:  # noqa: BLE001
        pass
    try:
        if splash is not None:
            splash.destroy()
    except Exception:  # noqa: BLE001
        pass


def _backend_name() -> str:
    if sys.platform.startswith("win"):
        return "WebView2"
    if sys.platform == "darwin":
        return "WKWebView"
    return "WebKitGTK"


def _quit(write_state: bool, main: Any, on_closed: Any) -> None:
    """End the process once the console window is gone.

    A GTK build can leave its loop alive after the last window is destroyed, so
    a desktop quit is explicit: flush geometry, stop the loopback server, exit.
    """
    try:
        if write_state and main is not None:
            _write_state(main)
    except Exception:  # noqa: BLE001
        pass
    try:
        if on_closed is not None:
            on_closed()
    except Exception:  # noqa: BLE001
        pass
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    os._exit(0)


def _open_webview(
    url: str,
    splash: bool = True,
    debug: bool = False,
    on_closed: Any = None,
) -> bool:
    """Return True when a native window was opened and has now closed."""
    try:
        import webview  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - any import failure means "no window"
        return False

    state = _read_state()
    width, height = _clamp_size(state)
    main = None
    splash_window = None
    try:
        main = webview.create_window(
            TITLE,
            url,
            width=width,
            height=height,
            x=state.get("x"),
            y=state.get("y"),
            min_size=MIN_SIZE,
            hidden=True,
            background_color="#0a0b0d",
            text_select=True,
        )
        source = _splash_source() if splash else None
        if source:
            splash_window = webview.create_window(
                "Relift",
                html=source,
                width=SPLASH_SIZE[0],
                height=SPLASH_SIZE[1],
                resizable=False,
                frameless=True,
                easy_drag=True,
                on_top=True,
                background_color="#0a0b0d",
                text_select=False,
            )
        def _on_closed(*_args: Any) -> None:
            _quit(True, main, on_closed)

        try:
            main.events.closed.__iadd__(_on_closed)
        except Exception:  # noqa: BLE001
            pass
        webview.start(
            _reveal,
            args=(main, splash_window, url),
            debug=debug,
            private_mode=False,
            storage_path=str(app_dir() / "webview"),
        )
        return True
    except Exception as exc:  # noqa: BLE001 - GTK/WebView2 missing or broken
        print(f"native window unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        for window in (main, splash_window):
            try:
                if window is not None:
                    window.destroy()
            except Exception:  # noqa: BLE001
                pass
        return False


def _stop_server(server: Any) -> Any:
    def stop() -> None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:  # noqa: BLE001
            pass

    return stop


def launch(
    open_window: bool = True,
    port: int = 0,
    browser: bool = False,
    splash: bool = True,
    debug: bool = False,
) -> int:
    try:
        server, _token = build_server(port)
    except OSError as exc:
        print(f"cannot bind 127.0.0.1:{port}: {exc}", file=sys.stderr)
        return 3

    host, bound = server.server_address[0], server.server_address[1]
    url = f"http://{host}:{bound}/"
    thread = threading.Thread(target=server.serve_forever, name="relift-desktop", daemon=True)
    thread.start()

    windowed = False
    if not open_window:
        _print_banner(url, "none (--no-window)")
    elif browser:
        _print_banner(url, "default browser (--browser)")
        _open_browser(url)
    elif _display_available() and _open_webview(
        url, splash=splash, debug=debug, on_closed=_stop_server(server)
    ):
        windowed = True
    else:
        _print_banner(url, "default browser (no native backend)")
        _open_browser(url)

    if windowed:
        server.shutdown()
        server.server_close()
        return 0

    try:
        while thread.is_alive():
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.shutdown()
        server.server_close()
    return 0


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        print(f"open {url} in a browser", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``relift-desktop`` and the frozen desktop builds."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="relift-desktop",
        description="Relift desktop application (native window, same scope gate).",
    )
    parser.add_argument("--port", type=int, default=0, help="0 picks a free port")
    parser.add_argument(
        "--no-window",
        action="store_true",
        help="serve only and print the URL instead of opening a window",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="open the console in the default browser instead of a native window",
    )
    parser.add_argument(
        "--no-splash",
        action="store_true",
        help="skip the startup splash and show the console immediately",
    )
    parser.add_argument("--debug", action="store_true", help="enable WebView devtools")
    args = parser.parse_args(argv)
    raise SystemExit(
        launch(
            open_window=not args.no_window,
            port=args.port,
            browser=args.browser,
            splash=not args.no_splash,
            debug=args.debug,
        )
    )


__all__ = ["app_dir", "launch", "main", "window_state_path"]
