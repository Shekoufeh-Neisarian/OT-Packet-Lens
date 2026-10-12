"""PySide6 native desktop shell for OT Packet Lens (no Edge dependency).

The existing HTTP API continues to operate *only on 127.0.0.1*; Qt WebEngine
provides the native desktop window. Python/Qt are frozen by PyInstaller and
TShark is supplied beside the executable in the portable Windows package.
"""
from __future__ import annotations

import ctypes
import http.server
import os
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

APP_NAME = "OT Packet Lens"


def distribution_dir() -> Path:
    """External TShark/captures live beside the frozen EXE, not in _MEIPASS."""
    origin = sys.executable if getattr(sys, "frozen", False) else __file__
    return Path(origin).resolve().parent


def user_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / APP_NAME


def configure_paths() -> Path:
    """Set overrides before loading web.app, which resolves paths at import."""
    root = user_data_dir()
    root.mkdir(parents=True, exist_ok=True)
    os.environ["OT_PACKET_LENS_DATA_DIR"] = str(root)
    os.environ["OT_PACKET_LENS_SAMPLE_ROOT"] = str(distribution_dir())
    if sys.stdout is None or sys.stderr is None:
        logfile = open(root / "desktop.log", "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = logfile
        if sys.stderr is None:
            sys.stderr = logfile
    return root


def find_tshark() -> Optional[str]:
    shipped = distribution_dir() / "Wireshark" / "tshark.exe"
    if shipped.is_file():
        return str(shipped.resolve())
    # Source mode remains useful while developing on Windows with Wireshark installed.
    from analyzer.wireshark_reference import find_tshark as installed
    return installed()


def show_error(message: str) -> None:
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)
    else:
        print(f"{APP_NAME}: {message}", file=sys.stderr)


def wait_for_server(url: str, server_thread: threading.Thread, timeout: float = 25.0) -> None:
    """Wait for *HTTP readiness*, not merely an allocated TCP port."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    reason = "no response"
    while time.monotonic() < deadline:
        if not server_thread.is_alive():
            raise RuntimeError("Local dashboard server stopped during startup")
        try:
            request = urllib.request.Request(url.rstrip("/") + "/api/health", headers={"Cache-Control": "no-cache"})
            with opener.open(request, timeout=0.8) as response:
                if response.status == 200 and b'"ok"' in response.read(256):
                    return
                reason = f"readiness endpoint returned HTTP {response.status}"
        except (OSError, urllib.error.URLError) as exc:
            reason = str(exc)
        time.sleep(0.15)
    raise RuntimeError(f"Local dashboard did not respond after {timeout:g} seconds: {reason}")


def start_local_server():
    # Import only after configure_paths sets writable and sample paths.
    from web.app import ICSRequestHandler
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ICSRequestHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True, name="packet-lens-http")
    t.start()
    return server, t, f"http://127.0.0.1:{server.server_port}/"


def create_desktop_window(url: str, data_root: Path):
    """Create a standalone Qt desktop window using embedded Chromium, not Edge."""
    from PySide6.QtCore import QUrl, Qt
    from PySide6.QtGui import QAction, QDesktopServices
    from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox
    from PySide6.QtWebEngineCore import QWebEngineProfile
    from PySide6.QtWebEngineWidgets import QWebEngineView

    class PacketLensWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("OT Packet Lens — Industrial Traffic Investigation")
            self.resize(1320, 860)
            self.setMinimumSize(920, 600)

            # Persistent, writable app data ensures downloads work in frozen mode.
            profile = QWebEngineProfile.defaultProfile()
            profile.setDownloadPath(str(data_root / "reports"))
            (data_root / "reports").mkdir(parents=True, exist_ok=True)
            profile.downloadRequested.connect(self._on_download)

            base = QWidget()
            vertical = QVBoxLayout(base)
            vertical.setContentsMargins(0, 0, 0, 0)
            vertical.setSpacing(0)
            bar = QWidget()
            bar.setStyleSheet("background: #101e2d; color: #ecf2fa;")
            h = QHBoxLayout(bar)
            h.setContentsMargins(18, 9, 18, 9)
            h.setSpacing(10)
            name = QLabel("◈  OT PACKET LENS")
            name.setStyleSheet("font-size: 13px; font-weight: 700; letter-spacing: 1px;")
            h.addWidget(name)
            h.addStretch(1)
            status = QLabel("●  LOCAL / OFFLINE")
            status.setStyleSheet("color: #65d6b0; font-weight: 600; font-size: 11px;")
            h.addWidget(status)
            def button(caption, callback):
                b = QPushButton(caption)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setStyleSheet("QPushButton {color: #dfe9f6; padding: 7px 11px; background: #263c55; border: 0; border-radius: 5px;} QPushButton:hover {background: #365575;}")
                b.clicked.connect(callback)
                h.addWidget(b)
            button("Home", lambda: self.viewer.setUrl(QUrl(url)))
            button("Reload", lambda: self.viewer.reload())
            button("Reports", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(data_root / "reports"))))
            vertical.addWidget(bar)
            self.viewer = QWebEngineView()
            self.viewer.loadFinished.connect(self._loaded)
            self.viewer.setUrl(QUrl(url))
            vertical.addWidget(self.viewer, 1)
            self.setCentralWidget(base)
            self.statusBar().showMessage("PCAPs stay on your device · TShark decoding runs locally")
            # Download links in Export Center are handled by the embedded profile.

        def _on_download(self, download):
            download.accept()
            self.statusBar().showMessage(f"Downloading report to {data_root / 'reports'}", 10000)

        def _loaded(self, ok: bool):
            if not ok:
                self.statusBar().showMessage("Dashboard loading error — use Reload", 20000)
                QMessageBox.warning(self, APP_NAME, "The local dashboard did not load. Try Reload or check desktop.log.")
            else:
                self.statusBar().showMessage("Ready · Choose a PCAP to analyze", 7000)

    return PacketLensWindow()


def launch_desktop() -> int:
    if sys.platform != "win32":
        show_error("Desktop executable targets Windows. For other platforms use python start.py.")
        return 2
    data = configure_paths()
    tshark = find_tshark()
    if not tshark:
        show_error("Bundled TShark is missing. Extract the complete portable ZIP and keep the Wireshark folder beside the EXE.")
        return 3
    os.environ["OT_PACKET_LENS_TSHARK"] = tshark
    server = thread = None
    try:
        server, thread, url = start_local_server()
        wait_for_server(url, thread)
        # Qt imports intentionally deferred so dependency-independent tests run
        # without requiring Qt on developer machines.
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
        app.setApplicationName(APP_NAME)
        app.setOrganizationName("Shekoufeh Neisarian")
        window = create_desktop_window(url, data)
        window.show()
        return app.exec()
    except Exception as exc:
        show_error(f"Desktop startup failed: {exc}\n\nDiagnostics: {data / 'desktop.log'}")
        return 1
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)


def main() -> int:
    return launch_desktop()


if __name__ == "__main__":
    raise SystemExit(main())
