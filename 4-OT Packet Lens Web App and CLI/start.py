"""OT Packet Lens: reliable, standard-library-only, one-command launcher.

From PowerShell in the extracted project directory: python start.py

On first launch creates a private .venv and installs requirements. It never
silently deletes an existing environment and never disables OS security.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
STAMP = VENV / ".ot_packet_lens_requirements_sha256"
HOST = "127.0.0.1"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def requirements_fingerprint() -> str:
    return hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()


def dependencies_healthy(python: Path) -> bool:
    """Verify dpkt in the *exact* interpreter used to start the website."""
    if not python.is_file():
        return False
    try:
        probe = (
            "import dpkt, importlib.metadata as m; "
            "assert tuple(map(int, m.version('dpkt').split('.')[:3])) >= (1,9,8)"
        )
        result = subprocess.run(
            [str(python), "-c", probe],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=ROOT,
            timeout=20,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def interpreter_healthy(python: Path) -> bool:
    if not python.is_file():
        return False
    try:
        result = subprocess.run(
            [str(python), "-c", "import sys; assert sys.version_info >= (3, 9)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=ROOT, timeout=20, check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def prepare_environment() -> Path:
    if sys.version_info < (3, 9):
        raise RuntimeError("Python 3.9 or later is required.")
    python = venv_python()
    if VENV.exists() and not interpreter_healthy(python):
        raise RuntimeError(
            "The existing .venv is incomplete or uses an invalid Python interpreter.\n"
            "To preserve it, close the app and rename .venv to .venv_old in File Explorer, "
            "then rerun 'python start.py'."
        )
    if not python.is_file():
        print("[Setup] Creating project-specific .venv...", flush=True)
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True, cwd=ROOT)
        if not interpreter_healthy(python):
            raise RuntimeError(
                "The virtual environment could not start. Check that your Python installation "
                "supports 'python -m venv' and is permitted by Windows security."
            )

    checksum = requirements_fingerprint()
    good = dependencies_healthy(python)
    up_to_date = STAMP.is_file() and STAMP.read_text(encoding="utf-8").strip() == checksum
    if not good or not up_to_date:
        print("[Setup] Installing dependencies into the project .venv...", flush=True)
        subprocess.run(
            [str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")],
            check=True, cwd=ROOT,
        )
        if not dependencies_healthy(python):
            raise RuntimeError("dpkt is still unavailable in the project .venv after installation.")
        STAMP.write_text(checksum + "\n", encoding="utf-8")
    else:
        print("[Setup] Project .venv already configured; installation skipped.", flush=True)
    return python


def find_tshark() -> str | None:
    configured = os.environ.get("OT_PACKET_LENS_TSHARK", "").strip().strip('"')
    if configured and Path(configured).is_file():
        return str(Path(configured))
    located = shutil.which("tshark")
    if located:
        return located
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                candidate = Path(base) / "Wireshark" / "tshark.exe"
                if candidate.is_file():
                    return str(candidate)
    return None


def port_available(port: int) -> bool:
    """Check localhost, without touching a server already using the port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST, port))
            return True
    except OSError:
        return False


def server_ready(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.15):
            return True
    except OSError:
        return False


def doctor(port: int) -> int:
    print("OT Packet Lens — startup diagnostics")
    print(f"Project folder : {ROOT}")
    print(f"Current Python : {sys.executable}")
    print(f"Python version : {sys.version.split()[0]}")
    python = venv_python()
    print(f"Virtual Python : {python}")
    print(f"Virtual env    : {'working' if interpreter_healthy(python) else 'missing or broken'}")
    print(f"dpkt in .venv  : {'available' if dependencies_healthy(python) else 'missing / invalid'}")
    print(f"TShark         : {find_tshark() or 'NOT FOUND'}")
    print(f"TCP port {port:5} : {'available' if port_available(port) else 'ALREADY IN USE'}")
    print("This check does not install, delete, or change anything.")
    return 0


def launch_server(python: Path, tshark: str, port: int, no_browser: bool) -> int:
    if not port_available(port):
        print(f"[Error] Port {port} is already in use. Stop the older server with Ctrl+C,", file=sys.stderr)
        print(f"        or start with: python start.py --port {port + 1 if port < 65535 else 8000}", file=sys.stderr)
        return 3

    env = os.environ.copy()
    env["OT_PACKET_LENS_TSHARK"] = tshark
    url = f"http://{HOST}:{port}/"
    cmd = [str(python), "-u", str(ROOT / "run.py"), "--host", HOST,
           "--port", str(port), "--no-browser"]
    print(f"[Start] Launching server: {url}", flush=True)
    try:
        process = subprocess.Popen(cmd, cwd=ROOT, env=env)
    except OSError as exc:
        print(f"[Error] Could not start the web server: {exc}", file=sys.stderr)
        return 4

    try:
        # Wait until localhost accepts connections before opening the browser.
        for _ in range(100):
            code = process.poll()
            if code is not None:
                print(f"[Error] Web server exited early (exit code {code}). Read the Python traceback above.",
                      file=sys.stderr)
                return code if code != 0 else 4
            if server_ready(port):
                print(f"[Ready] OT Packet Lens: {url}", flush=True)
                if not no_browser:
                    try:
                        if not webbrowser.open(url):
                            print(f"[Browser] Open manually: {url}", flush=True)
                    except Exception as exc:
                        print(f"[Browser] Automatic opening failed ({exc}). Open manually: {url}", flush=True)
                return process.wait()
            time.sleep(0.2)
        print(f"[Warning] Server has not become ready yet. Wait, or check the terminal errors. URL: {url}")
        return process.wait()
    except KeyboardInterrupt:
        print("\n[Stop] Stopping the local web server...", flush=True)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Set up and start OT Packet Lens")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    parser.add_argument("--port", type=int, default=8000, help="Local HTTP port")
    parser.add_argument("--setup-only", action="store_true", help="Install dependencies without launching")
    parser.add_argument("--doctor", action="store_true", help="Print startup diagnostics without changes")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.doctor:
        return doctor(args.port)
    try:
        python = prepare_environment()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[Error] Automatic environment setup failed: {exc}", file=sys.stderr)
        print("[Help] Run 'python start.py --doctor' and share the output.", file=sys.stderr)
        print("[Help] Check internet connectivity and Python. Do not disable Smart App Control.", file=sys.stderr)
        return 1
    if args.setup_only:
        print("[OK] Dependencies ready. Start with: python start.py")
        return 0
    tshark = find_tshark()
    if not tshark:
        print("[Error] TShark not found. Install the TShark component with Wireshark,", file=sys.stderr)
        print("        or set OT_PACKET_LENS_TSHARK to its existing executable path.", file=sys.stderr)
        return 2
    print(f"[OK] TShark: {tshark}", flush=True)
    return launch_server(python, tshark, args.port, args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
