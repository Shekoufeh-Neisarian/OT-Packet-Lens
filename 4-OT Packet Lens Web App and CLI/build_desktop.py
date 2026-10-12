"""Build a native PySide6 OT Packet Lens executable with a portable TShark runtime.

Windows PowerShell (run in project root)::

    python build_desktop.py --include-captures

Build output:
    dist/OT Packet Lens/OT Packet Lens.exe
    dist/OT Packet Lens/_internal/ (Qt/Python runtime)
    dist/OT Packet Lens/Wireshark/tshark.exe   (bundled official installation, no install on target)
    dist/OT Packet Lens/THIRD_PARTY_NOTICES.md
    dist/OT Packet Lens/sources/wireshark-<matching-version>.tar.xz
    dist/OT_Packet_Lens_Windows_Portable.zip

Source is included in the shareable ZIP to help satisfy GPLv2 source-distribution
obligations. Other third-party license obligations must still be reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE_BASE = "https://www.wireshark.org/download/src/all-versions"
MAX_SOURCE_BYTES = 180 * 1024 * 1024


def build_command(python: Path) -> list[str]:
    """Freeze PySide6 QtWebEngine and the dashboard in a fast-starting folder.

    Use --onedir: QtWebEngine needs a helper process, Qt plugins and resources.
    A onefile build extracts these on every launch and is significantly slower.
    """
    sep = os.pathsep
    return [
        str(python), "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name", "OT Packet Lens", "--collect-all", "dpkt",
        "--hidden-import", "PySide6.QtWebEngineWidgets",
        "--hidden-import", "PySide6.QtWebEngineCore",
        "--version-file", str(ROOT / "docs" / "windows_version_info.txt"),
        "--add-data", f"{ROOT / 'web' / 'static'}{sep}web/static",
        "--add-data", f"{ROOT / 'web' / 'templates'}{sep}web/templates",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build" / "pyinstaller"),
        "--specpath", str(ROOT / "build"),
        str(ROOT / "desktop.py"),
    ]


def validate_qt_runtime(app_root: Path) -> None:
    """Fail the build if the QtWebEngine helper/resources were omitted."""
    if not (app_root / "OT Packet Lens.exe").is_file():
        raise RuntimeError("Qt desktop executable not found in portable application folder")
    helpers = list(app_root.rglob("QtWebEngineProcess.exe"))
    if not helpers:
        raise RuntimeError("QtWebEngineProcess.exe was not included by PyInstaller; upgrade PyInstaller and PySide6")
    resources = list(app_root.rglob("qtwebengine_resources.pak"))
    if not resources:
        raise RuntimeError("Qt WebEngine resources missing; cannot distribute a working embedded browser")


def parse_tshark_version(output: str) -> str:
    """Accept official TShark version forms, fail closed on unknown builds."""
    first = output.splitlines()[0] if output.strip() else ""
    match = re.search(r"\b(?:TShark|Wireshark)\s*(?:\(Wireshark\))?\s*(\d+\.\d+\.\d+)\b", first, re.I)
    if not match:
        raise ValueError(f"Cannot determine official Wireshark version from: {first[:120]!r}")
    return match.group(1)


def source_filename(version: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid Wireshark version")
    return f"wireshark-{version}.tar.xz"


def locate_installed_tshark() -> Path:
    from analyzer.wireshark_reference import find_tshark
    found = find_tshark()
    if not found:
        raise FileNotFoundError(
            "TShark is required on the BUILD computer only. Install Wireshark with TShark, "
            "then rerun. Recipients will not need Wireshark."
        )
    path = Path(found).resolve()
    if not path.is_file() or path.name.lower() != "tshark.exe":
        raise FileNotFoundError(f"TShark executable not found: {path}")
    return path


def check_tshark(binary: Path, sample: Path | None = None) -> str:
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True,
                             timeout=35, check=True)
    detected = parse_tshark_version(version.stdout)
    if sample and sample.is_file():
        result = subprocess.run([str(binary), "-n", "-r", str(sample.resolve()), "-c", "1",
                                 "-T", "fields", "-e", "frame.number"],
                                capture_output=True, text=True, timeout=40, check=True)
        if not result.stdout.strip():
            raise RuntimeError("Portable TShark returned no decoded packet for the validation PCAP")
    return detected


def select_test_pcap() -> Path | None:
    sample = ROOT / "pcaps" / "samples" / "ModbusTCP_ModbusTCP.pcap"
    if sample.is_file():
        return sample
    return next((p for p in (ROOT / "pcaps").rglob("*.pcap") if p.is_file()), None)


def bundle_tshark(source_exe: Path, target: Path) -> str:
    """Copy the WHOLE runtime tree to retain native DLLs, profiles and dissector plugins.

    Do not copy only tshark.exe: that regularly fails on clean Windows machines.
    """
    source_root = source_exe.parent.resolve()
    target = target.resolve()
    if source_root == target or source_root in target.parents:
        raise RuntimeError("Destination must not be inside the installed Wireshark directory")
    if target.exists():
        shutil.rmtree(target)
    print(f"[Portable] Copying Wireshark/TShark runtime from {source_root}...", flush=True)
    shutil.copytree(source_root, target)
    bundled_exe = target / "tshark.exe"
    if not bundled_exe.is_file():
        raise RuntimeError("Copied runtime has no tshark.exe")
    detected = check_tshark(bundled_exe, select_test_pcap())
    print(f"[Portable] Bundled TShark {detected}: version and PCAP decode test passed.", flush=True)
    return detected


def _download_matching_source(version: str, destination: Path) -> Path:
    filename = source_filename(version)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / filename
    if target.exists() and target.stat().st_size > 1024 * 1024:
        print(f"[Licenses] Using existing matching source archive: {target.name}")
        return target
    url = f"{SOURCE_BASE}/{filename}"
    print(f"[Licenses] Downloading the matching Wireshark source archive ({version})...", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "OTPacketLens-PortableBuilder/1.0"})
    tmp_path = None
    try:
        with urllib.request.urlopen(req, timeout=60) as response, tempfile.NamedTemporaryFile(
                dir=str(destination), prefix=".source-", delete=False) as temp:
            tmp_path = Path(temp.name)
            amount = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                amount += len(chunk)
                if amount > MAX_SOURCE_BYTES:
                    raise RuntimeError("Downloaded Wireshark source exceeds allowed size")
                temp.write(chunk)
        if amount < 1024 * 1024:
            raise RuntimeError("Downloaded source archive is unexpectedly small")
        tmp_path.replace(target)
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
    return target


def prepare_source_archive(version: str, sources_dir: Path, provided: Path | None = None) -> Path:
    expected = source_filename(version)
    if provided is not None:
        if provided.name != expected:
            raise ValueError(f"Source archive must be named {expected} to match bundled TShark")
        if not provided.is_file() or provided.stat().st_size < 1024 * 1024:
            raise ValueError("Provided source archive is missing or too small")
        sources_dir.mkdir(parents=True, exist_ok=True)
        dest = sources_dir / expected
        if provided.resolve() != dest.resolve():
            shutil.copy2(provided, dest)
        return dest
    return _download_matching_source(version, sources_dir)


def write_distribution_notices(dist: Path, version: str) -> None:
    notice = f"""# Third-party software and source distribution

OT Packet Lens invokes a **separate** TShark executable for decoding PCAPs.
It does not link to TShark or its libraries. The included `Wireshark/`
folder is copied from an official Wireshark installation and retains
supporting DLLs, plugin dissectors, and runtime data.

**Qt / PySide6:** Dynamically linked desktop UI runtime, subject to the applicable
Qt LGPL/GPL/commercial license terms. Review https://doc.qt.io/qtforpython-6/licenses.html
and include applicable Qt license texts and corresponding source or written offer,
as required by your chosen licensing route. Keep replaceable Qt shared libraries.

**Wireshark/TShark version:** {version}
**Project:** https://www.wireshark.org/
**Wireshark license:** GNU GPL version 2 (and other applicable component terms)
**Corresponding upstream source:** `sources/wireshark-{version}.tar.xz`
**Upstream source URL:** {SOURCE_BASE}/wireshark-{version}.tar.xz
**Upstream license details:** https://www.wireshark.org/download/docs/faq

Wireshark and TShark are independent open-source products, not developed by
OT Packet Lens. Redistribution requires compliance with Wireshark GPLv2 and
ALL applicable third-party dependency licenses. Check the included Wireshark
installation's licenses and the corresponding source archive. If you make
modified builds or use non-official components, provide their corresponding
sources as required. Consider formal licensing review for external distribution.

**Npcap:** The product analyzes SAVED PCAP/PCAPNG files only. It does not
install a packet-capture driver or require Npcap on the recipient PC.

**Runtime:** Windows 10/11 x64. PySide6 / Qt WebEngine provides the embedded
application window; Microsoft Edge, Python and Wireshark are not required
on the recipient's machine. All contents of the portable folder are needed.

**Windows code signing:** The EXE is unsigned unless you sign it. Do not
bypass Microsoft Smart App Control or your organization's security settings.
"""
    (dist / "THIRD_PARTY_NOTICES.md").write_text(notice, encoding="utf-8")


def create_portable_zip(app_root: Path, archive_path: Path) -> None:
    """Zip the full native Qt application tree; never just the EXE."""
    if not (app_root / "OT Packet Lens.exe").is_file():
        raise FileNotFoundError("No compiled desktop executable in application folder")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=5,
                         allowZip64=True) as archive:
        for item in sorted(app_root.rglob("*")):
            if item.is_file():
                archive.write(item, Path(app_root.name) / item.relative_to(app_root))
    with zipfile.ZipFile(archive_path) as check:
        if check.testzip() is not None:
            raise RuntimeError("Failed portable ZIP integrity test")
    print(f"[Portable] Shareable release: {archive_path}", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build the Windows desktop application and bundled TShark release")
    parser.add_argument("--include-captures", action="store_true",
                        help="Include demo Mystery/sample PCAPs beside the EXE")
    parser.add_argument("--source-archive", type=Path,
                        help="Use a locally downloaded matching-version Wireshark source tarball")
    parser.add_argument("--skip-source-download", action="store_true",
                        help="Local testing only: do not fetch matching source or create a distributable ZIP")
    parser.add_argument("--no-bundle-tshark", action="store_true",
                        help="Legacy build only: require installed TShark on recipient computers")
    parser.add_argument("--sign-thumbprint", help="Sign after build using this certificate in the Windows user store")
    parser.add_argument("--self-signed-test", action="store_true",
                        help="Local testing only: use PowerShell, no SignTool; signature will not be publicly trusted")
    args = parser.parse_args(argv)
    if args.self_signed_test and not args.sign_thumbprint:
        parser.error("--self-signed-test requires --sign-thumbprint")
    if args.sign_thumbprint and (args.no_bundle_tshark or args.skip_source_download):
        parser.error("Signing-and-packaging requires bundled TShark and the matching source archive")
    if os.name != "nt":
        print("Windows executables must be compiled using Windows PowerShell.", file=sys.stderr)
        return 2
    from start import prepare_environment
    try:
        installed_tshark = locate_installed_tshark() if not args.no_bundle_tshark else None
        if installed_tshark:
            print(f"[Build] Source TShark: {installed_tshark}", flush=True)
            check_tshark(installed_tshark)
        python = prepare_environment()
        # Build-time dependencies only. Web/CLI installs do not need Qt.
        check = subprocess.run([str(python), "-c", "import PyInstaller; from PySide6.QtWebEngineWidgets import QWebEngineView"], check=False)
        if check.returncode:
            print("[Build] Installing PySide6 QtWebEngine and PyInstaller in .venv...", flush=True)
            subprocess.run([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements-desktop.txt")], check=True, cwd=ROOT)
        print("[Build] Compiling desktop executable...", flush=True)
        subprocess.run(build_command(python), check=True, cwd=ROOT)
        dist = ROOT / "dist"
        app_root = dist / "OT Packet Lens"
        exe = app_root / "OT Packet Lens.exe"
        validate_qt_runtime(app_root)
        if args.include_captures:
            shutil.copytree(ROOT / "pcaps", app_root / "pcaps", dirs_exist_ok=True)
        if installed_tshark:
            version = bundle_tshark(installed_tshark, app_root / "Wireshark")
            write_distribution_notices(app_root, version)
            if not args.skip_source_download:
                try:
                    source_archive = prepare_source_archive(version, app_root / "sources", args.source_archive)
                    print(f"[Licenses] Corresponding source: {source_archive}", flush=True)
                    from sign_release import write_checksums
                    write_checksums(app_root)
                    create_portable_zip(app_root, dist / "OT_Packet_Lens_Windows_Portable.zip")
                except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
                    print(f"[Licenses] Could not prepare corresponding source: {exc}", file=sys.stderr)
                    print("[Licenses] Portable app built for LOCAL TESTING; no distributable ZIP was created.", file=sys.stderr)
                    print("[Licenses] Supply --source-archive <matching source> or fix internet and rerun.", file=sys.stderr)
                    return 1
            else:
                print("[Licenses] Source skipped: for local testing only; no shareable ZIP created.")
        else:
            print("[Build] Legacy EXE requires installed Wireshark on recipients.")
        if args.sign_thumbprint:
            from sign_release import main as sign_main
            signing_args = ["--thumbprint", args.sign_thumbprint]
            if args.self_signed_test:
                signing_args += ["--method", "powershell", "--allow-untrusted-self-signed"]
            result = sign_main(signing_args)
            if result:
                # Avoid leaving a stale unsigned ZIP that looks like a completed signed release.
                (dist / "OT_Packet_Lens_Windows_Portable.zip").unlink(missing_ok=True)
                raise RuntimeError("Signing failed. Portable ZIP removed to prevent stale distribution.")
        print(f"[Build ready] {exe}")
        print("Extract the PORTABLE ZIP; double-click OT Packet Lens/OT Packet Lens.exe. No Edge/Python/Wireshark install required.")
        if not args.sign_thumbprint:
            print("EXE unsigned: run sign_release.py, or rebuild with --sign-thumbprint.")
        elif args.self_signed_test:
            print("SELF-SIGNED LOCAL TEST ONLY. Other PCs will not trust this publisher automatically.")
        else:
            print("Trusted signing completed. Test the signed portable ZIP on clean Windows.")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[Build error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
