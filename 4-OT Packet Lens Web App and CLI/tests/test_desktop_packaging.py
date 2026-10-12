"""Qt desktop source/portable packaging checks, runnable without PySide6 installed."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import desktop
import build_desktop


class DesktopQtTests(unittest.TestCase):
    def test_distribution_dir_source(self):
        self.assertEqual(desktop.distribution_dir(), ROOT)

    def test_user_data_is_per_user(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                self.assertEqual(desktop.user_data_dir(), Path(folder) / "OT Packet Lens")

    def test_configure_paths_before_web_app_import(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                path = desktop.configure_paths()
                self.assertTrue(path.is_dir())
                self.assertEqual(os.environ["OT_PACKET_LENS_DATA_DIR"], str(path))
                self.assertEqual(os.environ["OT_PACKET_LENS_SAMPLE_ROOT"], str(ROOT))

    def test_bundled_tshark_preferred(self):
        with tempfile.TemporaryDirectory() as folder:
            shipped = Path(folder) / "Wireshark" / "tshark.exe"
            shipped.parent.mkdir()
            shipped.write_bytes(b"test")
            with mock.patch.object(desktop, 'distribution_dir', return_value=Path(folder)):
                self.assertEqual(desktop.find_tshark(), str(shipped))

    def test_builder_bundles_native_qt_and_web_assets(self):
        args = build_desktop.build_command(Path("python.exe"))
        self.assertIn("--onedir", args)
        self.assertNotIn("--onefile", args)
        self.assertIn("--windowed", args)
        self.assertIn("PySide6.QtWebEngineWidgets", args)
        self.assertTrue(any("web/static" in v for v in args))
        self.assertTrue(any("web/templates" in v for v in args))
        self.assertFalse(any("pcaps" in v for v in args))
        self.assertTrue((ROOT / "requirements-desktop.txt").is_file())

    def test_qt_runtime_check(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / "OT Packet Lens.exe").write_bytes(b"exe")
            with self.assertRaisesRegex(RuntimeError, "QtWebEngineProcess"):
                build_desktop.validate_qt_runtime(p)
            (p / "_internal" / "PySide6").mkdir(parents=True)
            (p / "_internal" / "PySide6" / "QtWebEngineProcess.exe").write_bytes(b"proc")
            with self.assertRaisesRegex(RuntimeError, "resources missing"):
                build_desktop.validate_qt_runtime(p)
            (p / "_internal" / "qtwebengine_resources.pak").write_bytes(b"data")
            build_desktop.validate_qt_runtime(p)

    def test_guard_linux_build(self):
        if os.name != "nt":
            self.assertEqual(build_desktop.main([]), 2)

    def test_guard_linux_desktop(self):
        if sys.platform != "win32":
            self.assertEqual(desktop.launch_desktop(), 2)


if __name__ == "__main__":
    unittest.main()
