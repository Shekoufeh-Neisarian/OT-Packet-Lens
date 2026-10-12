"""Local-web safety regression checks without requiring dpkt or TShark."""
import importlib.util
import pathlib
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_server_helpers():
    # This test checks pure route/file handling, without loading the analyzer.
    old = sys.modules.get("analyzer")
    stub = types.ModuleType("analyzer")
    stub.PcapAnalyzer = object
    stub.ReportExporter = object
    try:
        sys.modules["analyzer"] = stub
        spec = importlib.util.spec_from_file_location("release_server_test", ROOT / "web" / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old is None:
            sys.modules.pop("analyzer", None)
        else:
            sys.modules["analyzer"] = old


server = load_server_helpers()


class WebsitePathSafetyTests(unittest.TestCase):
    def test_sample_capture_selectable(self):
        sample = ROOT / "pcaps" / "samples" / "ModbusTCP_ModbusTCP.pcap"
        self.assertTrue(server.is_sample_capture_path(str(sample)))

    def test_arbitrary_file_rejected_and_upload_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            local_file = pathlib.Path(td) / "external.pcap"
            local_file.write_bytes(b"pcap test")
            self.assertFalse(server.is_sample_capture_path(str(local_file)))
            self.assertFalse(server.is_sample_capture_path(str(local_file.with_suffix('.txt'))))

    def test_suspicious_filename_is_sanitized(self):
        for name in ('..\\secret\\weird\r\nname.pcap', '../../x"; evil.pcap'):
            safe = server.safe_capture_name(name)
            self.assertTrue(safe.endswith(".pcap"))
            self.assertNotIn('\r', safe)
            self.assertNotIn('\n', safe)
            self.assertNotIn('"', safe)
            self.assertNotIn('/', safe)
            self.assertNotIn('\\', safe)

    def test_web_upload_size_bound(self):
        self.assertEqual(server.MAX_UPLOAD_BYTES, 512 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
