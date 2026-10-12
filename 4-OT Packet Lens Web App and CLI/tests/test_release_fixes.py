"""Regression checks for HTML export and DNP3 IIN flags, no PCAP or TShark needed."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_module(rel_path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = load_module("analyzer/report_exporter.py", "release_report_exporter")
dnp3 = load_module("analyzer/protocols/dnp3.py", "release_dnp3")


class ReleaseRegressionTests(unittest.TestCase):
    def test_html_export_works_and_escapes_untrusted_strings(self):
        source = {
            "summary": {
                "filename": "<script>alert(1)</script>.pcap",
                "packet_count": 5,
                "total_transferred_mb": 0.01,
                "device_count": 1,
                "ot_asset_count": 0,
                "start_time": "2026-01-01",
                "end_time": "2026-01-01",
                "duration_human": "2 seconds",
            },
            "detected_protocols": {"TCP": 5},
            "transport_summary": {"tcp": 5},
            "devices": {"192.0.2.1": {"mac_vendor": "<img src=x onerror=alert(1)>",
                "suspected_role": "Unknown", "confidence": "Low",
                "evidence": ["Unexpected <value>"]}},
            "conversations": [],
            "protocol_insights": {},
            "anomalies": [],
        }
        document = exporter.ReportExporter.to_html(source)
        self.assertIn("<!DOCTYPE html>", document)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", document)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn("&lt;img", document)

    def test_html_provenance_is_escaped(self):
        report = {
            "summary": {"filename": "trace.pcap", "packet_count": 1, "total_transferred_mb": 1.0,
                        "device_count": 0, "ot_asset_count": 0},
            "detected_protocols": {}, "transport_summary": {}, "devices": {},
            "conversations": [], "protocol_insights": {}, "anomalies": [],
            "analysis_quality": {"mode": "<svg onload=alert(1)>"},
            "wireshark_reference": {"version": "<img src=x>"}
        }
        rendered = exporter.ReportExporter.to_html(report)
        self.assertIn("&lt;svg", rendered)
        self.assertNotIn("<svg onload", rendered)
        self.assertNotIn("<img src=x>", rendered)

    def test_csv_escapes_formula_like_capture_text(self):
        report = {"devices": {"192.0.2.1": {
            "ip_address": "192.0.2.1", "mac_vendor": "=HYPERLINK(\"https://bad.test\")",
            "evidence": ["+cmd|'/C calc'!A0"], "protocols_used": ["TCP"]
        }}, "conversations": []}
        document = exporter.ReportExporter.to_csv_devices(report)
        self.assertIn("'=HYPERLINK", document)
        self.assertIn("'+cmd", document)

    def test_dnp3_all_stations_flag_present(self):
        pkt = bytearray(15)
        pkt[0:2] = b"\x05\x64"
        pkt[2] = 5
        pkt[3] = 0x00
        pkt[12] = 129  # application response
        pkt[13] = 0x11  # All Stations plus Need Time
        info = dnp3.parse_dnp3(bytes(pkt), 20000, 21000)
        self.assertTrue(info["is_response"])
        self.assertIn("All Stations", info["iin_flags"])
        self.assertIn("Need Time", info["iin_flags"])

    def test_dnp3_non_response_has_no_iin(self):
        pkt = bytearray(15)
        pkt[0:2] = b"\x05\x64"
        pkt[2] = 5
        pkt[12] = 1  # read request
        pkt[13] = 0x01
        info = dnp3.parse_dnp3(bytes(pkt), 20000, 21000)
        self.assertEqual(info["iin_flags"], [])


if __name__ == "__main__":
    unittest.main()
