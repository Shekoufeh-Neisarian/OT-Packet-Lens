"""Offline tests for honest two-capture validation reporting (no TShark required)."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from validate_development_captures import compare_counts, as_markdown, coverage_status


class DevelopmentValidationTests(unittest.TestCase):
    def test_nonzero_differences_recorded(self):
        rows = compare_counts({'tcp': 12, 'modbus': 4}, {'tcp': 12, 'modbus': 3}, ('tcp','modbus'))
        self.assertEqual(rows[0]['status'], 'MATCH')
        self.assertEqual(rows[1]['difference'], 1)
        self.assertEqual(rows[1]['status'], 'DIFFERENCE')

    def test_missing_counts_are_not_silently_dropped(self):
        rows = compare_counts({}, {'s7comm': 1}, ('s7comm',))
        self.assertEqual(rows[0]['app_frames'], 0)
        self.assertEqual(rows[0]['independent_frames'], 1)
        self.assertEqual(rows[0]['status'], 'DIFFERENCE')

    def test_s7_cotp_without_s7comm_is_limited_not_validated(self):
        result = coverage_status('s7_S7-1200-Uploading-OB1-TIAV12.pcap', {'cotp': 133, 'tpkt': 133, 's7comm': 0})
        self.assertEqual(result['status'], 'LIMITED_TO_ISO_ON_TCP')
        self.assertIn('NOT decoded', result['notes'])

    def test_mystery3_positive_s7comm_control(self):
        result = coverage_status('Mystery3.pcap', {'s7comm': 47464})
        self.assertEqual(result['status'], 'POSITIVE_PROTOCOL_DETECTED')
        negative = coverage_status('Mystery3.pcap', {'s7comm': 0})
        self.assertEqual(negative['status'], 'MISSING_EXPECTED_PROTOCOL')

    def test_report_requires_manual_signoff(self):
        cap = {'filename':'synthetic.pcap','sha256':'hash','app_frames':4,
               'independent_frames':4,'frame_status':'MATCH','analysis_mode':'wireshark_dissected',
               'filters': compare_counts({'tcp': 4},{'tcp': 4}, ('tcp',)),
               'fields': [], 'differences': []}
        report = as_markdown([cap], 'today', 'Wireshark test')
        self.assertIn('Manual Wireshark GUI / asset review — pending', report)
        self.assertIn('Inferences:', report)
        self.assertIn('NOT independently confirmed', report)

if __name__ == '__main__':
    unittest.main()
