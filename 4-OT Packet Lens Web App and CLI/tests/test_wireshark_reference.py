"""Unit checks for TShark field-dissection counting. Run `python -m unittest discover -s tests`."""
import unittest
from collections import Counter, defaultdict
from analyzer.wireshark_reference import _summarize_line, TSHARK_FIELDS


class FieldCounterTests(unittest.TestCase):
    def setUp(self):
        self.exclusive = Counter()
        self.filters = Counter()
        self.modbus = Counter()
        self.s7 = Counter()
        self.extra = {"modbus_exception_codes": Counter(), "modbus_exception_source_ips": Counter(),
                      "modbus_exception_frames": 0, "s7_rosctr": Counter(), "enip_commands": Counter(),
                      "dnp3_functions": Counter(), "modbus_unit_ids": Counter(),
                      "outer_transport_packet_counts": Counter(),
                      "s7_job_functions_by_src_ip": defaultdict(Counter),
                      "s7_response_functions_by_src_ip": defaultdict(Counter),
                      "s7_ambiguous_field_frames": 0}

    def feed(self, values):
        line = "\t".join(values + [""] * (len(TSHARK_FIELDS) - len(values))) + "\n"
        _summarize_line(line, self.exclusive, self.filters, self.modbus, self.s7, self.extra)

    def test_cotp_only_is_not_s7comm(self):
        self.feed(['COTP', 'eth:ip:tcp:tpkt:cotp:data', '', '', '1'])
        self.assertEqual(self.filters['tpkt'], 1)
        self.assertEqual(self.filters['cotp'], 1)
        self.assertEqual(self.filters['s7comm'], 0)
        self.assertEqual(self.exclusive['ISO-on-TCP (COTP)'], 1)

    def test_overlap_transport_application(self):
        self.feed(["Modbus/TCP", "eth:ip:tcp:mbtcp:modbus", "1", "", "1"])
        self.assertEqual(self.filters["tcp"], 1)
        self.assertEqual(self.filters["mbtcp"], 1)
        self.assertEqual(self.filters["modbus"], 1)
        self.assertEqual(self.exclusive["Modbus/TCP"], 1)
        self.assertEqual(self.modbus["Read Coils"], 1)

    def test_framing_without_modbus_pdu(self):
        self.feed(["Modbus/TCP", "eth:ip:tcp:mbtcp", "", "", "1"])
        self.assertEqual(self.exclusive["Modbus/TCP framing only"], 1)
        self.assertEqual(self.filters["modbus"], 0)

    def test_multiple_pdu_fields_one_frame(self):
        self.feed(["Modbus", "eth:ip:tcp:mbtcp:modbus", "1,1,3", "", "2"])
        self.assertEqual(self.exclusive["Modbus/TCP"], 1)
        self.assertEqual(sum(self.modbus.values()), 3)

    def test_tcp_port_without_decoded_protocol(self):
        self.feed(["TCP", "eth:ip:tcp", "", "", "3"])
        self.assertEqual(self.filters["modbus"], 0)
        self.assertEqual(self.exclusive["TCP"], 1)

    def test_modbus_exception_source_and_code(self):
        self.feed(["Modbus", "eth:ip:tcp:mbtcp:modbus", "0x81", "", "5",
                   "192.0.2.20", "2", "", "", "", "42"])
        self.assertEqual(self.modbus["Exception response to Read Coils (0x81)"], 1)
        self.assertEqual(self.extra["modbus_exception_codes"]["Illegal Data Address"], 1)
        self.assertEqual(self.extra["modbus_exception_source_ips"]["192.0.2.20"], 1)
        self.assertEqual(self.extra["modbus_exception_frames"], 1)
        self.assertEqual(self.extra["modbus_unit_ids"][42], 1)

    def test_s7_rosctr_and_functions(self):
        self.feed(["S7", "eth:ip:tcp:tpkt:cotp:s7comm", "", "4,5", "8", "192.0.2.10", "", "1,3"])
        self.assertEqual(self.filters["s7comm"], 1)
        self.assertEqual(self.s7["Read Var"], 1)
        self.assertEqual(self.s7["Write Var"], 1)
        self.assertEqual(self.extra["s7_rosctr"]["Job (Request)"], 1)
        self.assertEqual(self.extra["s7_rosctr"]["Ack-Data (Response)"], 1)

    def test_dnp_and_enip(self):
        self.feed(["EthernetIP", "eth:ip:tcp:enip", "", "", "9", "192.0.2.11", "", "", "99", "1,2"])
        self.assertEqual(self.extra["enip_commands"]["ListIdentity"], 1)
        self.assertEqual(self.extra["dnp3_functions"]["Function 0x01"], 1)
        self.assertEqual(self.extra["dnp3_functions"]["Function 0x02"], 1)

    def test_udp_inside_icmp_is_protocol_presence_not_outer_udp(self):
        self.feed(["ICMP", "eth:ethertype:ip:icmp:ip:udp", "", "", "14"])
        self.assertEqual(self.filters["udp"], 1)
        self.assertEqual(self.filters["icmp"], 1)
        self.assertEqual(self.extra["outer_transport_packet_counts"]["icmp"], 1)
        self.assertEqual(self.extra["outer_transport_packet_counts"]["udp"], 0)

    def test_s7_per_source_only_decoded_job_requests(self):
        self.feed(["S7", "eth:ip:tcp:s7comm", "", "4", "21", "10.10.10.20", "", "1"])
        self.feed(["S7", "eth:ip:tcp:s7comm", "", "4", "22", "10.10.10.10", "", "3"])
        self.feed(["S7", "eth:ip:tcp:s7comm", "", "5", "23", "10.10.10.30", "", "1"])
        self.assertEqual(self.extra["s7_job_functions_by_src_ip"]["10.10.10.20"]["Read Var"], 1)
        self.assertEqual(self.extra["s7_response_functions_by_src_ip"]["10.10.10.10"]["Read Var"], 1)
        self.assertEqual(self.extra["s7_job_functions_by_src_ip"]["10.10.10.30"]["Write Var"], 1)
        self.assertNotIn("10.10.10.10", self.extra["s7_job_functions_by_src_ip"])

    def test_exclusive_classes_total_frames(self):
        for i in range(12):
            self.feed(["", "eth:ip:tcp" if i % 2 else "eth:arp", "", "", str(i + 1)])
        self.assertEqual(sum(self.exclusive.values()), 12)


if __name__ == "__main__":
    unittest.main()
