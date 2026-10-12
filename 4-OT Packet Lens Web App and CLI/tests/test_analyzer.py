import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from analyzer import PcapAnalyzer, ReportExporter

def test_samples():
    print("================ Testing Modbus Sample ================")
    a1 = PcapAnalyzer("pcaps/samples/ModbusTCP_ModbusTCP.pcap")
    r1 = a1.analyze()
    print("Summary:", json.dumps(r1["summary"], indent=2))
    print("Detected Protocols:", r1["detected_protocols"])
    print("Modbus Insights:", r1["protocol_insights"]["Modbus/TCP"])
    print("Devices:")
    for ip, dev in r1["devices"].items():
        print(f"  {ip}: role={dev['suspected_role']}, conf={dev['confidence']}, vendor={dev['mac_vendor']}")
        for ev in dev['evidence']:
            print(f"    - {ev}")

    print("\n================ Testing EtherNet/IP Sample ================")
    a2 = PcapAnalyzer("pcaps/samples/EthernetIP_EthernetIP-CIP.pcap")
    r2 = a2.analyze()
    print("Summary:", json.dumps(r2["summary"], indent=2))
    print("Detected Protocols:", r2["detected_protocols"])
    print("CIP Insights:", r2["protocol_insights"]["EtherNet/IP"])

    print("\n================ Testing Mystery3.pcap ================")
    a3 = PcapAnalyzer("pcaps/mystery/Mystery3.pcap")
    r3 = a3.analyze()
    print("Summary:", json.dumps(r3["summary"], indent=2))
    print("Detected Protocols:", r3["detected_protocols"])
    print("S7 Insights:", r3["protocol_insights"]["S7comm"])
    print("Devices:")
    for ip, dev in r3["devices"].items():
        print(f"  {ip}: role={dev['suspected_role']}, conf={dev['confidence']}, vendor={dev['mac_vendor']}")
    print("Anomalies detected in Mystery3:")
    for anom in r3["anomalies"]:
        print(f"  [{anom['severity']}] {anom['type']}: {anom['evidence']}")

if __name__ == "__main__":
    test_samples()
