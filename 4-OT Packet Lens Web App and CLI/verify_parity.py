r"""Independently validate a generated website report against TShark -Y filters.

Usage:
    python verify_parity.py pcaps\mystery\Mystery3.pcap reports\Mystery3.json

This reruns TShark separately for each protocol filter; it can take minutes.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from analyzer.wireshark_reference import find_tshark

FILTERS = ("tcp", "udp", "arp", "icmp", "modbus", "mbtcp", "s7comm", "enip", "dnp3", "dns")


def count_frames(tshark, capture, display_filter):
    command = [tshark, "-n", "-r", str(capture), "-Y", display_filter,
               "-T", "fields", "-e", "frame.number"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace")
    total = 0
    try:
        for line in process.stdout:
            if line.strip():
                total += 1
    finally:
        process.stdout.close()
    err = process.stderr.read()
    code = process.wait()
    if code:
        raise RuntimeError(f"TShark filter {display_filter!r} failed: {err[:400]}")
    return total


def main():
    parser = argparse.ArgumentParser(description="Independent -Y verification of website counts")
    parser.add_argument("capture")
    parser.add_argument("report_json")
    args = parser.parse_args()
    tshark = find_tshark()
    if not tshark:
        parser.error("TShark not installed or not found")
    report = json.loads(Path(args.report_json).read_text(encoding="utf-8"))
    if report.get("analysis_quality", {}).get("mode") != "wireshark_dissected":
        parser.error("Given report does not have verified TShark-mode counts")
    reference = report["wireshark_reference"]["display_filter_packet_counts"]
    different = 0
    for protocol in FILTERS:
        direct = count_frames(tshark, args.capture, protocol)
        website = int(reference.get(protocol, 0))
        status = "MATCH" if direct == website else "DIFFERENT"
        print(f"{protocol:10s} Direct -Y: {direct:>10,}  Website: {website:>10,}  {status}", flush=True)
        different += (direct != website)
    return 0 if not different else 1

if __name__ == "__main__":
    sys.exit(main())
