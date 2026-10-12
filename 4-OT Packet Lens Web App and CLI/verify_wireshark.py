"""Run the installed Wireshark/TShark dissector and save reproducible counts.

Usage: python verify_wireshark.py pcaps\\mystery\\Mystery1.pcap
"""
import argparse
import json
import os
import sys

from analyzer.wireshark_reference import analyze_with_tshark, find_tshark


def main():
    parser = argparse.ArgumentParser(description="Wireshark-level PCAP count verification")
    parser.add_argument("capture", help="Full path to .pcap or .pcapng capture")
    parser.add_argument("--output", help="Write JSON reference results to this file")
    args = parser.parse_args()
    if not os.path.isfile(args.capture):
        parser.error("capture file not found: " + args.capture)
    exe = find_tshark()
    if not exe:
        parser.error("tshark not detected. Install Wireshark/TShark and retry.")
    print("Using:", exe, flush=True)
    result = analyze_with_tshark(args.capture)
    print("TShark version:", result["version"])
    print("Frames:", result["packet_count"])
    print("\nWireshark display-filter frame counts (overlap allowed):")
    for k, n in result["display_filter_packet_counts"].items():
        print(f"  {k:20} {n:>12,}")
    print("\nFunction-code occurrences (NOT frames):")
    for proto, counts in result["function_code_occurrences"].items():
        print(f"  {proto}")
        for k, n in counts.items():
            print(f"    {k:50} {n:>12,}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print("\nSaved:", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
