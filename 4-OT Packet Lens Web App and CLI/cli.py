"""
Command-Line Interface (CLI) for Industrial Network PCAP Analyzer.
Provides terminal analysis, asset profiling, protocol insights, and multi-format exports.
"""

import argparse
import sys
import os
import time
from datetime import datetime

# Configure safe UTF-8 output on Windows terminal
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import PcapAnalyzer, ReportExporter

def fmt_ts(ts) -> str:
    """Human-readable timestamp for console output."""
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(ts)).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return str(ts)

def print_banner():
    banner = r"""
  ___ ____ ____    _                _                     
 |_ _/ ___/ ___|  / \   _ __   __ _| |_   _ _______ _ __ 
  | | |   \___ \ / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
  | | |___ ___) / ___ \| | | | (_| | | |_| |/ /  __/ |   
 |___\____|____/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                                      |___/               
    ICS / OT Network Traffic Analyzer & Asset Profiler
    """
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Analyze Industrial Control Systems (ICS/OT) PCAP/PCAPNG network captures.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("pcap_file", help="Path to PCAP or PCAPNG capture file to analyze")
    parser.add_argument("--export", help="Comma-separated export formats (json,csv,html,md,all)", default=None)
    parser.add_argument("--output-dir", help="Directory to save exported reports (default: reports/)", default="reports")
    parser.add_argument("--silent", action="store_true", help="Suppress verbose console tables")
    parser.add_argument("--allow-estimates", action="store_true", help="Allow approximate fallback if TShark is unavailable or fails (not Wireshark comparable)")

    args = parser.parse_args()

    # 1. PCAP Input Validation
    if not os.path.exists(args.pcap_file):
        print(f"\n[ERROR] File not found: '{args.pcap_file}'", file=sys.stderr)
        print("Please verify the path and make sure the file exists.", file=sys.stderr)
        sys.exit(1)

    if not args.pcap_file.lower().endswith(('.pcap', '.pcapng', '.cap')):
        print(f"\n[WARNING] File extension does not end in .pcap, .pcapng, or .cap: '{args.pcap_file}'")
        print("Attempting to parse file structure anyway...")

    if os.path.getsize(args.pcap_file) == 0:
        print(f"\n[ERROR] The capture file is empty (0 bytes): '{args.pcap_file}'", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting analysis of '{os.path.basename(args.pcap_file)}' ({os.path.getsize(args.pcap_file)/(1024*1024):.2f} MB)...")
    
    t_start = time.time()
    try:
        analyzer = PcapAnalyzer(args.pcap_file, require_tshark=not args.allow_estimates)
        result = analyzer.analyze()
    except Exception as e:
        print(f"\n[ERROR] Analysis failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)

    elapsed = time.time() - t_start
    summary = result["summary"]

    if not args.silent:
        # Display Capture Summary
        print("\n" + "="*80)
        print(f"  CAPTURE SUMMARY: {summary['filename']}")
        print("="*80)
        print(f"  File Size:         {summary['file_size_mb']} MB ({summary['file_size_bytes']:,} bytes)")
        print(f"  Total Packets:     {summary['packet_count']:,}")
        print(f"  Total Transferred: {summary['total_transferred_mb']} MB ({summary['total_bytes']:,} bytes)")
        print(f"  Capture Start:     {summary['start_time']}")
        print(f"  Capture End:       {summary['end_time']}")
        print(f"  Duration:          {summary['duration_human']} ({summary['duration_seconds']}s)")
        print(f"  Discovered Assets: {summary['device_count']} total ({summary['ot_asset_count']} OT assets)")
        print(f"  Analysis Speed:    {summary['processing_rate_pkts_sec']:,.0f} pkts/s (elapsed {elapsed:.2f}s)")
        print("="*80)

        # Operational & Security Findings
        anomalies = result.get("anomalies", [])
        if anomalies:
            print("\n" + "!"*80)
            print("  OPERATIONAL & SECURITY ALERTS")
            print("!"*80)
            for a in anomalies:
                print(f"  [{a['severity']}] {a['type']} (Source: {a['source_ip']})")
                print(f"      Evidence: {a['evidence']}")
            print("!"*80)

        # Detected Protocols
        print("\n" + "-"*80)
        print("  DETECTED PROTOCOLS (one classification per packet)")
        print("-"*80)
        for proto, count in result["detected_protocols"].items():
            pct = (count / max(1, summary["packet_count"])) * 100
            print(f"  - {proto:<25} {count:>10,} packets ({pct:>5.1f}%)")

        # Transport / Link Layer Totals
        transport = result.get("transport_summary", {})
        if transport:
            print("\n  TRANSPORT / LINK LAYER TOTALS")
            print("-"*80)
            for proto, count in transport.items():
                print(f"  - {proto:<25} {count:>10,} packets")

        # Protocol-Specific Insights (Bonus)
        insights = result.get("protocol_insights", {})
        has_insights = any(
            v.get("function_codes") or v.get("operations") or v.get("device_identifiers") or v.get("service_codes")
            for v in insights.values()
        )
        if has_insights:
            print("\n" + "-"*80)
            print("  PROTOCOL-SPECIFIC INSIGHTS (BONUS)")
            print("-"*80)
            for proto, data in insights.items():
                fcs = data.get("function_codes")
                ops = data.get("operations")
                svcs = data.get("service_codes")
                asdus = data.get("asdu_types")
                dev_ids = data.get("device_identifiers")
                uids = data.get("unit_ids")
                excs = data.get("exception_codes")

                if fcs or ops or svcs or asdus or dev_ids or uids or excs:
                    print(f"  * {proto}:")
                    if fcs:
                        print(f"    Function Codes:     {', '.join([f'{k} ({v:,})' for k, v in fcs.items()])}")
                    if ops:
                        print(f"    Operations / PDUs:  {', '.join([f'{k} ({v:,})' for k, v in ops.items()])}")
                    if svcs:
                        print(f"    CIP Services:       {', '.join([f'{k} ({v:,})' for k, v in svcs.items()])}")
                    if asdus:
                        print(f"    ASDU Types:         {', '.join([f'{k} ({v:,})' for k, v in asdus.items()])}")
                    if uids:
                        print(f"    Unit IDs:           {uids}")
                    if dev_ids:
                        print(f"    Device Info / Name: {', '.join(dev_ids)}")
                    if excs:
                        print(f"    Exceptions / Errors:{', '.join([f'{k} ({v:,})' for k, v in excs.items()])}")

        # Device Inventory
        print("\n" + "="*80)
        print("  DEVICE INVENTORY & ASSET PROFILES")
        print("="*80)
        fmt_hdr = "  {:<16} {:<18} {:<24} {:<22} {:<10} {:<10}"
        print(fmt_hdr.format("IP Address", "MAC Address", "Vendor", "Suspected Role", "Confidence", "Packets"))
        print("  " + "-"*78)
        for ip, dev in sorted(result["devices"].items()):
            print(fmt_hdr.format(
                ip,
                dev["mac_address"],
                dev["mac_vendor"][:23],
                dev["suspected_role"][:21],
                dev["confidence"],
                f"{dev['total_packets']:,}"
            ))
            for ev in dev["evidence"]:
                print(f"      - {ev}")
            print(f"      - First observed: {fmt_ts(dev.get('first_seen'))} | Last observed: {fmt_ts(dev.get('last_seen'))}")
            print()

        # Communication Matrix / Top Flows
        print("="*80)
        print("  TOP COMMUNICATIONS & SESSIONS")
        print("="*80)
        fmt_flow = "  {:<21} -> {:<21} {:<15} {:<10} {:<10}"
        print(fmt_flow.format("Client (Source)", "Server (Target)", "Protocol", "Packets", "Bytes"))
        print("  " + "-"*78)
        for flow in result["conversations"][:15]:
            client = f"{flow['client_ip']}:{flow['source_port']}"
            server = f"{flow['server_ip']}:{flow['destination_port']}"
            print(fmt_flow.format(
                client[:20],
                server[:20],
                flow["protocol"][:14],
                f"{flow['packet_count']:,}",
                f"{flow['total_bytes']:,}"
            ))
        print("="*80)

    # 6. Exportable Reports
    if args.export:
        os.makedirs(args.output_dir, exist_ok=True)
        base_name = os.path.splitext(summary["filename"])[0]
        formats = [f.strip().lower() for f in args.export.split(",")]
        if "all" in formats:
            formats = ["json", "csv", "html", "md"]

        print(f"\n[*] Exporting reports to directory: '{args.output_dir}'")
        if "json" in formats:
            json_file = os.path.join(args.output_dir, f"{base_name}_report.json")
            with open(json_file, "w", encoding="utf-8") as f:
                f.write(ReportExporter.to_json(result))
            print(f"  [+] JSON report saved:      {json_file}")

        if "csv" in formats:
            csv_dev_file = os.path.join(args.output_dir, f"{base_name}_devices.csv")
            with open(csv_dev_file, "w", newline="", encoding="utf-8") as f:
                f.write(ReportExporter.to_csv_devices(result))
            csv_flow_file = os.path.join(args.output_dir, f"{base_name}_flows.csv")
            with open(csv_flow_file, "w", newline="", encoding="utf-8") as f:
                f.write(ReportExporter.to_csv_conversations(result))
            print(f"  [+] CSV devices report saved: {csv_dev_file}")
            print(f"  [+] CSV flows report saved:   {csv_flow_file}")

        if "html" in formats:
            html_file = os.path.join(args.output_dir, f"{base_name}_report.html")
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(ReportExporter.to_html(result))
            print(f"  [+] HTML report saved:      {html_file}")

        if "md" in formats or "markdown" in formats:
            md_file = os.path.join(args.output_dir, f"{base_name}_report.md")
            with open(md_file, "w", encoding="utf-8") as f:
                f.write(ReportExporter.to_markdown(result))
            print(f"  [+] Markdown report saved:  {md_file}")

    print("\n[SUCCESS] Analysis completed successfully.\n")

if __name__ == "__main__":
    main()
