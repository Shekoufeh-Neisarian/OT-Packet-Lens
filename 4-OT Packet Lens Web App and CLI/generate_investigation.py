"""Summarize freshly regenerated, strict TShark-backed mystery reports only."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def generate():
    lines = ["# Mystery PCAP Investigation — verified-count provenance", "",
             "Generated only from this revision's TShark-backed JSON. Protocol frames and decoded field occurrences are evidence; device roles and selected security findings remain hypotheses.",
             "", "**No claim of proven attacks, physical-device identities, or successful PLC changes.**", ""]
    for n in (1, 2, 3):
        path = ROOT / "reports" / f"Mystery{n}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Missing fresh report {path.name}; first run python regenerate_mystery_reports.py")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("analysis_quality", {}).get("mode") != "wireshark_dissected":
            raise RuntimeError(f"{path.name}: not TShark-verified; refusing consolidated report")
        sm = data["summary"]
        ref = data["wireshark_reference"]
        if sm["packet_count"] != ref["packet_count"]:
            raise RuntimeError(f"{path.name}: frame count mismatch")
        lines += [f"## Mystery{n}.pcap", "",
                  f"- Captured frames: **{sm['packet_count']:,}**",
                  f"- TShark version: `{ref['version']}`",
                  f"- Capture interval (UTC): {sm['start_time']} to {sm['end_time']}",
                  f"- Observed IP entries: **{sm['device_count']}** (not physical devices)", "",
                  "### TShark frame.protocols presence (overlapping frame counts)", "",
                  "| Protocol | Frames |", "|---|---:|"]
        for protocol, count in sorted(ref["display_filter_packet_counts"].items()):
            lines.append(f"| {protocol} | {count:,} |")
        lines += ["", "### Decoded industrial field occurrences", ""]
        for name, fc in ref["function_code_occurrences"].items():
            if fc:
                lines += [f"**{name}:** " + "; ".join(f"{k}: {v:,}" for k,v in fc.items()), ""]
        decoded = ref.get("decoded_insights", {})
        exceptions = decoded.get("modbus_exception_codes", {})
        if exceptions:
            lines += ["**TShark Modbus exception codes:** " + "; ".join(f"{k}: {v:,}" for k,v in exceptions.items()), ""]
        lines += ["### Asset and alert interpretation", "",
                  "- Candidate OT assets, MAC/OUI vendor claims, and network roles in the individual report are heuristic.",
                  "- A destination TCP port does not prove a listening process. Source-IP Modbus exception-code counts require context and a valid request-rate denominator.",
                  "- Short SYN-bearing flow groups are an investigation lead, not proof of scanning; check distinct destination ports before claiming a port scan.",
                  "- Device-level S7 read/write job counts use TShark-decoded requests by source IP; raw TCP payload counts can include retransmissions.",
                  "- Outer transport statistics take the first decoded L4/ARP protocol. Wireshark protocol-presence filters such as udp may include an inner UDP header inside ICMP.", "",
                  f"Full report: `Mystery{n}.json`, `Mystery{n}.md`, `Mystery{n}.html`.", ""]
    out = ROOT / 'reports' / 'Mystery_PCAP_Investigation.md'
    out.write_text("\n".join(lines), encoding="utf-8")
    print("Consolidated report:", out)


if __name__ == "__main__":
    generate()
