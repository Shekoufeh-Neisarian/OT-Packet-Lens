"""
Multi-Format Report Exporter for ICS Network Analysis.
Generates JSON, CSV, Markdown, and Standalone HTML Reports.
"""

import json
import csv
import io
import html
import os
from datetime import datetime, timezone
from typing import Dict, Any, List


def format_ts(ts) -> str:
    """Human-readable timestamp for report output; handles missing values."""
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return str(ts)


def _csv_safe(value):
    """Prevent spreadsheet formula execution from capture-derived text."""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


class ReportExporter:
    @staticmethod
    def to_json(analysis_result: Dict[str, Any], indent: int = 2) -> str:
        """Export full analysis result as JSON."""
        return json.dumps(analysis_result, indent=indent, default=str)

    @staticmethod
    def to_csv_devices(analysis_result: Dict[str, Any]) -> str:
        """Export device inventory as CSV formatted string."""
        output = io.StringIO()
        raw_writer = csv.writer(output)
        def write_row(values):
            raw_writer.writerow([_csv_safe(v) for v in values])
        
        # Headers
        write_row([
            "IP Address", "MAC Address", "MAC Vendor", "Hostname", 
            "Suspected Role", "Confidence", "Is OT Asset", 
            "Packets Sent", "Packets Received", "Total Packets", 
            "Bytes Sent", "Bytes Received", "Total Bytes", 
            "First Seen", "Last Seen", "Protocols", "Supporting Evidence"
        ])
        
        devices = analysis_result.get("devices", {})
        for ip, dev in devices.items():
            evidence_str = " | ".join(dev.get("evidence", []))
            protocols_str = ", ".join(dev.get("protocols_used", []))
            write_row([
                dev.get("ip_address"),
                dev.get("mac_address"),
                dev.get("mac_vendor"),
                dev.get("hostname") or "",
                dev.get("suspected_role"),
                dev.get("confidence"),
                "YES" if dev.get("is_ot_asset") else "NO",
                dev.get("packets_sent", 0),
                dev.get("packets_received", 0),
                dev.get("total_packets", 0),
                dev.get("bytes_sent", 0),
                dev.get("bytes_received", 0),
                dev.get("total_bytes", 0),
                dev.get("first_seen"),
                dev.get("last_seen"),
                protocols_str,
                evidence_str
            ])
            
        return output.getvalue()

    @staticmethod
    def to_csv_conversations(analysis_result: Dict[str, Any]) -> str:
        """Export communication flows as CSV formatted string."""
        output = io.StringIO()
        raw_writer = csv.writer(output)
        def write_row(values):
            raw_writer.writerow([_csv_safe(v) for v in values])
        
        write_row([
            "Source IP", "Source Port", "Destination IP", "Destination Port", 
            "Protocol", "Packet Count", "Total Bytes", 
            "First Seen", "Last Seen",
            "Client IP", "Server IP", "Likely Requester", "Likely Responder"
        ])
        
        flows = analysis_result.get("conversations", [])
        for f in flows:
            write_row([
                f.get("source_ip"),
                f.get("source_port"),
                f.get("destination_ip"),
                f.get("destination_port"),
                f.get("protocol"),
                f.get("packet_count"),
                f.get("total_bytes"),
                format_ts(f.get("first_seen")),
                format_ts(f.get("last_seen")),
                f.get("client_ip"),
                f.get("server_ip"),
                f.get("likely_requester"),
                f.get("likely_responder")
            ])
            
        return output.getvalue()

    @staticmethod
    def to_markdown(analysis_result: Dict[str, Any]) -> str:
        """Generates comprehensive Markdown report."""
        summary = analysis_result.get("summary", {})
        protocols = analysis_result.get("detected_protocols", {})
        transport = analysis_result.get("transport_summary", {})
        devices = analysis_result.get("devices", {})
        flows = analysis_result.get("conversations", [])[:25]
        insights = analysis_result.get("protocol_insights", {})
        anomalies = analysis_result.get("anomalies", [])

        md = []
        md.append(f"# Industrial Network Capture Analysis Report\n")
        md.append(f"**Capture File:** `{summary.get('filename')}`  \n")
        md.append(f"**Capture Start (UTC):** {summary.get('start_time')}  \n")
        md.append(f"**Capture End (UTC):** {summary.get('end_time')}  \n")
        md.append(f"**Capture Duration:** {summary.get('duration_human')} ({summary.get('duration_seconds')}s)  \n")
        md.append(f"**Total Packets:** {summary.get('packet_count', 0):,}  \n")
        md.append(f"**Captured frame data:** {summary.get('total_transferred_mb', 0)} MiB ({summary.get('total_bytes', 0):,} bytes)  \n")
        md.append(f"**Total Devices Identified:** {summary.get('device_count', 0)} (OT Assets: {summary.get('ot_asset_count', 0)})  \n")
        md.append(f"**Capture average packet rate:** {summary.get('capture_average_pkts_sec', 0)} packets/s (total packets / capture duration)  \n")
        md.append(f"**Analysis processing speed:** {summary.get('processing_rate_pkts_sec', 0):,.0f} packets/s in {summary.get('analysis_time_seconds')}s (software execution speed)  \n\n")
        quality = analysis_result.get("analysis_quality", {})
        reference = analysis_result.get("wireshark_reference") or {}
        md.append(f"**Counting source:** {quality.get('mode', 'unverified')} | {reference.get('version', 'TShark unavailable')}  \n")
        md.append(f"**Validation:** {quality.get('message', 'not established')}  \n\n")

        md.append("> **Observed facts:** Captured frame records, IP addresses, ports, timestamps and lengths; ARP MAC mappings are *claims visible in the capture*, not authenticated identity.\n")
        md.append("> **Derived information:** TShark-dissected protocol/field counts, rates, OUI vendor lookups and correlations. A decoded occurrence is not necessarily a unique transaction.\n")
        md.append("> **Inferences:** Suspected device roles, scan/attack hypotheses and risk severities remain unverified and require manual context.\n")
        md.append("> Counting: exclusive chart categories differ from overlapping Wireshark display-filter frame counts.\n\n")

        # Security & Operational Alerts
        if anomalies:
            md.append("## Operational & Security Findings\n")
            for a in anomalies:
                md.append(f"> **[{a.get('severity')}] {a.get('type')}**  \n")
                md.append(f"> Target / Source: `{a.get('source_ip')}`  \n")
                md.append(f"> {a.get('evidence')}\n\n")

        # Protocols Overview
        md.append("## Detected Protocols\n")
        md.append("Each packet is classified into exactly one protocol, so shares add up to at most 100%.\n")
        md.append("| Protocol | Packet Count | Share of Packets |\n")
        md.append("| :--- | :--- | :--- |\n")
        total_p = summary.get('packet_count', 1)
        for p, count in protocols.items():
            pct = (count / total_p) * 100
            md.append(f"| **{p}** | {count:,} | {pct:.1f}% |\n")
        md.append("\n")

        if transport:
            md.append("### Outermost Transport / Link Layer Totals\n")
            md.append("First decoded TCP/UDP/ICMP/ARP per frame; unlike an overlapping Wireshark display filter, this excludes inner UDP carried in an ICMP error:\n\n")
            md.append("| Layer | Packet Count |\n")
            md.append("| :--- | :--- |\n")
            for p, count in transport.items():
                md.append(f"| {p} | {count:,} |\n")
            md.append("\n")

        # Device Inventory
        md.append("## Device Inventory & Asset Classification\n")
        md.append("| IP Address | MAC Address | Vendor | Role | Confidence | Total Packets | Volume |\n")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for ip, dev in sorted(devices.items()):
            mb = dev.get('total_bytes', 0) / (1024 * 1024)
            md.append(f"| `{ip}` | `{dev.get('mac_address')}` | {dev.get('mac_vendor')} | **{dev.get('suspected_role')}** | {dev.get('confidence')} | {dev.get('total_packets', 0):,} | {mb:.2f} MB |\n")
        md.append("\n")

        # Detailed Asset Profiling & Evidence
        md.append("### Asset Forensic Evidence & Profiling\n")
        for ip, dev in sorted(devices.items()):
            md.append(f"#### Device: `{ip}` ({dev.get('suspected_role')})\n")
            md.append(f"- **MAC Address:** `{dev.get('mac_address')}` ({dev.get('mac_vendor')})\n")
            if dev.get('hostname'):
                md.append(f"- **Hostname:** `{dev.get('hostname')}`\n")
            md.append(f"- **Suspected Role:** **{dev.get('suspected_role')}** (Confidence: **{dev.get('confidence')}**)\n")
            md.append(f"- **Observed TCP destination ports (not verified listeners):** {dev.get('observed_ports_tcp_server')}\n")
            md.append(f"- **Observed Client Ports:** {len(dev.get('observed_ports_tcp_client'))} dynamic ports\n")
            md.append(f"- **Protocols Used:** {', '.join(dev.get('protocols_used', []))}\n")
            md.append(f"- **Traffic Volume:** {dev.get('packets_sent', 0):,} pkts sent ({dev.get('bytes_sent', 0):,} B), {dev.get('packets_received', 0):,} pkts received ({dev.get('bytes_received', 0):,} B)\n")
            md.append(f"- **First Observed:** {format_ts(dev.get('first_seen'))}  \n")
            md.append(f"- **Last Observed:** {format_ts(dev.get('last_seen'))}  \n")
            md.append("- **Supporting Evidence:**\n")
            for ev in dev.get('evidence', []):
                md.append(f"  - {ev}\n")
            md.append("\n")

        # Protocol-Specific Insights
        md.append("## Protocol-Specific Insights\n")
        for proto, data in insights.items():
            fcs = data.get("function_codes", {})
            ops = data.get("operations", {})
            uids = data.get("unit_ids", [])
            dev_ids = data.get("device_identifiers", [])
            if fcs or ops or uids or dev_ids:
                md.append(f"### {proto}\n")
                if fcs:
                    md.append(f"- **Function Codes ({data.get('function_source', 'unverified')}):** {', '.join([f'{k} ({v:,})' for k, v in fcs.items()])}\n")
                if ops:
                    md.append(f"- **Operations / ROSCTR ({data.get('operation_source', 'unverified')}):** {', '.join([f'{k} ({v:,})' for k, v in ops.items()])}\n")
                if uids:
                    md.append(f"- **Unit IDs:** {uids}\n")
                if dev_ids:
                    md.append(f"- **Device Identifiers / Strings:** {', '.join(dev_ids)}\n")
                md.append("\n")

        # Top Communications
        md.append("## Top Communications & Flows\n")
        md.append("| Client (Requester) | Server (Responder) | Port | Protocol | Packets | Bytes | First Seen | Last Seen |\n")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for f in flows:
            md.append(f"| `{f.get('client_ip')}:{f.get('source_port')}` | `{f.get('server_ip')}:{f.get('destination_port')}` | {f.get('destination_port')} | {f.get('protocol')} | {f.get('packet_count', 0):,} | {f.get('total_bytes', 0):,} | {format_ts(f.get('first_seen'))} | {format_ts(f.get('last_seen'))} |\n")

        return "".join(md)

    @staticmethod
    def to_html(analysis_result: Dict[str, Any]) -> str:
        """Generates a standalone, styled, premium HTML report."""
        summary = analysis_result.get("summary", {})
        protocols = analysis_result.get("detected_protocols", {})
        transport = analysis_result.get("transport_summary", {})
        devices = analysis_result.get("devices", {})
        flows = analysis_result.get("conversations", [])[:50]
        insights = analysis_result.get("protocol_insights", {})
        anomalies = analysis_result.get("anomalies", [])

        # Escape untrusted PCAP-derived strings in standalone HTML output.
        def esc(value):
            if isinstance(value, str):
                return html.escape(value, quote=True)
            if isinstance(value, dict):
                return {esc(k): esc(v) for k, v in value.items()}
            if isinstance(value, list):
                return [esc(v) for v in value]
            return value

        summary, protocols, transport, devices, flows, insights, anomalies = map(
            esc, (summary, protocols, transport, devices, flows, insights, anomalies)
        )
        quality = esc(analysis_result.get("analysis_quality") or {})
        reference = esc(analysis_result.get("wireshark_reference") or {})

        # Build protocol badges
        proto_badges_html = "".join([
            f"""<div class="proto-card">
                <span class="proto-name">{p}</span>
                <span class="proto-val">{count:,}</span>
            </div>""" for p, count in protocols.items()
        ])

        # Build transport layer badges
        transport_badges_html = "".join([
            f"""<div class="proto-card">
                <span class="proto-name">{p}</span>
                <span class="proto-val">{count:,}</span>
            </div>""" for p, count in transport.items()
        ])

        # Self-contained SVG graphics. Labels are already HTML-escaped above;
        # values are numeric. No remote libraries or JavaScript are required.
        def svg_bars(entries, color="#17b6be", height_per_row=38):
            clean = []
            for name, value in entries:
                try:
                    val = max(0, float(value))
                except (ValueError, TypeError):
                    continue
                clean.append((str(name), val))
            clean = sorted(clean, key=lambda x: x[1], reverse=True)[:7]
            if not clean:
                return "<p class='empty-visual'>No comparable data available.</p>"
            top = max(1, max(v for _,v in clean))
            width, height = 900, 30 + len(clean) * height_per_row
            svg = [f'<svg class="report-bars" viewBox="0 0 {width} {height}" role="img" aria-label="Ranked values chart">']
            for i, (label, v) in enumerate(clean):
                y = 18 + i * height_per_row
                safe_label = html.escape(label, quote=True)
                bar_width = 470 * v / top
                svg.append(f'<text x="3" y="{y+13}" class="bar-label">{safe_label[:46]}</text>')
                svg.append(f'<rect x="282" y="{y}" width="470" height="17" rx="5" fill="#243449"/>')
                svg.append(f'<rect x="282" y="{y}" width="{bar_width:.1f}" height="17" rx="5" fill="{color}"/>')
                svg.append(f'<text x="770" y="{y+13}" class="bar-value">{v:,.0f}</text>')
            svg.append('</svg>')
            return ''.join(svg)

        protocol_chart = svg_bars(protocols.items())
        roles_count = {}
        for dev in devices.values():
            role = dev.get('suspected_role') or 'Unknown'
            roles_count[role] = roles_count.get(role, 0) + 1
        role_chart = svg_bars(roles_count.items(), "#8ca3c0")
        top_conversations_chart = svg_bars([
            (f"{f.get('client_ip', '?')} → {f.get('server_ip', '?')}", f.get('total_bytes', 0))
            for f in flows
        ], "#20b69c")
        # Render each supported protocol's most frequent decoded functions as bars.
        function_charts = []
        for protocol_name, data in insights.items():
            fields = data.get('function_codes') or {}
            if fields:
                function_charts.append(
                    '<section class="figure-card"><h3>' + str(protocol_name) +
                    ' — function field occurrences</h3>' + svg_bars(fields.items(), "#4a9eea") +
                    '<p class="figure-caption">Decoded field occurrences; multiple fields may occur in one captured frame.</p></section>'
                )
        protocol_function_charts = ''.join(function_charts) or '<p>No decoded industrial function fields for this capture.</p>'

        # Build anomaly cards
        anom_html = ""
        if anomalies:
            anom_html = "<h2>Security & Operational Findings</h2><div class='anom-grid'>"
            for a in anomalies:
                sev_cls = "sev-high" if a.get("severity") in ["HIGH", "CRITICAL"] else "sev-med"
                anom_html += f"""
                <div class="anom-card {sev_cls}">
                    <div class="anom-hdr">
                        <span class="badge {sev_cls}">{a.get('severity')}</span>
                        <strong>{a.get('type')}</strong>
                    </div>
                    <p><strong>Device:</strong> <code>{a.get('source_ip')}</code></p>
                    <p>{a.get('evidence')}</p>
                </div>"""
            anom_html += "</div>"

        # Build device rows
        device_rows_html = ""
        for ip, dev in sorted(devices.items()):
            role = dev.get("suspected_role", "Unknown")
            conf = dev.get("confidence", "Low")
            role_cls = f"role-{role.lower().replace(' ', '-')}"
            conf_cls = f"conf-{conf.lower()}"
            ev_list = "".join([f"<li>{e}</li>" for e in dev.get("evidence", [])])
            ev_list = (f"<li><strong>First observed:</strong> {format_ts(dev.get('first_seen'))}</li>"
                       f"<li><strong>Last observed:</strong> {format_ts(dev.get('last_seen'))}</li>") + ev_list
            ports = ", ".join(map(str, dev.get("observed_ports_tcp_server", []))) or "None"
            mb = dev.get("total_bytes", 0) / (1024 * 1024)

            device_rows_html += f"""
            <tr>
                <td><strong><code>{ip}</code></strong></td>
                <td><code>{dev.get('mac_address')}</code></td>
                <td>{dev.get('mac_vendor')}</td>
                <td><span class="badge {role_cls}">{role}</span></td>
                <td><span class="badge {conf_cls}">{conf}</span></td>
                <td>{dev.get('total_packets', 0):,}</td>
                <td>{mb:.2f} MB</td>
                <td><code>{ports}</code></td>
                <td>
                    <details>
                        <summary>{len(dev.get('evidence', []))} Observations</summary>
                        <ul class="ev-list">{ev_list}</ul>
                    </details>
                </td>
            </tr>"""

        # Build flow rows
        flow_rows_html = ""
        for f in flows:
            flow_rows_html += f"""
            <tr>
                <td><code>{f.get('client_ip')}:{f.get('source_port')}</code></td>
                <td><code>{f.get('server_ip')}:{f.get('destination_port')}</code></td>
                <td><span class="proto-tag">{f.get('protocol')}</span></td>
                <td>{f.get('packet_count', 0):,}</td>
                <td>{f.get('total_bytes', 0):,} B</td>
                <td><code>{format_ts(f.get('first_seen'))}</code></td>
                <td><code>{format_ts(f.get('last_seen'))}</code></td>
                <td><code>{f.get('likely_requester')}</code></td>
                <td><code>{f.get('likely_responder')}</code></td>
            </tr>"""

        # Build protocol insights cards
        insights_html = ""
        for proto, data in insights.items():
            fcs = data.get("function_codes", {})
            ops = data.get("operations", {})
            dev_ids = data.get("device_identifiers", [])
            if fcs or ops or dev_ids:
                fcs_txt = ", ".join([f"{k} ({v:,})" for k, v in fcs.items()]) or "None"
                ops_txt = ", ".join([f"{k} ({v:,})" for k, v in ops.items()]) or "None"
                dev_ids_txt = ", ".join(dev_ids) or "None"
                insights_html += f"""
                <div class="insight-card">
                    <h3>{proto}</h3>
                    <p><strong>Function provenance:</strong> {data.get('function_source', 'unverified')}</p>
                    <p><strong>Operations provenance:</strong> {data.get('operation_source', 'unverified')}</p>
                    <p><strong>Functions:</strong> {fcs_txt}</p>
                    <p><strong>Operations:</strong> {ops_txt}</p>
                    <p><strong>Discovered Device Identifiers:</strong> <code>{dev_ids_txt}</code></p>
                </div>"""

        report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OT Network Capture Report - {summary.get('filename')}</title>
<style>
    :root {{
        --bg: #0b0f19;
        --card: #131b2e;
        --border: #1f293d;
        --text: #e2e8f0;
        --text-muted: #94a3b8;
        --cyan: #06b6d4;
        --cyan-glow: rgba(6, 182, 212, 0.15);
        --amber: #f59e0b;
        --red: #ef4444;
        --green: #10b981;
        --purple: #8b5cf6;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        background-color: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 40px;
        line-height: 1.5;
    }}
    .container {{
        max-width: 1400px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 1px solid var(--border);
        padding-bottom: 24px;
        margin-bottom: 32px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
    }}
    h1 {{
        margin: 0 0 8px 0;
        font-size: 28px;
        letter-spacing: -0.5px;
        color: #fff;
    }}
    .file-badge {{
        background: var(--cyan-glow);
        color: var(--cyan);
        padding: 4px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-size: 14px;
    }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        margin-bottom: 32px;
    }}
    .kpi-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 20px;
    }}
    .kpi-title {{
        font-size: 13px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
    }}
    .kpi-val {{
        font-size: 26px;
        font-weight: 700;
        color: #fff;
    }}
    .proto-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 32px;
    }}
    .proto-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 10px 16px;
        display: flex;
        gap: 12px;
        align-items: center;
    }}
    .proto-name {{ font-weight: 600; color: var(--cyan); }}
    .proto-val {{ color: var(--text-muted); font-size: 14px; }}
    
    .table-container {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow-x: auto;
        margin-bottom: 40px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 14px;
    }}
    th, td {{
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid var(--border);
    }}
    th {{
        background: rgba(255, 255, 255, 0.02);
        color: var(--text-muted);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 12px;
        letter-spacing: 0.5px;
    }}
    tr:hover td {{
        background: rgba(255, 255, 255, 0.015);
    }}
    code {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
    }}
    .role-plc {{ background: rgba(6, 182, 212, 0.2); color: #38bdf8; }}
    .role-hmi {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
    .role-engineering-workstation {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
    .role-scada-server {{ background: rgba(139, 92, 246, 0.2); color: #a78bfa; }}
    .role-network-device {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
    .role-server {{ background: rgba(107, 114, 128, 0.2); color: #9ca3af; }}
    .role-unknown {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
    .conf-high {{ color: #10b981; }}
    .conf-medium {{ color: #f59e0b; }}
    .conf-low {{ color: #ef4444; }}
    
    .anom-grid {{
        display: grid;
        grid-template-columns: 1fr;
        gap: 16px;
        margin-bottom: 32px;
    }}
    .anom-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-left: 4px solid var(--amber);
        border-radius: 8px;
        padding: 16px;
    }}
    .sev-high {{ border-left-color: var(--red); }}
    .ev-list {{
        margin: 6px 0 0 0;
        padding-left: 20px;
        color: var(--text-muted);
        font-size: 13px;
    }}
    .insight-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 16px;
        margin-bottom: 32px;
    }}
    .insight-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 18px;
    }}
    .insight-card h3 {{
        margin-top: 0;
        color: var(--cyan);
        font-size: 16px;
    }}
    .figure-grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(390px,1fr));gap:18px;margin:22px 0 30px;}}
    .figure-card {{background:var(--card);border:1px solid var(--border);padding:20px;border-radius:10px;break-inside:avoid;}}
    .figure-card h3 {{font-size:15px;color:var(--text);margin:0 0 8px;}}
    .report-bars {{display:block;width:100%;height:auto;max-width:100%;}}
    .bar-label {{font:500 14px Arial, sans-serif;fill:#ccd8e6;}}
    .bar-value {{font:700 14px Arial, sans-serif;fill:#e7f1fb;}}
    .figure-caption,.empty-visual {{font-size:12px;color:var(--text-muted);line-height:1.5;}}
    @media print {{body {{background:white;color:#182236;padding:18px;}} .figure-card,.kpi-card,.table-container {{background:#f4f7fa;border-color:#d7dfe6;}} .figure-card h3,h1,.bar-label,.bar-value,.kpi-val {{color:#152941;fill:#152941;}} .report-bars rect:first-of-type {{fill:#e7ebef}} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>Industrial Network Capture Analysis Report</h1>
            <p><strong>Counting provenance:</strong> {quality.get('mode', 'unverified')} | {reference.get('version', 'TShark unavailable')}</p>
            <p>Frame counts may overlap across protocols; role and asset identification remains heuristic. ARP MAC claims are not independently authenticated.</p>
            <span class="file-badge">{summary.get('filename')}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 14px;">
            Captured: {summary.get('start_time')} to {summary.get('end_time')}
        </div>
    </div>

    <p style="color: var(--text-muted); font-size: 12px; max-width: 900px; margin-top: -8px;">
        <strong>Observed facts:</strong> IPs, ports, frame lengths and times as captured; ARP MAC bindings are unverified claims in the PCAP.
        <strong>Derived information:</strong> TShark protocol/field decoding, counts, rates and OUI vendor lookups.
        <strong>Inferences:</strong> suspected roles and alerts require external confirmation; decoded messages do not prove successful PLC actions.
    </p>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Total Packets</div>
            <div class="kpi-val">{summary.get('packet_count', 0):,}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Captured Frame Volume</div>
            <div class="kpi-val">{summary.get('total_transferred_mb', 0)} MiB</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Discovered Assets</div>
            <div class="kpi-val">{summary.get('device_count', 0)}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">OT Industrial Assets</div>
            <div class="kpi-val" style="color: var(--cyan);">{summary.get('ot_asset_count', 0)}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Capture Duration</div>
            <div class="kpi-val">{summary.get('duration_human')}</div>
        </div>
    </div>

    {anom_html}

    <h2>Visual evidence overview</h2>
    <div class="figure-grid">
        <section class="figure-card"><h3>Primary frame classification</h3>{protocol_chart}
            <p class="figure-caption">Exclusive protocol classes; one primary label per captured frame.</p></section>
        <section class="figure-card"><h3>Suspected device-role distribution</h3>{role_chart}
            <p class="figure-caption">Heuristic categories, not verified physical-device identities.</p></section>
        <section class="figure-card"><h3>Top communication groups by captured bytes</h3>{top_conversations_chart}
            <p class="figure-caption">Endpoint directions inferred; byte volumes may overlap by endpoint.</p></section>
    </div>
    <h2>Decoded industrial operations</h2>
    <div class="figure-grid">{protocol_function_charts}</div>
    <h2>Detailed protocol evidence</h2>
    <p style="color: var(--text-muted); font-size: 13px; margin-top: -6px;">Each packet is classified into exactly one protocol, so shares add up to at most 100%.</p>
    <div class="proto-grid">
        {proto_badges_html}
    </div>

    {("<h3>Outermost Transport / Link Layer Totals</h3><div class='proto-grid'>" + transport_badges_html + "</div>") if transport_badges_html else ""}

    <h2>Device Inventory & Asset Profiles</h2>
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>Suspected Role</th>
                    <th>Confidence</th>
                    <th>Packets</th>
                    <th>Volume</th>
                    <th>Server Ports</th>
                    <th>Supporting Evidence</th>
                </tr>
            </thead>
            <tbody>
                {device_rows_html}
            </tbody>
        </table>
    </div>

    <h2>Protocol-Specific Insights (Bonus)</h2>
    <div class="insight-grid">
        {insights_html}
    </div>

    <h2>Top Conversations & Flows</h2>
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Client (Port)</th>
                    <th>Server (Port)</th>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Volume</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Likely Requester</th>
                    <th>Likely Responder</th>
                </tr>
            </thead>
            <tbody>
                {flow_rows_html}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>"""
        return report_html
