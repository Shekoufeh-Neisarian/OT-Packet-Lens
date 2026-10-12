"""
Core PCAP/PCAPNG Packet Analysis Engine.
Processes network captures at high speed using dpkt streaming with fallback dissectors.
"""

import os
import time
import socket
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable
from collections import Counter, defaultdict

import dpkt

from .oui_lookup import get_vendor, normalize_mac
from .protocols import inspect_payload
from .protocols.common import ProtocolInsight
from .device_profiler import DeviceRecord
from .flow_analyzer import ConversationManager
from .wireshark_reference import analyze_with_tshark, find_tshark

class PcapAnalyzer:
    def __init__(self, file_path: str, require_tshark: bool = False):
        self.file_path = file_path
        self.require_tshark = require_tshark
        self.file_name = os.path.basename(file_path)
        self.file_size_bytes = 0
        
        # Capture Statistics
        self.total_packets = 0
        self.total_bytes = 0
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        
        # Protocol Counters
        # detected_protocols: exactly ONE classification per packet
        # (app-layer protocol when identified, otherwise the transport protocol)
        self.detected_protocols = Counter()
        # transport_counts: informational totals per link/network/transport protocol
        self.transport_counts = Counter()
        
        # Protocol-specific insights
        self.insights: Dict[str, ProtocolInsight] = {
            "Modbus/TCP": ProtocolInsight("Modbus/TCP"),
            "S7comm": ProtocolInsight("S7comm"),
            "EtherNet/IP": ProtocolInsight("EtherNet/IP"),
            "DNP3": ProtocolInsight("DNP3"),
            "BACnet/IP": ProtocolInsight("BACnet/IP"),
            "IEC 60870-5-104": ProtocolInsight("IEC 60870-5-104"),
            "OPC UA": ProtocolInsight("OPC UA")
        }
        
        # Hostnames and DNS mapping
        self.dns_queries = Counter()
        self.dns_answers = Counter()
        self.discovered_hostnames = {}  # ip -> hostname
        
        # Devices and Flows
        self.devices: Dict[str, DeviceRecord] = {}
        self.conversations = ConversationManager()
        
        # Anomalies and Suspicious Findings
        self.anomalies = []

    def _get_device(self, ip: str) -> DeviceRecord:
        if ip not in self.devices:
            self.devices[ip] = DeviceRecord(ip)
        return self.devices[ip]

    def analyze(self, progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Dict[str, Any]:
        """
        Executes complete PCAP stream analysis.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")

        self.file_size_bytes = os.path.getsize(self.file_path)
        if self.file_size_bytes == 0:
            raise ValueError(f"PCAP file is empty (0 bytes): {self.file_path}")

        t_start = time.time()
        non_ethernet_warning = None
        
        with open(self.file_path, "rb") as f:
            # Check file magic to identify pcap vs pcapng
            magic = f.read(4)
            f.seek(0)
            
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception as e:
                # Attempt pcapng reader if available in dpkt
                try:
                    f.seek(0)
                    reader = dpkt.pcapng.Reader(f)
                except Exception:
                    raise ValueError(f"Unsupported or corrupted capture file format: {e}")

            # A raw IP/SLL/802.11 capture must not be interpreted as Ethernet:
            # protocol statistics still come from TShark, but endpoint discovery
            # is disabled unless the link-layer parser is applicable.
            datalink = reader.datalink() if hasattr(reader, "datalink") else 1
            ethernet_link = (datalink == 1)  # DLT_EN10MB
            if not ethernet_link:
                non_ethernet_warning = f"Link type {datalink}: IP endpoint/role analysis disabled; TShark still counts protocols."
            pkt_idx = 0
            last_progress_time = time.time()
            
            for ts, buf in reader:
                pkt_idx += 1
                pkt_len = len(buf)
                self.total_packets += 1
                self.total_bytes += pkt_len

                if self.first_timestamp is None or ts < self.first_timestamp:
                    self.first_timestamp = ts
                if self.last_timestamp is None or ts > self.last_timestamp:
                    self.last_timestamp = ts

                # Periodic progress callback
                if progress_callback and (pkt_idx % 25000 == 0):
                    now = time.time()
                    if now - last_progress_time >= 0.5:
                        progress_callback(pkt_idx, self.file_size_bytes, f"Processed {pkt_idx:,} packets...")
                        last_progress_time = now

                # Parse Ethernet Layer
                if not ethernet_link:
                    continue
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                src_mac = eth.src.hex(':') if hasattr(eth, 'src') else ""
                dst_mac = eth.dst.hex(':') if hasattr(eth, 'dst') else ""
                src_vendor = get_vendor(src_mac)
                dst_vendor = get_vendor(dst_mac)

                # 1. ARP Handling
                if isinstance(eth.data, dpkt.arp.ARP):
                    self.detected_protocols["ARP"] += 1
                    self.transport_counts["ARP"] += 1
                    arp = eth.data
                    try:
                        arp_src_ip = socket.inet_ntoa(arp.spa)
                        arp_dst_ip = socket.inet_ntoa(arp.tpa)
                        if arp_src_ip and arp_src_ip != "0.0.0.0":
                            dev = self._get_device(arp_src_ip)
                            claimed_mac = getattr(arp, "sha", b"").hex(":")
                            if claimed_mac and claimed_mac != "00:00:00:00:00:00":
                                dev.mac_addresses.add(claimed_mac)
                                dev.vendors.add(get_vendor(claimed_mac))
                            dev.protocols_used.add("ARP")
                            dev.update_timestamps(ts)
                            dev.packets_sent += 1
                            dev.bytes_sent += pkt_len
                    except Exception:
                        pass
                    continue

                # 2. IP Layer Handling
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    # Non-IP Ethernet packet
                    continue

                ip = eth.data
                try:
                    src_ip = socket.inet_ntoa(ip.src) if isinstance(ip, dpkt.ip.IP) else socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst) if isinstance(ip, dpkt.ip.IP) else socket.inet_ntop(socket.AF_INET6, ip.dst)
                except Exception:
                    continue

                dev_src = self._get_device(src_ip)
                dev_dst = self._get_device(dst_ip)
                # Do not infer an IP endpoint MAC from the Ethernet envelope.
                # Routed packets carry gateway MAC addresses, not remote-host MACs.
                dev_src.packets_sent += 1
                dev_src.bytes_sent += pkt_len
                dev_src.update_timestamps(ts)
                dev_src.communication_partners.add(dst_ip)

                dev_dst.packets_received += 1
                dev_dst.bytes_received += pkt_len
                dev_dst.update_timestamps(ts)
                dev_dst.communication_partners.add(src_ip)

                # IPv4 uses `p`; IPv6 uses `nxt` for the next-header field.
                ip_protocol = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
                # ICMP
                if ip_protocol in (dpkt.ip.IP_PROTO_ICMP, 58):
                    self.detected_protocols["ICMP"] += 1
                    self.transport_counts["ICMP"] += 1
                    dev_src.protocols_used.add("ICMP")
                    dev_dst.protocols_used.add("ICMP")
                    self.conversations.record_packet(src_ip, dst_ip, 0, 0, "ICMP", pkt_len, ts)
                    continue

                # Transport Layer
                transport = ""
                sport = 0
                dport = 0
                payload = b""
                is_syn = False

                if ip_protocol == dpkt.ip.IP_PROTO_TCP:
                    transport = "TCP"
                    self.transport_counts["TCP"] += 1
                    try:
                        tcp = ip.data
                        sport = tcp.sport
                        dport = tcp.dport
                        payload = tcp.data
                        is_syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not bool(tcp.flags & dpkt.tcp.TH_ACK)
                        dev_src.observed_ports_tcp_client.add(sport)
                        dev_dst.observed_ports_tcp_server.add(dport)
                    except Exception:
                        continue
                elif ip_protocol == dpkt.ip.IP_PROTO_UDP:
                    transport = "UDP"
                    self.transport_counts["UDP"] += 1
                    try:
                        udp = ip.data
                        sport = udp.sport
                        dport = udp.dport
                        payload = udp.data
                        dev_src.observed_ports_udp.add(sport)
                        dev_dst.observed_ports_udp.add(dport)
                    except Exception:
                        continue
                else:
                    self.detected_protocols[f"IP_Proto_{ip_protocol}"] += 1
                    continue

                # Deep protocol inspection
                inspection = inspect_payload(payload, sport, dport, transport)
                proto_name = inspection.get("protocol") if inspection else transport
                self.detected_protocols[proto_name] += 1
                dev_src.protocols_used.add(proto_name)
                dev_dst.protocols_used.add(proto_name)

                is_req = inspection.get("is_request", False) if inspection else False
                is_resp = inspection.get("is_response", False) if inspection else False

                # Process Protocol-Specific Insights
                if inspection:
                    self._record_insights(inspection, dev_src, dev_dst, sport, dport, payload)

                # Record Flow
                self.conversations.record_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    protocol=transport,
                    length=pkt_len,
                    ts=ts,
                    is_syn=is_syn,
                    is_req=is_req,
                    is_resp=is_resp
                )

        # A separate Wireshark pass supplies the authoritative dissector-based
        # protocol counts, including TCP reassembly and multiple application
        # PDUs in the same frame. Device heuristics remain separately inferred.
        tshark_result = None
        verification_warning = None
        if find_tshark():
            try:
                if progress_callback:
                    progress_callback(self.total_packets, self.file_size_bytes,
                                      "Computing Wireshark/TShark reference counts...")
                tshark_result = analyze_with_tshark(self.file_path,
                                                    progress_callback=progress_callback)
                if tshark_result["packet_count"] != self.total_packets:
                    raise RuntimeError(
                        f"Frame mismatch: Python counted {self.total_packets}, "
                        f"TShark counted {tshark_result['packet_count']}"
                    )
                self.detected_protocols = Counter(tshark_result["packet_classifications"])
                # Outer transport differs from overlapping protocol PRESENCE:
                # ICMP packets in Mystery3 embed a UDP header, causing a `udp`
                # display filter to match additional ICMP frames. Use FIRST
                # decoded transport for mutually exclusive outer-layer counts.
                outer = tshark_result["outer_transport_packet_counts"]
                self.transport_counts = Counter({
                    tag.upper() if tag != "icmpv6" else "ICMPv6": int(outer.get(tag, 0))
                    for tag in ("tcp", "udp", "arp", "icmp", "icmpv6")
                })
                for name in ("Modbus/TCP", "S7comm"):
                    self.insights[name].function_codes = dict(
                        tshark_result["function_code_occurrences"].get(name, {})
                    )
                decoded = tshark_result["decoded_insights"]
                self.insights["Modbus/TCP"].exception_codes = decoded["modbus_exception_codes"]
                self.insights["Modbus/TCP"].unit_ids = set(decoded["modbus_unit_ids"])
                self.insights["S7comm"].operations = decoded["s7_rosctr"]
                # Replace retransmission-inflated per-segment S7 device counters
                # with Wireshark-decoded JOB requests by originating IP address.
                s7_by_ip = decoded.get("s7_job_functions_by_src_ip", {})
                for dev in self.devices.values():
                    jobs = s7_by_ip.get(dev.ip, {})
                    dev.s7_read_vars = jobs.get("Read Var", 0)
                    dev.s7_write_vars = jobs.get("Write Var", 0)
                    dev.s7_prog_ops = sum(count for name, count in jobs.items()
                        if name in {"Request Download", "Download Block", "Download Ended",
                                    "Start Upload", "Upload Block", "End Upload",
                                    "PLC Control (Start CPU)", "PLC Stop"})
                self.insights["EtherNet/IP"].operations = decoded["enip_commands"]
                self.insights["DNP3"].function_codes = decoded["dnp3_functions"]
                # Remove per-segment exception estimates from incident scoring.
                for dev in self.devices.values():
                    dev.modbus_exceptions = decoded["modbus_exception_source_ips"].get(dev.ip, 0)
            except Exception as exc:
                tshark_result = None
                verification_warning = f"Wireshark dissection failed: {exc}"
                if self.require_tshark:
                    raise RuntimeError(verification_warning) from exc
        else:
            if self.require_tshark:
                raise RuntimeError("TShark is required for website analysis but was not found. "
                                   "Install Wireshark with TShark or set OT_PACKET_LENS_TSHARK.")
            verification_warning = (
                "Wireshark/TShark is not installed. Protocol and function-code "
                "statistics use an approximate per-segment parser, not "
                "Wireshark-equivalent TCP reassembly."
            )

        t_elapsed = time.time() - t_start
        
        # Scanning heuristics may run without TShark, but a Modbus exception
        # alert must never originate from a TCP-segment-only approximation.
        self._detect_anomalies(verified_exceptions=bool(tshark_result))

        # Build Device Inventory with Role Inferences
        inventory = {}
        for ip, dev in self.devices.items():
            # Attach discovered hostname if any
            if ip in self.discovered_hostnames:
                dev.hostnames.add(self.discovered_hostnames[ip])
            inventory[ip] = dev.infer_role(self.devices)

        # Build Flow & Matrix Data
        flow_list = self.conversations.get_flow_list()
        matrix_list = self.conversations.get_matrix_list()
        graph_data = self.conversations.get_graph_data(inventory)

        # Calculate Capture Duration
        duration_sec = (self.last_timestamp - self.first_timestamp) if (self.first_timestamp is not None and self.last_timestamp is not None) else 0.0

        start_time_iso = datetime.fromtimestamp(self.first_timestamp, timezone.utc).isoformat() if self.first_timestamp is not None else "N/A"
        end_time_iso = datetime.fromtimestamp(self.last_timestamp, timezone.utc).isoformat() if self.last_timestamp is not None else "N/A"

        return {
            "summary": {
                "filename": self.file_name,
                "file_size_bytes": self.file_size_bytes,
                "file_size_mb": round(self.file_size_bytes / (1024 * 1024), 2),
                "packet_count": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_bytes_note": "Captured frame bytes, not wire-rate throughput or unique traffic across IP endpoints",
                "total_transferred_mb": round(self.total_bytes / (1024 * 1024), 2),
                "start_time": start_time_iso,
                "end_time": end_time_iso,
                "duration_seconds": round(duration_sec, 2),
                "duration_human": f"{int(duration_sec // 60)}m {int(duration_sec % 60)}s",
                "device_count": len(inventory),
                "device_count_note": "Observed unique IP entries (ARP plus IPv4/IPv6), not physical devices",
                "ot_asset_count": sum(1 for d in inventory.values() if d.get("is_ot_asset")),
                "analysis_time_seconds": round(t_elapsed, 2),
                "processing_rate_pkts_sec": round(self.total_packets / t_elapsed, 0) if t_elapsed > 0 else 0,
                "capture_average_pkts_sec": round(self.total_packets / duration_sec, 2) if duration_sec > 0 else 0
            },
            "analysis_quality": {
                "mode": "wireshark_dissected" if tshark_result else "estimated",
                "message": (
                    "Protocol frame classes, outer-layer transport counts and supported decoded fields "
                    "come from Wireshark/TShark. Device roles, network flows and "
                    "some other insights remain estimates. Frame and field counts have different units."
                    if tshark_result else verification_warning
                ),
                "note": "One exclusive chart label per frame; function codes are decoded field occurrences.",
                "endpoint_warning": non_ethernet_warning,
                "methodology": {"protocols": "TShark frame.protocols" if tshark_result else "Python per-segment estimate",
                                "modbus_s7_functions": "TShark decoded field occurrences" if tshark_result else "Python per-segment estimate",
                                "modbus_exceptions": "TShark decoded modbus.exception_code" if tshark_result else "Not validated; alerts suppressed",
                                "s7_device_requests": "TShark decoded Job (ROSCTR=1) S7 function fields by source IP; not retransmitted raw payload count",
                                "outer_transport": "First decoded TCP/UDP/ICMP/ICMPv6/ARP in TShark frame.protocols; inner encapsulated UDP excluded",
                                "asset_roles": "Heuristic; NOT confirmed physical-device identities",
                                "other_operations": "Mixed: TShark for S7 ROSCTR / ENIP commands / DNP3 function, other fields estimated",
                                "traffic_bytes": "Captured frame bytes; per-IP sent + received double counts endpoints"},
            },
            "wireshark_reference": tshark_result,
            "detected_protocols": dict(self.detected_protocols.most_common()),
            "transport_summary": dict(self.transport_counts.most_common()),
            "transport_source": "TShark outermost decoded L4/ARP frame counts (not overlapping -Y filters)" if tshark_result else "Python network-layer estimates",
            "devices": inventory,
            "conversations": flow_list[:250],  # top 250 flows
            "communication_matrix": matrix_list[:100],
            "topology_graph": graph_data,
            "protocol_insights": {k: dict(v.to_dict(),
                    function_source=("TShark decoded field occurrences" if tshark_result and k in ("Modbus/TCP", "S7comm", "DNP3") else "Python per-segment estimate"),
                    operation_source=("TShark decoded field occurrences" if tshark_result and k in ("S7comm", "EtherNet/IP") else "Python per-segment estimate"),
                    exception_source=("TShark decoded exception fields" if tshark_result and k == "Modbus/TCP" else "Unverified / heuristic"))
                    for k, v in self.insights.items()},
            "anomalies": self.anomalies
        }

    def _record_insights(self, insp: Dict[str, Any], dev_src: DeviceRecord, dev_dst: DeviceRecord, sport: int, dport: int, payload: bytes):
        p_name = insp.get("protocol")
        is_req = insp.get("is_request", False)
        is_resp = insp.get("is_response", False)

        if p_name in ["Modbus/TCP", "S7comm", "EtherNet/IP", "DNP3", "BACnet/IP", "IEC 60870-5-104", "OPC UA"]:
            if is_req:
                dev_src.industrial_requests_sent += 1
                dev_dst.industrial_requests_received += 1
            if is_resp:
                dev_src.industrial_responses_sent += 1
                dev_dst.industrial_responses_received += 1

        # Modbus Insights
        if p_name == "Modbus/TCP":
            ins = self.insights["Modbus/TCP"]
            fc_name = insp.get("function_name", "Unknown")
            ins.function_codes[fc_name] = ins.function_codes.get(fc_name, 0) + 1
            if "unit_id" in insp:
                ins.unit_ids.add(insp["unit_id"])
            if insp.get("is_exception"):
                exc = insp.get("exception_desc", "Exception")
                ins.exception_codes[exc] = ins.exception_codes.get(exc, 0) + 1
                dev_src.modbus_exceptions += 1
            
            fn_code = insp.get("function_code", 0)
            if fn_code in [1, 2, 3, 4]:
                if is_req: dev_src.modbus_read_ops += 1
            elif fn_code in [5, 6, 15, 16]:
                if is_req: dev_src.modbus_write_ops += 1

            if "device_info" in insp.get("extra_info", {}):
                dev_id = insp["extra_info"]["device_info"]
                ins.device_identifiers.add(dev_id)
                dev_src.device_identities.add(dev_id)

        # S7comm Insights
        elif p_name == "S7comm":
            ins = self.insights["S7comm"]
            rosctr = insp.get("rosctr_desc", "Unknown")
            ins.operations[rosctr] = ins.operations.get(rosctr, 0) + 1
            fn_name = insp.get("function_name", "Unknown")
            ins.function_codes[fn_name] = ins.function_codes.get(fn_name, 0) + 1
            
            fn_code = insp.get("function_code")
            if fn_code == 0x04:  # Read Var
                if is_req: dev_src.s7_read_vars += 1
            elif fn_code == 0x05:  # Write Var
                if is_req: dev_src.s7_write_vars += 1
            elif fn_code in [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29]:
                if is_req: dev_src.s7_prog_ops += 1
            elif fn_code == 0xF0:
                dev_src.s7_setup_comm += 1

            if insp.get("device_info"):
                ins.device_identifiers.add(insp["device_info"])
                dev_src.device_identities.add(insp["device_info"])

        # EtherNet/IP & CIP Insights
        elif p_name == "EtherNet/IP":
            ins = self.insights["EtherNet/IP"]
            cmd_name = insp.get("command_name", "Unknown")
            ins.operations[cmd_name] = ins.operations.get(cmd_name, 0) + 1
            if insp.get("cip_service_name"):
                svc = insp["cip_service_name"]
                ins.service_codes[svc] = ins.service_codes.get(svc, 0) + 1
                if "Read" in svc: dev_src.cip_read_ops += 1
                elif "Write" in svc or "Set" in svc: dev_src.cip_write_ops += 1
                elif "Forward Open" in svc: dev_src.cip_config_ops += 1
            if insp.get("device_identity"):
                ins.device_identifiers.add(insp["device_identity"])
                dev_src.device_identities.add(insp["device_identity"])

        # DNP3 Insights
        elif p_name == "DNP3":
            ins = self.insights["DNP3"]
            if insp.get("app_function_name"):
                fn = insp["app_function_name"]
                ins.function_codes[fn] = ins.function_codes.get(fn, 0) + 1
                if "Read" in fn: dev_src.dnp3_read_ops += 1
                elif "Write" in fn or "Operate" in fn: dev_src.dnp3_write_ops += 1
                elif "Restart" in fn: dev_src.dnp3_restart_ops += 1
            for flag in insp.get("iin_flags", []):
                ins.exception_codes[flag] = ins.exception_codes.get(flag, 0) + 1

        # BACnet Insights
        elif p_name == "BACnet/IP":
            ins = self.insights["BACnet/IP"]
            if insp.get("bvll_function"):
                ins.operations[insp["bvll_function"]] = ins.operations.get(insp["bvll_function"], 0) + 1
            if insp.get("service_name"):
                ins.service_codes[insp["service_name"]] = ins.service_codes.get(insp["service_name"], 0) + 1

        # IEC 104 Insights
        elif p_name == "IEC 60870-5-104":
            ins = self.insights["IEC 60870-5-104"]
            if insp.get("asdu_name"):
                ins.asdu_types[insp["asdu_name"]] = ins.asdu_types.get(insp["asdu_name"], 0) + 1
            if insp.get("apci_format"):
                ins.operations[insp["apci_format"]] = ins.operations.get(insp["apci_format"], 0) + 1

        # OPC UA Insights
        elif p_name == "OPC UA":
            ins = self.insights["OPC UA"]
            m_desc = insp.get("message_desc", "Unknown")
            ins.opcua_messages[m_desc] = ins.opcua_messages.get(m_desc, 0) + 1
            if insp.get("endpoint_url"):
                ins.device_identifiers.add(insp["endpoint_url"])
                dev_src.device_identities.add(insp["endpoint_url"])

        # DNS Insights & Hostname resolution
        elif p_name == "DNS":
            if is_req:
                dev_src.it_dns_queries += 1
                for q in insp.get("queries", []):
                    self.dns_queries[q] += 1
            if is_resp:
                dev_src.it_dns_responses += 1
                for ans in insp.get("answers", []):
                    self.dns_answers[ans] += 1
                    if " -> " in ans:
                        name, resolved_ip = ans.split(" -> ", 1)
                        self.discovered_hostnames[resolved_ip] = name

        # DHCP Hostname
        elif p_name == "DHCP":
            hname = insp.get("hostname")
            if hname:
                dev_src.hostnames.add(hname)
                self.discovered_hostnames[dev_src.ip] = hname

        # NetBIOS Name
        elif p_name == "NetBIOS-NS":
            for n in insp.get("names", []):
                dev_src.hostnames.add(n)
                self.discovered_hostnames[dev_src.ip] = n

    def _detect_anomalies(self, verified_exceptions=False):
        """Identifies suspicious behaviors, port scans, and unusual OT commands."""
        # 1. Detect rapid connection probes / port scans
        for (key, flow) in self.conversations.flows.items():
            ip1, ip2, port1, port2, proto = key
            # If a flow contacted S7 port 102 or Modbus 502 with small packet count and multiple ephemeral ports
            if proto == "TCP" and (port1 in [102, 502] or port2 in [102, 502]):
                client_ip = flow.ip1 if flow.port2 in [102, 502] else flow.ip2
                server_ip = flow.ip2 if flow.port2 in [102, 502] else flow.ip1
                target_port = flow.port2 if flow.port2 in [102, 502] else flow.port1
                # If flow only has 2-4 packets (SYN / RST or connection probe)
                if (flow.packets_1_to_2 + flow.packets_2_to_1) <= 6 and (flow.syn_from_1 or flow.syn_from_2):
                    dev = self.devices.get(client_ip)
                    if dev:
                        dev.port_scan_attempts += 1

        for ip, dev in self.devices.items():
            if dev.port_scan_attempts > 15:
                self.anomalies.append({
                    "severity": "MEDIUM",
                    "type": "Repeated Short TCP Sessions at Industrial Ports (heuristic)",
                    "source_ip": ip,
                    "evidence": f"Observed {dev.port_scan_attempts} short, SYN-bearing TCP flow groups involving industrial ports for {ip}. This may reflect retries, connection churn or probing; no scan intent or successful access is established."
                })
            
            # Write Var anomaly without read baseline
            if dev.s7_write_vars > 0 and dev.s7_read_vars == 0:
                self.anomalies.append({
                    "severity": "MEDIUM",
                    "type": "S7 Writes With No Decoded Reads From Same Source (review)",
                    "source_ip": ip,
                    "evidence": f"TShark decoded {dev.s7_write_vars} S7 Write Var job requests from {ip} but no decoded Read Var jobs from that IP in the capture. The request count alone does not establish authorization, target effect, or successful execution." if verified_exceptions else f"The per-segment parser saw {dev.s7_write_vars} S7 Write Var request-bearing segments from {ip}; retransmissions may be counted, and successful execution is not established."
                })
            
            # Modbus exception surge
            if verified_exceptions and dev.modbus_exceptions > 20:
                self.anomalies.append({
                    "severity": "MEDIUM",
                    "type": "High Modbus Exception Count (verify severity)",
                    "source_ip": ip,
                    "evidence": f"TShark decoded {dev.modbus_exceptions} Modbus exception-code occurrences with source IP {ip}; this is not an exception-rate measurement."
                })
