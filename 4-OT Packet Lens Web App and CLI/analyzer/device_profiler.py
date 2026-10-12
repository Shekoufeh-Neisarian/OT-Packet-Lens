"""
Device Profiler and OT Role Inference Engine.
Maintains device inventories and applies evidence-based classification rules to infer
device roles (PLC, HMI, Engineering Workstation, SCADA Server, Historian, Network Device, etc.)
with confidence scores and transparent evidence trails.
"""

from typing import Dict, Any, List, Set, Optional
from collections import defaultdict, Counter
from .oui_lookup import get_vendor

# Known industrial vendors
INDUSTRIAL_PLC_VENDORS = {
    "Siemens AG",
    "Rockwell Automation",
    "Schneider Electric",
    "Beckhoff Automation GmbH",
    "Phoenix Contact",
    "Omron Corporation",
    "WAGO Kontakttechnik GmbH",
    "Yokogawa Electric Corp.",
    "GE Energy",
    "GE Fanuc Automation",
    "ABB Automation",
    "Mitsubishi Electric",
    "Honeywell"
}

INDUSTRIAL_NET_VENDORS = {
    "Westermo Network Technologies AB",
    "Moxa Technologies Inc.",
    "Hirschmann Automation and Control GmbH",
    "Cisco Systems",
    "Belden",
    "Extreme Networks"
}

class DeviceRecord:
    def __init__(self, ip: str):
        self.ip: str = ip
        self.mac_addresses: Set[str] = set()
        self.vendors: Set[str] = set()
        self.hostnames: Set[str] = set()
        self.observed_ports_tcp_server: Set[int] = set()
        self.observed_ports_tcp_client: Set[int] = set()
        self.observed_ports_udp: Set[int] = set()
        self.protocols_used: Set[str] = set()
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None
        self.communication_partners: Set[str] = set()
        
        # Protocol behaviors
        self.industrial_requests_sent: int = 0
        self.industrial_responses_sent: int = 0
        self.industrial_requests_received: int = 0
        self.industrial_responses_received: int = 0
        
        # Granular operation tracking
        self.s7_read_vars: int = 0
        self.s7_write_vars: int = 0
        self.s7_setup_comm: int = 0
        self.s7_prog_ops: int = 0   # block upload/download, cpu start/stop
        self.modbus_read_ops: int = 0
        self.modbus_write_ops: int = 0
        self.modbus_exceptions: int = 0
        self.cip_read_ops: int = 0
        self.cip_write_ops: int = 0
        self.cip_config_ops: int = 0
        self.dnp3_read_ops: int = 0
        self.dnp3_write_ops: int = 0
        self.dnp3_restart_ops: int = 0
        self.it_dns_queries: int = 0
        self.it_dns_responses: int = 0
        self.it_ntp_traffic: int = 0
        self.port_scan_attempts: int = 0
        self.device_identities: Set[str] = set()

    def update_timestamps(self, ts: float):
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def infer_role(self, all_devices: Dict[str, "DeviceRecord"]) -> Dict[str, Any]:
        """
        Infers the device role with confidence rating and supporting evidence.
        Returns a dictionary separating Facts, Derived Info, and Inferences.
        """
        role = "Unknown"
        confidence = "Low"
        evidence: List[str] = []

        primary_vendor = sorted(self.vendors)[0] if self.vendors else "Unknown"
        primary_mac = sorted(self.mac_addresses)[0] if self.mac_addresses else "Unknown"
        primary_host = sorted(self.hostnames)[0] if self.hostnames else None

        is_ind_vendor = any(v in INDUSTRIAL_PLC_VENDORS for v in self.vendors)
        is_net_vendor = any(v in INDUSTRIAL_NET_VENDORS for v in self.vendors)

        ind_server_ports = {502, 102, 44818, 20000, 47808, 2404, 4840}
        has_ind_server = bool(self.observed_ports_tcp_server & ind_server_ports)
        listens_modbus = 502 in self.observed_ports_tcp_server
        listens_s7 = 102 in self.observed_ports_tcp_server
        listens_cip = 44818 in self.observed_ports_tcp_server
        listens_dnp3 = 20000 in self.observed_ports_tcp_server
        listens_bacnet = 47808 in self.observed_ports_udp
        listens_iec = 2404 in self.observed_ports_tcp_server
        listens_opc = 4840 in self.observed_ports_tcp_server

        # 1. Evaluate Network Device
        if is_net_vendor or self.ip.endswith(".1") or self.ip.endswith(".254"):
            if is_net_vendor:
                evidence.append(f"MAC vendor '{primary_vendor}' is a known industrial networking/switch manufacturer")
            if self.ip.endswith(".1") or self.ip.endswith(".254"):
                evidence.append(f"IP address {self.ip} follows standard default gateway / router conventions")
            if self.it_dns_responses > 0:
                evidence.append(f"Parser-observed responses to {self.it_dns_responses} DNS queries for network nodes")
            
            # If not primarily a PLC
            if not has_ind_server:
                role = "Network Device"
                confidence = "Medium" if is_net_vendor else "Low"
                return self._build_result(role, confidence, evidence)

        # 2. Evaluate PLC (Programmable Logic Controller)
        if has_ind_server or self.industrial_responses_sent > 50:
            evidence_plc = []
            if listens_s7:
                evidence_plc.append("Observed destination TCP port 102 (Siemens S7comm)")
            if listens_modbus:
                evidence_plc.append("Observed destination TCP port 502 (Modbus/TCP)")
            if listens_cip:
                evidence_plc.append("Observed destination TCP port 44818 (EtherNet/IP & CIP)")
            if listens_dnp3:
                evidence_plc.append("Observed destination TCP port 20000 (DNP3 Outstation)")
            if listens_bacnet:
                evidence_plc.append("Observed UDP port 47808")
            if listens_iec:
                evidence_plc.append("Observed destination TCP port 2404 (IEC 60870-5-104 Server)")
            if listens_opc:
                evidence_plc.append("Observed destination TCP port 4840 (OPC UA Server)")

            if self.industrial_responses_sent > 0:
                evidence_plc.append(f"Per-segment parser observed {self.industrial_responses_sent:,} industrial response-bearing segments; retransmissions may inflate this count")
            if is_ind_vendor:
                evidence_plc.append(f"MAC vendor '{primary_vendor}' matches major industrial automation PLC manufacturer")
            if self.industrial_requests_sent == 0 or (self.industrial_responses_sent > self.industrial_requests_sent * 5):
                evidence_plc.append("Traffic pattern is predominantly responder/slave (passive server behavior)")

            if len(evidence_plc) >= 2:
                role = "PLC"
                confidence = "Medium" if is_ind_vendor else "Low"
                evidence.extend(evidence_plc)
                return self._build_result(role, confidence, evidence)

        # 3. Evaluate Engineering Workstation (EWS)
        ews_evidence = []
        if self.s7_prog_ops > 0:
            ews_evidence.append(f"Decoded {self.s7_prog_ops} S7 programming-related request fields (Block Upload/Download / CPU Control); execution not verified")
        if self.s7_write_vars > 0 and self.s7_read_vars < self.s7_write_vars * 2:
            ews_evidence.append(f"Decoded {self.s7_write_vars} S7 Write Var requests with relatively few read requests (successful writes not established)")
        if self.cip_config_ops > 0 or self.cip_write_ops > 0:
            ews_evidence.append("Initiated CIP configuration/forward open or tag write commands")
        if self.dnp3_restart_ops > 0 or self.dnp3_write_ops > 0:
            ews_evidence.append("Sent DNP3 configuration, class assignment, or restart requests")
        if self.port_scan_attempts > 10:
            ews_evidence.append(f"Observed {self.port_scan_attempts} short SYN-bearing TCP flow groups involving industrial ports (retries, connection churn, or probing possible; scanning unproven)")
        if any(v in ["Wistron InfoComm (Kunshan) Co., Ltd.", "Dell Inc.", "Hewlett-Packard", "Pegatron Corporation"] for v in self.vendors):
            ews_evidence.append(f"Hardware manufacturer '{primary_vendor}' represents PC workstation hardware")

        if len(ews_evidence) >= 2 or self.s7_prog_ops > 0 or (self.s7_write_vars > 0 and self.s7_read_vars == 0):
            role = "Engineering Workstation"
            confidence = "Medium" if (self.s7_prog_ops > 0 or len(ews_evidence) >= 3) else "Low"
            evidence.extend(ews_evidence)
            return self._build_result(role, confidence, evidence)

        # 4. Evaluate HMI (Human Machine Interface)
        hmi_evidence = []
        if (self.s7_read_vars > 50 or self.modbus_read_ops > 50 or self.cip_read_ops > 50 or self.dnp3_read_ops > 50):
            hmi_evidence.append(f"Observed industrial Read Var request activity (decoded S7 jobs: {self.s7_read_vars}; per-segment Modbus read candidates: {self.modbus_read_ops}); cadence and role unconfirmed")
        if not has_ind_server and self.industrial_requests_sent > 0:
            hmi_evidence.append("Observed acting as an industrial request initiator; other roles cannot be excluded")
        if len(self.communication_partners) <= 3 and self.industrial_requests_sent > 100:
            hmi_evidence.append(f"Communicates with a small set of endpoint IPs: {sorted(self.communication_partners)}")

        if hmi_evidence:
            # Distinguish HMI vs SCADA vs Historian:
            #   1-2 controllers polled      -> HMI
            #   3+ controllers + data-store -> Historian
            #   3+ controllers otherwise    -> SCADA Server
            plc_targets = [p for p in self.communication_partners if all_devices.get(p) and all_devices[p].observed_ports_tcp_server & ind_server_ports]
            historian_ports = {1433, 5432, 3306, 27017, 5984, 8086, 8088, 9042}
            has_data_store = bool(self.observed_ports_tcp_server & historian_ports) or bool(self.device_identities)
            if len(plc_targets) >= 3 and has_data_store:
                role = "Historian"
                confidence = "Medium"
                if self.observed_ports_tcp_server & historian_ports:
                    evidence.append(f"Observed database / archival destination ports {sorted(self.observed_ports_tcp_server & historian_ports)}")
                if self.device_identities:
                    evidence.append(f"Identifies itself as a data/archival service: {sorted(self.device_identities)}")
                evidence.append(f"Collects telemetry from {len(plc_targets)} separate industrial controllers for long-term storage")
                evidence.extend(hmi_evidence)
            elif len(plc_targets) >= 3:
                role = "SCADA Server"
                confidence = "Medium"
                evidence.append(f"Orchestrates communications with {len(plc_targets)} separate industrial PLCs")
                evidence.extend(hmi_evidence)
            else:
                role = "HMI"
                confidence = "Medium" if (self.s7_read_vars > 1000 or self.modbus_read_ops > 1000) else "Low"
                evidence.extend(hmi_evidence)
            return self._build_result(role, confidence, evidence)

        # 5. Evaluate IT Servers (DNS, NTP, Web, etc.)
        if self.observed_ports_udp & {53, 123} or self.observed_ports_tcp_server & {80, 443, 445}:
            if 53 in self.observed_ports_udp:
                evidence.append("Observed DNS activity on UDP port 53")
            if 123 in self.observed_ports_udp:
                evidence.append("Observed NTP activity on UDP port 123")
            if 445 in self.observed_ports_tcp_server:
                evidence.append("Observed destination TCP port 445")
            role = "Server"
            confidence = "Medium" if self.it_dns_responses else "Low"
            return self._build_result(role, confidence, evidence)

        # 6. Evaluate Workstation / Client
        if self.it_dns_queries > 0 or self.observed_ports_tcp_client or self.it_ntp_traffic > 0:
            if self.it_dns_queries > 0:
                evidence.append(f"Generated {self.it_dns_queries} outbound DNS queries")
            if any(v in ["Apple Inc.", "Intel Corporate", "Realtek Semiconductor Corp."] for v in self.vendors):
                evidence.append(f"Hardware vendor '{primary_vendor}' represents standard computing client device")
            role = "Workstation"
            confidence = "Medium"
            return self._build_result(role, confidence, evidence)

        # 7. Fallback Unknown
        if self.packets_sent + self.packets_received < 10:
            evidence.append("Sparse traffic (less than 10 packets observed)")
        else:
            evidence.append(f"Observed {self.packets_sent + self.packets_received} packets but lacked definitive OT/IT role signatures")
        return self._build_result("Unknown", "Low", evidence)

    def _build_result(self, role: str, confidence: str, evidence: List[str]) -> Dict[str, Any]:
        primary_mac = sorted(self.mac_addresses)[0] if self.mac_addresses else "Unknown"
        primary_vendor = sorted(self.vendors)[0] if self.vendors else "Unknown"
        primary_host = sorted(self.hostnames)[0] if self.hostnames else None

        return {
            "ip_address": self.ip,
            "mac_address": primary_mac,
            "all_macs": sorted(list(self.mac_addresses)),
            "mac_vendor": primary_vendor,
            "all_vendors": sorted(list(self.vendors)),
            "hostname": primary_host,
            "all_hostnames": sorted(list(self.hostnames)),
            "observed_ports_tcp_server": sorted(list(self.observed_ports_tcp_server)),
            "port_method": "Observed TCP destination ports (not a verified LISTEN state)",
            "observed_ports_tcp_client": sorted(list(self.observed_ports_tcp_client)),
            "observed_ports_udp": sorted(list(self.observed_ports_udp)),
            "protocols_used": sorted(list(self.protocols_used)),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "total_packets": self.packets_sent + self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_bytes": self.bytes_sent + self.bytes_received,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "communication_partners": sorted(list(self.communication_partners)),
            "suspected_role": role,
            "confidence": confidence,
            "role_method": "Heuristic: passive capture indicators; not an authenticated device identity",
            "mac_method": "ARP-advertised binding (may be spoofed); unknown when absent",
            "evidence": evidence,
            "is_ot_asset": role in ["PLC", "HMI", "Engineering Workstation", "SCADA Server", "Historian"],
            "device_identities": sorted(list(self.device_identities))
        }
