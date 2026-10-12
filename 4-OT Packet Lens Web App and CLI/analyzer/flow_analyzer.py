"""
Communication Flow and Network Topology Analyzer.
Tracks conversations, determines Client/Server & Requester/Responder roles,
and builds communication matrices and graph datasets.
"""

from typing import Dict, Any, List, Tuple, Optional
from collections import defaultdict

class FlowRecord:
    def __init__(self, ip1: str, ip2: str, port1: int, port2: int, protocol: str):
        self.ip1: str = ip1
        self.ip2: str = ip2
        self.port1: int = port1
        self.port2: int = port2
        self.protocol: str = protocol
        
        self.packets_1_to_2: int = 0
        self.packets_2_to_1: int = 0
        self.bytes_1_to_2: int = 0
        self.bytes_2_to_1: int = 0
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None
        
        self.syn_from_1: bool = False
        self.syn_from_2: bool = False
        self.requests_from_1: int = 0
        self.requests_from_2: int = 0
        self.responses_from_1: int = 0
        self.responses_from_2: int = 0

    def add_packet(self, src: str, dst: str, length: int, ts: float, is_syn: bool, is_req: bool, is_resp: bool):
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        if src == self.ip1:
            self.packets_1_to_2 += 1
            self.bytes_1_to_2 += length
            if is_syn: self.syn_from_1 = True
            if is_req: self.requests_from_1 += 1
            if is_resp: self.responses_from_1 += 1
        else:
            self.packets_2_to_1 += 1
            self.bytes_2_to_1 += length
            if is_syn: self.syn_from_2 = True
            if is_req: self.requests_from_2 += 1
            if is_resp: self.responses_from_2 += 1

    def to_dict(self) -> Dict[str, Any]:
        # Determine likely client vs server
        # Registered/listening port heuristic
        known_service_ports = {502, 102, 44818, 2222, 20000, 47808, 2404, 4840, 53, 67, 68, 80, 443, 445, 123}
        if self.syn_from_1 and not self.syn_from_2:
            client_ip, client_port = self.ip1, self.port1
            server_ip, server_port = self.ip2, self.port2
        elif self.syn_from_2 and not self.syn_from_1:
            client_ip, client_port = self.ip2, self.port2
            server_ip, server_port = self.ip1, self.port1
        elif self.port2 in known_service_ports and self.port1 not in known_service_ports:
            client_ip, client_port = self.ip1, self.port1
            server_ip, server_port = self.ip2, self.port2
        elif self.port1 in known_service_ports and self.port2 not in known_service_ports:
            client_ip, client_port = self.ip2, self.port2
            server_ip, server_port = self.ip1, self.port1
        else:
            # Fallback to port asymmetry (higher port is usually client ephemeral)
            if self.port1 > self.port2:
                client_ip, client_port = self.ip1, self.port1
                server_ip, server_port = self.ip2, self.port2
            else:
                client_ip, client_port = self.ip2, self.port2
                server_ip, server_port = self.ip1, self.port1

        # Determine requester vs responder
        if self.requests_from_1 > self.requests_from_2 or self.responses_from_2 > self.responses_from_1:
            requester_ip = self.ip1
            responder_ip = self.ip2
        elif self.requests_from_2 > self.requests_from_1 or self.responses_from_1 > self.responses_from_2:
            requester_ip = self.ip2
            responder_ip = self.ip1
        else:
            requester_ip = client_ip
            responder_ip = server_ip

        return {
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_ip,
            "destination_port": server_port,
            "protocol": self.protocol,
            "packet_count": self.packets_1_to_2 + self.packets_2_to_1,
            "total_bytes": self.bytes_1_to_2 + self.bytes_2_to_1,
            "bytes_forward": self.bytes_1_to_2 if client_ip == self.ip1 else self.bytes_2_to_1,
            "bytes_reverse": self.bytes_2_to_1 if client_ip == self.ip1 else self.bytes_1_to_2,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "client_ip": client_ip,
            "server_ip": server_ip,
            "likely_requester": requester_ip,
            "likely_responder": responder_ip
        }

class ConversationManager:
    def __init__(self):
        # Key: (min_ip, max_ip, min_port, max_port, protocol)
        self.flows: Dict[Tuple, FlowRecord] = {}
        # Matrix aggregated by IP pair (ip_a, ip_b)
        self.matrix: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "protocols": set(), "first_seen": None, "last_seen": None}
        )

    def record_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                      protocol: str, length: int, ts: float, is_syn: bool = False,
                      is_req: bool = False, is_resp: bool = False):
        if not src_ip or not dst_ip:
            return

        # Canonical ordering for flow key
        if (src_ip, src_port) < (dst_ip, dst_port):
            key = (src_ip, dst_ip, src_port, dst_port, protocol)
            ip1, ip2, port1, port2 = src_ip, dst_ip, src_port, dst_port
        else:
            key = (dst_ip, src_ip, dst_port, src_port, protocol)
            ip1, ip2, port1, port2 = dst_ip, src_ip, dst_port, src_port

        if key not in self.flows:
            self.flows[key] = FlowRecord(ip1, ip2, port1, port2, protocol)

        self.flows[key].add_packet(src_ip, dst_ip, length, ts, is_syn, is_req, is_resp)

        # Update host-to-host conversation matrix
        host_key = tuple(sorted([src_ip, dst_ip]))
        m = self.matrix[host_key]
        m["packets"] += 1
        m["bytes"] += length
        m["protocols"].add(protocol)
        if m["first_seen"] is None or ts < m["first_seen"]:
            m["first_seen"] = ts
        if m["last_seen"] is None or ts > m["last_seen"]:
            m["last_seen"] = ts

    def get_flow_list(self) -> List[Dict[str, Any]]:
        flows_sorted = sorted(self.flows.values(), key=lambda f: (f.packets_1_to_2 + f.packets_2_to_1), reverse=True)
        return [f.to_dict() for f in flows_sorted]

    def get_matrix_list(self) -> List[Dict[str, Any]]:
        res = []
        for (ip1, ip2), data in self.matrix.items():
            res.append({
                "host_a": ip1,
                "host_b": ip2,
                "packet_count": data["packets"],
                "total_bytes": data["bytes"],
                "protocols": sorted(list(data["protocols"])),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"]
            })
        return sorted(res, key=lambda x: x["packet_count"], reverse=True)

    def get_graph_data(self, device_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Builds nodes and links for interactive network topology visualization."""
        nodes = []
        node_indices = {}
        for i, (ip, dev) in enumerate(device_dict.items()):
            node_indices[ip] = i
            nodes.append({
                "id": ip,
                "label": f"{dev.get('hostname') or ip}",
                "role": dev.get("suspected_role", "Unknown"),
                "vendor": dev.get("mac_vendor", "Unknown"),
                "is_ot": dev.get("is_ot_asset", False),
                "packets": dev.get("total_packets", 0),
                "bytes": dev.get("total_bytes", 0)
            })

        links = []
        for (ip1, ip2), data in self.matrix.items():
            if ip1 in node_indices and ip2 in node_indices:
                links.append({
                    "source": ip1,
                    "target": ip2,
                    "value": data["packets"],
                    "bytes": data["bytes"],
                    "protocols": list(data["protocols"])
                })

        return {"nodes": nodes, "links": links}
