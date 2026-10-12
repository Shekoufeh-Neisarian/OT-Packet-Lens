"""
Common Protocol Constants and Helper Classes for ICS/IT Traffic Analysis.
"""

from typing import Dict, Any, Optional

# Standard Well-Known Industrial OT Ports
PORT_MODBUS = 502
PORT_S7COMM = 102
PORT_ETHERNET_IP_EXPLICIT = 44818
PORT_ETHERNET_IP_IMPLICIT = 2222
PORT_DNP3 = 20000
PORT_BACNET_IP = 47808  # 0xBAC0
PORT_IEC104 = 2404
PORT_OPC_UA = 4840

# Standard IT Ports
PORT_DNS = 53
PORT_DHCP_SERVER = 67
PORT_DHCP_CLIENT = 68
PORT_HTTP = 80
PORT_NTP = 123
PORT_NETBIOS_NS = 137
PORT_NETBIOS_DGM = 138
PORT_NETBIOS_SSN = 139
PORT_HTTPS = 443
PORT_SMB = 445

class ProtocolInsight:
    """Represents protocol-specific extracted metadata."""
    def __init__(self, protocol: str):
        self.protocol = protocol
        self.function_codes: Dict[str, int] = {}
        self.operations: Dict[str, int] = {}
        self.unit_ids: set = set()
        self.device_identifiers: set = set()
        self.exception_codes: Dict[str, int] = {}
        self.service_codes: Dict[str, int] = {}
        self.object_types: Dict[str, int] = {}
        self.asdu_types: Dict[str, int] = {}
        self.opcua_messages: Dict[str, int] = {}
        self.details: list = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "function_codes": self.function_codes,
            "operations": self.operations,
            "unit_ids": sorted(list(self.unit_ids)),
            "device_identifiers": sorted(list(self.device_identifiers)),
            "exception_codes": self.exception_codes,
            "service_codes": self.service_codes,
            "object_types": self.object_types,
            "asdu_types": self.asdu_types,
            "opcua_messages": self.opcua_messages,
            "details": self.details[-50:]  # keep recent details
        }
