"""
Unified Protocol Dissection Dispatcher.
Inspects packet content independently of port numbers first, then uses ports as secondary context.
"""

from typing import Dict, Any, Optional
from .modbus import parse_modbus
from .s7comm import parse_s7comm
from .enip_cip import parse_enip_cip
from .dnp3 import parse_dnp3
from .bacnet import parse_bacnet
from .iec104 import parse_iec104
from .opcua import parse_opcua
from .it_protocols import (
    parse_dns,
    parse_dhcp,
    parse_netbios_name,
    parse_http,
    parse_tls_sni
)
from .common import (
    PORT_MODBUS,
    PORT_S7COMM,
    PORT_ETHERNET_IP_EXPLICIT,
    PORT_DNP3,
    PORT_BACNET_IP,
    PORT_IEC104,
    PORT_OPC_UA,
    PORT_DNS,
    PORT_DHCP_SERVER,
    PORT_DHCP_CLIENT,
    PORT_HTTP,
    PORT_HTTPS,
    PORT_NETBIOS_NS
)

def inspect_payload(payload: bytes, sport: int, dport: int, transport: str) -> Optional[Dict[str, Any]]:
    """
    Deep inspection of application payload independent of standard ports.
    Returns parsed dictionary or None.
    """
    if not payload:
        return None

    # 1. Modbus/TCP inspection
    modbus_res = parse_modbus(payload, sport, dport) if transport == "TCP" else None
    if modbus_res:
        return modbus_res

    # 2. Siemens S7comm inspection
    s7_res = parse_s7comm(payload, sport, dport) if transport == "TCP" else None
    if s7_res:
        return s7_res

    # 3. DNP3 inspection
    dnp3_res = parse_dnp3(payload, sport, dport)
    if dnp3_res:
        return dnp3_res

    # 4. BACnet/IP inspection
    bacnet_res = parse_bacnet(payload, sport, dport) if transport == "UDP" else None
    if bacnet_res:
        return bacnet_res

    # 5. EtherNet/IP & CIP inspection
    enip_res = parse_enip_cip(payload, sport, dport)
    if enip_res:
        return enip_res

    # 6. IEC 60870-5-104 inspection
    iec_res = parse_iec104(payload, sport, dport) if transport == "TCP" else None
    if iec_res:
        return iec_res

    # 7. OPC UA inspection
    opcua_res = parse_opcua(payload, sport, dport) if transport == "TCP" else None
    if opcua_res:
        return opcua_res

    # 8. IT Protocols: DNS
    if transport == "UDP" and (sport == PORT_DNS or dport == PORT_DNS):
        dns_res = parse_dns(payload)
        if dns_res:
            return dns_res

    # 9. DHCP
    if transport == "UDP" and (sport in [PORT_DHCP_SERVER, PORT_DHCP_CLIENT] or dport in [PORT_DHCP_SERVER, PORT_DHCP_CLIENT]):
        dhcp_res = parse_dhcp(payload)
        if dhcp_res:
            return dhcp_res

    # 10. NetBIOS Name Service
    if transport == "UDP" and (sport == PORT_NETBIOS_NS or dport == PORT_NETBIOS_NS):
        nb_res = parse_netbios_name(payload)
        if nb_res:
            return nb_res

    # 11. HTTP
    if transport == "TCP" and (sport == PORT_HTTP or dport == PORT_HTTP or len(payload) >= 10):
        http_res = parse_http(payload)
        if http_res:
            return http_res

    # 12. TLS / HTTPS SNI
    if transport == "TCP" and (sport == PORT_HTTPS or dport == PORT_HTTPS or payload.startswith(b"\x16\x03")):
        sni = parse_tls_sni(payload)
        if sni:
            return {
                "protocol": "HTTPS/TLS",
                "sni_hostname": sni,
                "is_request": (dport == 443),
                "is_response": (sport == 443)
            }
        elif sport == 443 or dport == 443:
            return {
                "protocol": "HTTPS/TLS",
                "is_request": (dport == 443),
                "is_response": (sport == 443)
            }

    # IMPORTANT: A TCP port is not proof that its application protocol was
    # decoded. Keep undecoded payloads as TCP/UDP, rather than polluting
    # verified protocol counts and device-operation statistics. Actual counts
    # after TCP reassembly come from the optional Wireshark/TShark pass.
    return None
