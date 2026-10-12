"""
EtherNet/IP and Common Industrial Protocol (CIP) Inspector and Dissector.
Supports encapsulation commands, CPF decoding, and CIP service analysis.
"""

from typing import Dict, Any, Optional

ENIP_COMMANDS = {
    0x0001: "NOP",
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnRegisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
    0x0072: "IndicateStatus",
    0x0073: "Cancel"
}

CIP_SERVICES = {
    0x01: "Get Attributes All",
    0x02: "Set Attributes All",
    0x03: "Get Attribute List",
    0x04: "Set Attribute List",
    0x0E: "Get Attribute Single",
    0x10: "Set Attribute Single",
    0x4C: "Read Tag Service",
    0x4D: "Write Tag Service",
    0x4E: "Forward Close",
    0x52: "Unconnected Send",
    0x54: "Forward Open",
    0x55: "Large Forward Open"
}

CIP_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x07: "General Purpose Discrete I/O",
    0x0E: "Programmable Logic Controller",
    0x10: "Position Controller",
    0x18: "Encoder",
    0x2B: "Generic Human-Machine Interface (HMI)"
}

def parse_enip_cip(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses EtherNet/IP Encapsulation Header (24 bytes) and CIP payload.
    """
    if len(payload) < 24:
        return None

    cmd = int.from_bytes(payload[0:2], 'little')
    # Validate command is a known EtherNet/IP command
    if cmd not in ENIP_COMMANDS:
        return None

    data_len = int.from_bytes(payload[2:4], 'little')
    session = int.from_bytes(payload[4:8], 'little')
    status = int.from_bytes(payload[8:12], 'little')

    cmd_name = ENIP_COMMANDS.get(cmd, f"Cmd 0x{cmd:04X}")
    is_response = (dport != 44818 and sport == 44818) or (status != 0 and session != 0)
    is_request = not is_response

    cip_service = None
    cip_service_name = None
    device_identity = None

    # Inspect CPF items if SendRRData (0x6F) or SendUnitData (0x70)
    if cmd in [0x006F, 0x0070] and len(payload) >= 30:
        # 24 header + 4 interface handle + 2 timeout = 30
        cpf_offset = 30 if cmd == 0x006F else 28
        if len(payload) >= cpf_offset + 2:
            item_count = int.from_bytes(payload[cpf_offset:cpf_offset+2], 'little')
            curr = cpf_offset + 2
            for _ in range(min(item_count, 4)):
                if curr + 4 > len(payload):
                    break
                type_id = int.from_bytes(payload[curr:curr+2], 'little')
                item_len = int.from_bytes(payload[curr+2:curr+4], 'little')
                curr += 4
                item_data = payload[curr:curr+item_len]
                curr += item_len

                # Type 0x00B2 = Unconnected Data, 0x00B1 = Connected Data
                if type_id in [0x00B2, 0x00B1] and len(item_data) >= 1:
                    raw_svc = item_data[0]
                    is_reply = bool(raw_svc & 0x80)
                    svc_code = raw_svc & 0x7F
                    cip_service = svc_code
                    cip_service_name = CIP_SERVICES.get(svc_code, f"CIP Service 0x{svc_code:02X}")
                    if is_reply:
                        cip_service_name += " [Reply]"

    # Inspect ListIdentity (0x0063) response for device name / product name
    if cmd == 0x0063 and len(payload) > 24:
        # Attempt to find ASCII strings of device names (e.g. Rockwell Logix controller)
        ascii_parts = []
        for b in payload[24:]:
            if 32 <= b <= 126:
                ascii_parts.append(chr(b))
            elif ascii_parts and len(ascii_parts) >= 4:
                s = "".join(ascii_parts).strip()
                if any(k in s for k in ["Logix", "1756", "1769", "Allen-Bradley", "Rockwell", "CIP", "Micro"]):
                    device_identity = s
                    break
                ascii_parts = []
            else:
                ascii_parts = []

    return {
        "protocol": "EtherNet/IP",
        "command": cmd,
        "command_name": cmd_name,
        "session_handle": hex(session),
        "status": status,
        "cip_service": cip_service,
        "cip_service_name": cip_service_name,
        "device_identity": device_identity,
        "is_request": is_request,
        "is_response": is_response
    }
