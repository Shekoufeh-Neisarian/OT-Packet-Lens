"""
Modbus/TCP Protocol Inspector and Dissector.
Inspects payload independent of port using Modbus Application Protocol (MBAP) header validation.
"""

from typing import Dict, Any, Optional

MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface (Read Device ID)"
}

MODBUS_EXCEPTIONS = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Slave Device Failure",
    5: "Acknowledge",
    6: "Slave Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond"
}

def parse_modbus(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses Modbus/TCP frame from payload bytes.
    MBAP Header:
      0-1: Transaction Identifier
      2-3: Protocol Identifier (0 = Modbus)
      4-5: Length (following bytes)
      6:   Unit Identifier
      7:   Function Code
    """
    if len(payload) < 8:
        return None

    proto_id = int.from_bytes(payload[2:4], 'big')
    # Modbus protocol ID in MBAP is strictly 0
    if proto_id != 0:
        return None

    length = int.from_bytes(payload[4:6], 'big')
    # MBAP length includes Unit ID + PDU; verify the *whole* ADU exists.
    # A TCP segment with only an MBAP-looking prefix must not be counted as a
    # fully decoded Modbus function. Reassembled PDUs are handled by TShark.
    if length < 2 or length > 254 or len(payload) < 6 + length:
        return None

    trans_id = int.from_bytes(payload[0:2], 'big')
    unit_id = payload[6]
    fc_raw = payload[7]

    is_exception = bool(fc_raw & 0x80)
    fc = fc_raw & 0x7F
    fc_name = MODBUS_FUNCTIONS.get(fc, f"User-Defined / Unknown (0x{fc:02X})")

    # Direction cannot be established from an arbitrary port alone; return
    # unknown rather than inventing request/response counts for nonstandard
    # ports. Exception responses are always responses.
    is_request = (dport == 502) and not is_exception
    is_response = bool(is_exception or (sport == 502))

    exception_desc = None
    if is_exception:
        exc_code = payload[8] if len(payload) > 8 else 0
        exception_desc = MODBUS_EXCEPTIONS.get(exc_code, f"Unknown Exception ({exc_code})")

    # Extract device identifiers or register ranges if present
    extra_info = {}
    if fc == 43 and len(payload) >= 10:
        # Encapsulated Interface Transport (MEI type 0x0E = Read Device ID)
        mei_type = payload[8]
        if mei_type == 0x0E:
            extra_info["mei_type"] = "Read Device ID"
            # Attempt to extract ASCII device ID strings
            ascii_parts = []
            for b in payload[10:]:
                if 32 <= b <= 126:
                    ascii_parts.append(chr(b))
            if ascii_parts:
                extra_info["device_info"] = "".join(ascii_parts).strip()
    elif is_request and fc in [1, 2, 3, 4, 15, 16] and len(payload) >= 12:
        # Start Address and Quantity
        start_addr = int.from_bytes(payload[8:10], 'big')
        quantity = int.from_bytes(payload[10:12], 'big')
        extra_info["start_address"] = start_addr
        extra_info["quantity"] = quantity

    return {
        "protocol": "Modbus/TCP",
        "trans_id": trans_id,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": fc_name,
        "is_request": is_request,
        "is_response": is_response,
        "is_exception": is_exception,
        "exception_desc": exception_desc,
        "extra_info": extra_info
    }
