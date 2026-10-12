"""
Siemens S7comm and S7comm-Plus Protocol Inspector.
Inspects TPKT, COTP, and S7 PDU headers.
"""

from typing import Dict, Any, Optional

S7_ROSCTR = {
    1: "Job (Request)",
    2: "Ack",
    3: "Ack-Data (Response)",
    7: "UserData"
}

S7_FUNCTIONS = {
    0xF0: "Setup Communication",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload Block",
    0x1F: "End Upload",
    0x28: "PLC Control (Start CPU)",
    0x29: "PLC Stop",
    0x00: "CPU Functions / SZL"
}

S7_USERDATA_FUNCS = {
    0x01: "Read SZL (System Status List)",
    0x02: "Time Functions",
    0x03: "Cyclic Read",
    0x04: "Block Functions",
    0x05: "Security / Password"
}

def parse_s7comm(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses S7comm frame over TPKT/COTP.
    TPKT: [0x03, 0x00, len_hi, len_lo]
    COTP: [len, pdu_type, ...]
    S7: [0x32, rosctr, redun_hi, redun_lo, pdu_ref_hi, pdu_ref_lo, param_len_hi, param_len_lo, data_len_hi, data_len_lo]
    """
    if len(payload) < 7:
        return None

    # TPKT Header check (RFC 1006)
    if payload[0] != 0x03 or payload[1] != 0x00:
        return None

    tpkt_len = int.from_bytes(payload[2:4], 'big')
    if tpkt_len > len(payload) + 4 or tpkt_len < 7:
        return None

    # COTP
    cotp_len = payload[4]
    if 4 + 1 + cotp_len > len(payload):
        return None

    cotp_pdu_type = payload[5]
    cotp_desc = "DT (Data)" if (cotp_pdu_type & 0xF0) == 0xF0 else (
        "CR (Connection Request)" if cotp_pdu_type == 0xE0 else (
            "CC (Connection Confirm)" if cotp_pdu_type == 0xD0 else "COTP Other"
        )
    )

    s7_offset = 4 + 1 + cotp_len
    # If connection setup packet without S7 header
    if s7_offset >= len(payload):
        return {
            "protocol": "COTP / ISO-on-TCP",
            "tpkt_len": tpkt_len,
            "cotp_pdu": cotp_desc,
            "is_request": (dport == 102),
            "is_response": (sport == 102),
            "function_name": cotp_desc,
            "rosctr_desc": "ISO-on-TCP Connection"
        }

    # S7 Header check (Magic 0x32)
    if payload[s7_offset] != 0x32:
        return None

    s7_hdr = payload[s7_offset:]
    if len(s7_hdr) < 10:
        return None

    rosctr = s7_hdr[1]
    pdu_ref = int.from_bytes(s7_hdr[4:6], 'big')
    param_len = int.from_bytes(s7_hdr[6:8], 'big')
    data_len = int.from_bytes(s7_hdr[8:10], 'big')

    rosctr_desc = S7_ROSCTR.get(rosctr, f"Unknown ROSCTR ({rosctr})")
    is_request = (rosctr == 1) or (rosctr == 7 and dport == 102)
    is_response = (rosctr in [2, 3]) or (rosctr == 7 and sport == 102)

    error_code = 0
    param_offset = 10
    if rosctr in [2, 3] and len(s7_hdr) >= 12:
        error_code = int.from_bytes(s7_hdr[10:12], 'big')
        param_offset = 12

    fn_code = None
    fn_name = "Header Only"
    subfunc_name = None
    device_info = None

    if len(s7_hdr) > param_offset:
        fn_code = s7_hdr[param_offset]
        fn_name = S7_FUNCTIONS.get(fn_code, f"Func 0x{fn_code:02X}")

        # Check for UserData subfunctions
        if rosctr == 7 and len(s7_hdr) > param_offset + 3:
            subfn = s7_hdr[param_offset + 3]
            subfunc_name = S7_USERDATA_FUNCS.get(subfn, f"Subfn 0x{subfn:02X}")

    # Inspect for printable strings like order number / MLFB (e.g., 6ES7...)
    payload_str = payload.decode('ascii', errors='ignore')
    for token in ["6ES7", "CPU ", "VIPA", "SIMATIC", "S7-1200", "S7-1500", "S7-300", "S7-400"]:
        idx = payload_str.find(token)
        if idx != -1:
            snippet = payload_str[idx:idx+30].strip()
            device_info = "".join(c for c in snippet if c.isprintable())
            break

    return {
        "protocol": "S7comm",
        "rosctr": rosctr,
        "rosctr_desc": rosctr_desc,
        "pdu_ref": pdu_ref,
        "param_len": param_len,
        "data_len": data_len,
        "error_code": error_code,
        "function_code": fn_code,
        "function_name": fn_name,
        "subfunc_name": subfunc_name,
        "is_request": is_request,
        "is_response": is_response,
        "device_info": device_info
    }
