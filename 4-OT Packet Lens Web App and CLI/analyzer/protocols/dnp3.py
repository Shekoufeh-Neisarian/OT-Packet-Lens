"""
DNP3 (Distributed Network Protocol 3) Inspector and Dissector.
Supports Data Link layer header, Transport layer, and Application Layer decoding.
"""

from typing import Dict, Any, Optional

DNP3_APP_FUNCTIONS = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    7: "Immediate Freeze",
    8: "Immediate Freeze No Ack",
    9: "Freeze and Clear",
    10: "Freeze and Clear No Ack",
    11: "Freeze with Time",
    12: "Freeze with Time No Ack",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    19: "Save Configuration",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measurement",
    24: "Record Current Time",
    129: "Response",
    130: "Unsolicited Response",
    131: "Authenticating Response"
}

DNP3_LINK_FUNCTIONS_PRI = {
    0: "Reset Link States",
    1: "Reset User Process",
    2: "Test Link States",
    3: "Confirmed User Data",
    4: "Unconfirmed User Data",
    9: "Request Link Status"
}

DNP3_LINK_FUNCTIONS_SEC = {
    0: "ACK",
    1: "NACK",
    11: "Status of Link",
    14: "Not Supported"
}

def parse_dnp3(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses DNP3 frame.
    Header: [0x05, 0x64, len, ctrl, dst_lo, dst_hi, src_lo, src_hi, crc_lo, crc_hi]
    """
    if len(payload) < 10:
        return None

    # Check magic start bytes
    if payload[0] != 0x05 or payload[1] != 0x64:
        return None

    dl_len = payload[2]
    if dl_len < 5:
        return None

    ctrl = payload[3]
    dir_master = bool(ctrl & 0x80)
    prm_primary = bool(ctrl & 0x40)
    fc_link = ctrl & 0x0F

    link_fn = DNP3_LINK_FUNCTIONS_PRI.get(fc_link, f"LinkPri {fc_link}") if prm_primary else DNP3_LINK_FUNCTIONS_SEC.get(fc_link, f"LinkSec {fc_link}")

    dst_addr = int.from_bytes(payload[4:6], 'little')
    src_addr = int.from_bytes(payload[6:8], 'little')

    app_fn_code = None
    app_fn_name = None
    is_response = False
    is_request = False
    iin_flags = []

    # Application layer typically starts at offset 10 (after 10 bytes link header) + 1 byte transport header = 12
    if len(payload) >= 12:
        transport_hdr = payload[10]
        app_ctrl = payload[11]
        if len(payload) >= 13:
            app_fn_code = payload[12]
            app_fn_name = DNP3_APP_FUNCTIONS.get(app_fn_code, f"AppFunc 0x{app_fn_code:02X}")
            if app_fn_code in [129, 130, 131]:
                is_response = True
                # Parse Internal Indications (IIN) bytes at 13-14
                if len(payload) >= 15:
                    iin1 = payload[13]
                    iin2 = payload[14]
                    if iin1 & 0x01: iin_flags.append("All Stations")
                    if iin1 & 0x10: iin_flags.append("Need Time")
                    if iin1 & 0x20: iin_flags.append("Local Control")
                    if iin1 & 0x40: iin_flags.append("Device Trouble")
                    if iin1 & 0x80: iin_flags.append("Device Restart")
                    if iin2 & 0x01: iin_flags.append("Bad Function")
                    if iin2 & 0x02: iin_flags.append("Object Unknown")
                    if iin2 & 0x04: iin_flags.append("Parameter Error")
            else:
                is_request = True
    else:
        is_request = dir_master

    return {
        "protocol": "DNP3",
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "direction": "Master -> Outstation" if dir_master else "Outstation -> Master",
        "link_function": link_fn,
        "app_function_code": app_fn_code,
        "app_function_name": app_fn_name,
        "is_request": is_request,
        "is_response": is_response,
        "iin_flags": iin_flags
    }
