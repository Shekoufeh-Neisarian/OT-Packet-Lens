"""
IEC 60870-5-104 Telecontrol Protocol Inspector and Dissector.
Supports APCI (I, S, U formats) and ASDU parsing.
"""

from typing import Dict, Any, Optional

IEC104_ASDU_TYPES = {
    1: "M_SP_NA_1 (Single-point)",
    3: "M_DP_NA_1 (Double-point)",
    9: "M_ME_NA_1 (Measured normalized)",
    11: "M_ME_NB_1 (Measured scaled)",
    13: "M_ME_NC_1 (Measured short float)",
    30: "M_SP_TB_1 (Single-point with time tag)",
    31: "M_DP_TB_1 (Double-point with time tag)",
    36: "M_ME_TF_1 (Measured float with time tag)",
    45: "C_SC_NA_1 (Single command)",
    46: "C_DC_NA_1 (Double command)",
    48: "C_SE_NA_1 (Set-point normalized)",
    50: "C_SE_NC_1 (Set-point float)",
    100: "C_IC_NA_1 (General Interrogation)",
    101: "C_CI_NA_1 (Counter Interrogation)",
    103: "C_CS_NA_1 (Clock Synchronization)"
}

IEC104_COT = {
    1: "Periodic / Cyclic",
    2: "Background scan",
    3: "Spontaneous",
    6: "Activation",
    7: "Activation confirmation",
    8: "Deactivation",
    9: "Deactivation confirmation",
    10: "Activation termination",
    20: "General interrogation"
}

def parse_iec104(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses IEC 60870-5-104 APDU.
    APCI: [0x68, apdu_len, ctrl1, ctrl2, ctrl3, ctrl4]
    """
    if len(payload) < 6:
        return None

    if payload[0] != 0x68:
        return None

    apdu_len = payload[1]
    if apdu_len != len(payload) - 2 and apdu_len > len(payload):
        return None

    ctrl1 = payload[2]
    # Check frame format:
    # Bit 0 = 0 -> I-format
    # Bit 0 = 1, Bit 1 = 0 -> S-format
    # Bit 0 = 1, Bit 1 = 1 -> U-format
    if (ctrl1 & 0x01) == 0:
        apci_format = "I-format (Information Transfer)"
    elif (ctrl1 & 0x03) == 0x01:
        apci_format = "S-format (Supervisory)"
    else:
        # U-format
        u_type = []
        if ctrl1 & 0x04: u_type.append("STARTDT act")
        if ctrl1 & 0x08: u_type.append("STARTDT con")
        if ctrl1 & 0x10: u_type.append("STOPDT act")
        if ctrl1 & 0x20: u_type.append("STOPDT con")
        if ctrl1 & 0x40: u_type.append("TESTFR act")
        if ctrl1 & 0x80: u_type.append("TESTFR con")
        apci_format = f"U-format ({', '.join(u_type) if u_type else 'Control'})"

    asdu_type_id = None
    asdu_name = None
    cot_name = None
    coa = None
    is_request = False
    is_response = False

    if apci_format.startswith("I-format") and len(payload) >= 12:
        asdu_type_id = payload[6]
        asdu_name = IEC104_ASDU_TYPES.get(asdu_type_id, f"ASDU Type {asdu_type_id}")
        cot_val = payload[8] & 0x3F
        cot_name = IEC104_COT.get(cot_val, f"COT {cot_val}")
        coa = int.from_bytes(payload[10:12], 'little')

        # Commands are typically requests, telemetry is response
        if asdu_type_id >= 45 and asdu_type_id <= 103:
            is_request = True
        else:
            is_response = True
    else:
        is_request = (dport == 2404)
        is_response = (sport == 2404)

    return {
        "protocol": "IEC 60870-5-104",
        "apci_format": apci_format,
        "asdu_type": asdu_type_id,
        "asdu_name": asdu_name,
        "cot_name": cot_name,
        "common_address": coa,
        "is_request": is_request,
        "is_response": is_response
    }
