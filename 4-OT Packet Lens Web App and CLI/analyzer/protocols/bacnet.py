"""
BACnet/IP (Building Automation and Control Networks) Inspector and Dissector.
Supports BVLL, NPDU, and APDU decoding.
"""

from typing import Dict, Any, Optional

BVLL_FUNCTIONS = {
    0x00: "BVLC-Result",
    0x01: "Write-BDT",
    0x02: "Read-BDT",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secured-BVLL"
}

BACNET_APDU_TYPES = {
    0: "Confirmed-Request",
    1: "Unconfirmed-Request",
    2: "Simple-ACK",
    3: "Complex-ACK",
    4: "Segment-ACK",
    5: "Error",
    6: "Reject",
    7: "Abort"
}

BACNET_SERVICES_CONFIRMED = {
    0: "AcknowledgeAlarm",
    1: "ConfirmedCOVNotification",
    2: "ConfirmedEventNotification",
    5: "SubscribeCOV",
    6: "AtomicReadFile",
    7: "AtomicWriteFile",
    12: "ReadProperty",
    14: "ReadPropertyMultiple",
    15: "WriteProperty",
    16: "WritePropertyMultiple",
    26: "Who-Has"
}

BACNET_SERVICES_UNCONFIRMED = {
    0: "I-Am",
    1: "I-Have",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    8: "Who-Is"
}

BACNET_OBJECT_TYPES = {
    0: "Analog Input",
    1: "Analog Output",
    2: "Analog Value",
    3: "Binary Input",
    4: "Binary Output",
    5: "Binary Value",
    8: "Device",
    17: "Schedule",
    19: "Trend Log"
}

def parse_bacnet(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses BACnet/IP frame.
    BVLL Header: [0x81, function, len_hi, len_lo]
    """
    if len(payload) < 4:
        return None

    if payload[0] != 0x81:
        return None

    bvll_fn = payload[1]
    bvll_len = int.from_bytes(payload[2:4], 'big')
    if bvll_len != len(payload) and bvll_len != len(payload) + 4: # some captures have small pad
        if bvll_fn not in BVLL_FUNCTIONS:
            return None

    bvll_name = BVLL_FUNCTIONS.get(bvll_fn, f"BVLL 0x{bvll_fn:02X}")

    npdu_offset = 4
    if bvll_fn == 0x04: # Forwarded-NPDU has 6-byte originating IP/port
        npdu_offset = 10

    if len(payload) <= npdu_offset + 1:
        return {
            "protocol": "BACnet/IP",
            "bvll_function": bvll_name,
            "is_request": False,
            "is_response": False
        }

    # NPDU Header: Version (0x01), Control
    npdu_version = payload[npdu_offset]
    if npdu_version != 0x01:
        return None

    npdu_ctrl = payload[npdu_offset + 1]
    apdu_offset = npdu_offset + 2

    # If DNET/DLEN present (bit 5)
    if npdu_ctrl & 0x20:
        if len(payload) > apdu_offset + 2:
            dlen = payload[apdu_offset + 2]
            apdu_offset += 3 + dlen

    # If SNET/SLEN present (bit 3)
    if npdu_ctrl & 0x08:
        if len(payload) > apdu_offset + 2:
            slen = payload[apdu_offset + 2]
            apdu_offset += 3 + slen

    apdu_type_name = None
    service_name = None
    is_request = False
    is_response = False
    device_id = None

    if len(payload) > apdu_offset:
        apdu_byte0 = payload[apdu_offset]
        pdu_type = (apdu_byte0 >> 4) & 0x0F
        apdu_type_name = BACNET_APDU_TYPES.get(pdu_type, f"APDU Type {pdu_type}")

        if pdu_type == 0:  # Confirmed-Request
            is_request = True
            # byte 1: max-segments/max-APDU, byte 2: invoke-id, byte 3: service-choice
            if len(payload) > apdu_offset + 3:
                svc = payload[apdu_offset + 3]
                service_name = BACNET_SERVICES_CONFIRMED.get(svc, f"Confirmed Service {svc}")
        elif pdu_type == 1:  # Unconfirmed-Request
            is_request = True
            if len(payload) > apdu_offset + 1:
                svc = payload[apdu_offset + 1]
                service_name = BACNET_SERVICES_UNCONFIRMED.get(svc, f"Unconfirmed Service {svc}")
                if svc == 0:  # I-Am
                    is_response = True
                    is_request = False
        elif pdu_type in [2, 3]:  # ACKs
            is_response = True
            if pdu_type == 3 and len(payload) > apdu_offset + 2:
                svc = payload[apdu_offset + 2]
                service_name = BACNET_SERVICES_CONFIRMED.get(svc, f"ACK Service {svc}")
        elif pdu_type in [5, 6, 7]:
            is_response = True
            service_name = apdu_type_name

    return {
        "protocol": "BACnet/IP",
        "bvll_function": bvll_name,
        "apdu_type": apdu_type_name,
        "service_name": service_name,
        "is_request": is_request,
        "is_response": is_response
    }
