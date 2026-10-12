"""
OPC UA (Open Platform Communications Unified Architecture) Inspector and Dissector.
Supports Binary Protocol connection handshake, HEL/ACK, OPN/CLO, and MSG frames.
"""

from typing import Dict, Any, Optional

OPCUA_MSG_TYPES = {
    b"HEL": "Hello (Client Connection Request)",
    b"ACK": "Acknowledge (Server Connection Response)",
    b"ERR": "Error",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
    b"MSG": "User Message / Service Data"
}

def parse_opcua(payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """
    Parses OPC UA binary protocol header.
    Header: [Type (3B), ChunkType (1B), MessageSize (4B LE)]
    """
    if len(payload) < 8:
        return None

    msg_type_raw = payload[0:3]
    if msg_type_raw not in OPCUA_MSG_TYPES:
        return None

    chunk_type = chr(payload[3]) if 32 <= payload[3] <= 126 else '?'
    msg_size = int.from_bytes(payload[4:8], 'little')
    if msg_size < 8 or (msg_size > len(payload) + 4 and len(payload) < 32):
        return None

    msg_type_desc = OPCUA_MSG_TYPES[msg_type_raw]
    endpoint_url = None
    is_request = (msg_type_raw in [b"HEL", b"CLO"]) or (dport == 4840)
    is_response = (msg_type_raw in [b"ACK", b"ERR"]) or (sport == 4840)

    # Decode Endpoint URL from HEL message
    if msg_type_raw == b"HEL" and len(payload) >= 32:
        url_len = int.from_bytes(payload[24:28], 'little')
        if 0 < url_len <= len(payload) - 28:
            try:
                endpoint_url = payload[28:28+url_len].decode('utf-8', errors='ignore')
            except Exception:
                pass

    return {
        "protocol": "OPC UA",
        "message_type": msg_type_raw.decode('ascii', errors='ignore'),
        "message_desc": msg_type_desc,
        "chunk_type": chunk_type,
        "message_size": msg_size,
        "endpoint_url": endpoint_url,
        "is_request": is_request,
        "is_response": is_response
    }
