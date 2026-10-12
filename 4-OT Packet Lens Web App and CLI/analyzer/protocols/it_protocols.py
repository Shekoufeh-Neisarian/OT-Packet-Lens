"""
IT and Network Management Protocol Parsers.
Includes DNS, DHCP, NetBIOS, HTTP, TLS SNI, ARP, and ICMP analyzers.
"""

from typing import Dict, Any, Optional
import socket
import dpkt

def parse_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse DNS query/response payload."""
    try:
        dns = dpkt.dns.DNS(payload)
        queries = [q.name for q in getattr(dns, 'qd', []) if hasattr(q, 'name')]
        answers = []
        for an in getattr(dns, 'an', []):
            if hasattr(an, 'name'):
                if getattr(an, 'type', None) == dpkt.dns.DNS_A and hasattr(an, 'ip'):
                    answers.append(f"{an.name} -> {socket.inet_ntoa(an.ip)}")
                elif getattr(an, 'type', None) == dpkt.dns.DNS_PTR and hasattr(an, 'ptrname'):
                    answers.append(f"{an.name} -> {an.ptrname}")
                else:
                    answers.append(an.name)

        is_response = bool(getattr(dns, 'qr', 0))
        return {
            "protocol": "DNS",
            "is_request": not is_response,
            "is_response": is_response,
            "queries": queries,
            "answers": answers,
            "rcode": getattr(dns, 'rcode', 0)
        }
    except Exception:
        return None

def parse_dhcp(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse DHCP payload and extract hostname option 12 and vendor class option 60."""
    try:
        dhcp = dpkt.dhcp.DHCP(payload)
        hostname = None
        vendor_class = None
        msg_type = None

        for opt in getattr(dhcp, 'opts', []):
            opt_code = opt[0]
            opt_data = opt[1]
            if opt_code == 53 and len(opt_data) >= 1:
                # DHCP Message Type
                msg_types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release"}
                msg_type = msg_types.get(opt_data[0], f"Type {opt_data[0]}")
            elif opt_code == 12:
                # Hostname
                hostname = opt_data.decode('ascii', errors='ignore').strip()
            elif opt_code == 60:
                # Vendor class identifier
                vendor_class = opt_data.decode('ascii', errors='ignore').strip()

        return {
            "protocol": "DHCP",
            "msg_type": msg_type,
            "hostname": hostname,
            "vendor_class": vendor_class,
            "is_request": (msg_type in ["Discover", "Request"]),
            "is_response": (msg_type in ["Offer", "ACK"])
        }
    except Exception:
        return None

def parse_netbios_name(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse NetBIOS Name Service (NBNS) packets on UDP port 137 to extract hostnames."""
    if len(payload) < 12:
        return None
    try:
        # Standard NBNS header is identical to DNS header
        dns = dpkt.dns.DNS(payload)
        names = []
        for q in getattr(dns, 'qd', []):
            raw_name = getattr(q, 'name', '')
            # NetBIOS names are encoded in first-level encoded half-ASCII representation
            # or already dotted
            decoded = decode_netbios_name(raw_name)
            if decoded:
                names.append(decoded)
        if names:
            return {
                "protocol": "NetBIOS-NS",
                "names": names,
                "is_request": not bool(getattr(dns, 'qr', 0)),
                "is_response": bool(getattr(dns, 'qr', 0))
            }
    except Exception:
        pass
    return None

def decode_netbios_name(encoded: str) -> Optional[str]:
    """Decodes NetBIOS 32-character half-ASCII encoded name (RFC 1001/1002)."""
    if not encoded:
        return None
    parts = encoded.split('.')[0]
    if len(parts) == 32:
        try:
            chars = []
            for i in range(0, 32, 2):
                c1 = ord(parts[i]) - 0x41
                c2 = ord(parts[i+1]) - 0x41
                chars.append(chr((c1 << 4) | c2))
            decoded = "".join(chars).strip()
            if decoded and all(c.isprintable() for c in decoded):
                return decoded
        except Exception:
            pass
    clean = encoded.strip()
    return clean if clean and clean.isprintable() else None

def parse_http(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse HTTP request/response methods, hostnames, and user agents."""
    if len(payload) < 10:
        return None
    try:
        text = payload[:500].decode('latin1', errors='ignore')
        first_line = text.split('\r\n')[0]
        methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "]
        for m in methods:
            if first_line.startswith(m):
                parts = first_line.split(' ')
                method = parts[0]
                uri = parts[1] if len(parts) > 1 else "/"
                # Extract Host header
                host = None
                for line in text.split('\r\n'):
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                return {
                    "protocol": "HTTP",
                    "is_request": True,
                    "is_response": False,
                    "method": method,
                    "uri": uri,
                    "host": host
                }
        if first_line.startswith("HTTP/1.") or first_line.startswith("HTTP/2."):
            status_parts = first_line.split(' ')
            status_code = status_parts[1] if len(status_parts) > 1 else ""
            server = None
            for line in text.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            return {
                "protocol": "HTTP",
                "is_request": False,
                "is_response": True,
                "status_code": status_code,
                "server": server
            }
    except Exception:
        pass
    return None

def parse_tls_sni(payload: bytes) -> Optional[str]:
    """Parse TLS Client Hello to extract Server Name Indication (SNI)."""
    if len(payload) < 43 or payload[0] != 0x16:  # Handshake
        return None
    try:
        # Handshake Type 0x01 == Client Hello
        if payload[5] != 0x01:
            return None
        # Skip fixed fields to reach extensions
        curr = 43  # 5 record + 4 hs + 2 ver + 32 random
        if curr >= len(payload): return None
        session_id_len = payload[curr]
        curr += 1 + session_id_len
        if curr + 2 > len(payload): return None
        cipher_len = int.from_bytes(payload[curr:curr+2], 'big')
        curr += 2 + cipher_len
        if curr >= len(payload): return None
        comp_len = payload[curr]
        curr += 1 + comp_len
        if curr + 2 > len(payload): return None
        ext_len = int.from_bytes(payload[curr:curr+2], 'big')
        curr += 2
        ext_end = curr + ext_len
        while curr + 4 <= ext_end and curr + 4 <= len(payload):
            ext_type = int.from_bytes(payload[curr:curr+2], 'big')
            e_len = int.from_bytes(payload[curr+2:curr+4], 'big')
            curr += 4
            if ext_type == 0x0000:  # SNI Extension
                if curr + 5 <= len(payload):
                    server_name_len = int.from_bytes(payload[curr+3:curr+5], 'big')
                    sni = payload[curr+5:curr+5+server_name_len].decode('ascii', errors='ignore')
                    return sni
            curr += e_len
    except Exception:
        pass
    return None
