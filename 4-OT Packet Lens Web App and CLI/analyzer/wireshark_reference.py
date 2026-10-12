"""Wireshark/TShark-aligned capture counts.

TShark is the headless Wireshark dissector, not a separate home-grown protocol
parser. Running it on the original capture supports TCP reassembly and
multiple protocol messages in one frame. No packet payloads leave the machine.

Two different units of measurement are intentionally reported:
* `packet_classifications`: ONE label per captured frame, for the pie chart.
* `display_filter_packet_counts`: count of frames with each protocol in frame.protocols;
  these overlap by design (TCP and Modbus may both be true for one frame).
* `outer_transport_packet_counts`: FIRST decoded transport protocol per frame;
  unlike presence counts, this does not double count embedded UDP in ICMP.
* `function_code_occurrences`: each decoded field occurrence, even when
  multiple Modbus PDUs share a single TCP frame.
"""
from collections import Counter
import os
import shutil
import subprocess
import tempfile
from typing import Optional

from .protocols.modbus import MODBUS_FUNCTIONS, MODBUS_EXCEPTIONS
from .protocols.s7comm import S7_FUNCTIONS


PROTOCOL_TAGS = {
    "modbus": "Modbus/TCP",
    "mbtcp": "Modbus/TCP framing only",
    "s7comm": "S7comm",
    "s7comm-plus": "S7comm Plus",
    "cotp": "ISO-on-TCP (COTP)",
    "tpkt": "TPKT framing",
    "enip": "EtherNet/IP",
    "dnp3": "DNP3",
    "bacapp": "BACnet/IP",
    "iec60870_104": "IEC 60870-5-104",
    "opcua": "OPC UA",
    "dns": "DNS",
    "dhcp": "DHCP",
    "bootp": "DHCP",
    "nbns": "NetBIOS-NS",
    "http": "HTTP",
    "tls": "HTTPS/TLS",
    "arp": "ARP",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "udp": "UDP",
    "tcp": "TCP",
    "ipv6": "IPv6",
    "ip": "IPv4",
}
# Choose deepest relevant dissector when constructing exclusive packet classes.
LABEL_PRIORITY = [
    "modbus", "mbtcp", "s7comm", "s7comm-plus", "enip", "dnp3", "bacapp",
    "iec60870_104", "opcua", "cotp", "tpkt", "dns", "dhcp", "bootp", "nbns",
    "http", "tls", "arp", "icmp", "icmpv6", "udp", "tcp", "ipv6", "ip",
]
# The filter's protocol name is identical to the string used in Wireshark's
# display filter bar. `mbtcp` and `modbus` are intentionally distinct.
DISPLAY_FILTERS = [
    "modbus", "mbtcp", "s7comm", "tpkt", "cotp", "enip", "dnp3", "bacapp",
    "iec60870_104", "opcua", "dns", "tcp", "udp", "arp", "icmp", "icmpv6",
]


def find_tshark() -> Optional[str]:
    """Locate tshark.exe even if Wireshark was not added to Windows PATH."""
    p = os.environ.get("OT_PACKET_LENS_TSHARK")
    if p and os.path.isfile(p):
        return p
    exe = shutil.which("tshark") or shutil.which("tshark.exe")
    if exe:
        return exe
    for base in [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")]:
        if base:
            p = os.path.join(base, "Wireshark", "tshark.exe")
            if os.path.isfile(p):
                return p
    return None


def _parse_int(token):
    token = token.strip()
    if not token:
        return None
    try:
        # TShark can output 4, 0x04, or '04' depending on versions/format.
        return int(token, 16) if token.lower().startswith("0x") else int(token, 10)
    except ValueError:
        return None


def _code_counts(raw, names, base_exceptions=False):
    result = Counter()
    for token in raw.split(","):
        code = _parse_int(token)
        if code is None:
            continue
        if base_exceptions and code & 0x80:
            base = code & 0x7f
            label = f"Exception response to {names.get(base, f'function {base}')} (0x{code:02X})"
        else:
            label = names.get(code, f"Unknown (0x{code:02X})")
        result[label] += 1
    return result


# TShark field layout. Use one streaming pass for every capture, regardless of filename.
TSHARK_FIELDS = (
    "_ws.col.protocol", "frame.protocols", "modbus.func_code",
    "s7comm.param.func", "frame.number", "ip.src", "modbus.exception_code",
    "s7comm.header.rosctr", "enip.command", "dnp3.al.func", "mbtcp.unit_id",
)
S7_ROSCTR = {1: "Job (Request)", 2: "Ack", 3: "Ack-Data (Response)", 7: "Userdata"}
ENIP_COMMANDS = {0: "NOP", 4: "ListServices", 99: "ListIdentity", 101: "ListInterfaces", 102: "RegisterSession", 103: "UnregisterSession", 111: "SendRRData", 112: "SendUnitData", 115: "IndicateStatus", 116: "Cancel"}


def _values(raw):
    """All field occurrences, NOT frame counts; empty tokens are ignored."""
    return [n for t in raw.split(",") if (n := _parse_int(t)) is not None]


def _summarize_line(line, exclusive, filter_counts, fc_counts, s7_counts, extra=None):
    # Preserve the simple five-column test interface; full capture uses 11 fields.
    fields = line.rstrip("\r\n").split("\t")
    fields.extend([""] * (len(TSHARK_FIELDS) - len(fields)))
    protocol_col, protocol_stack, modbus_fcs, s7_fcs = fields[:4]
    stack = [t for t in protocol_stack.casefold().split(":") if t]
    names = set(stack)
    names.discard("")
    for k in DISPLAY_FILTERS:
        if k in names:
            filter_counts[k] += 1
    label = next((PROTOCOL_TAGS[tag] for tag in LABEL_PRIORITY if tag in names), None)
    # Other/Undecoded instead of the GUI's environment-dependent Info column.
    exclusive[label or "Other/Undecoded"] += 1
    fc_counts.update(_code_counts(modbus_fcs, MODBUS_FUNCTIONS, base_exceptions=True))
    s7_counts.update(_code_counts(s7_fcs, S7_FUNCTIONS))
    if extra is None:
        return
    # Count the first decoded outer transport in the stack, not every nested
    # protocol. In Mystery3, ICMP errors carry an inner UDP header; Wireshark's
    # display filter `udp` legitimately matches both outer and encapsulated UDP.
    # Those frames must NOT also be counted as outer UDP transport packets.
    for tag in stack:
        if tag in {"tcp", "udp", "icmp", "icmpv6", "arp"}:
            extra["outer_transport_packet_counts"][tag] += 1
            break
    src_ip, exception_raw, rosctr_raw, enip_raw, dnp_raw, unit_raw = fields[5:11]
    # Exception codes are separate decoded TShark fields. A raw Modbus FC
    # alone is NOT proof of an exception (nor is a parser-estimated flag).
    exc = _values(exception_raw)
    if exc:
        extra["modbus_exception_codes"].update(
            MODBUS_EXCEPTIONS.get(n, f"Unknown exception 0x{n:02X}") for n in exc
        )
        if src_ip and "," not in src_ip:
            extra["modbus_exception_source_ips"][src_ip] += len(exc)
        extra["modbus_exception_frames"] += 1
    rosctrs = _values(rosctr_raw)
    funcs = _values(s7_fcs)
    extra["s7_rosctr"].update(S7_ROSCTR.get(n, f"ROSCTR 0x{n:02X}") for n in rosctrs)
    # Only count decoded S7 job request functions for the source IP. We must
    # not conflate retransmitted raw TCP payloads with decoded S7 requests.
    # If a frame contains multiple unequal field arrays, correspondence
    # cannot be proven, so mark it as ambiguous instead of guessing.
    if src_ip and "," not in src_ip and funcs and rosctrs:
        if len(funcs) == len(rosctrs):
            for fcode, kind in zip(funcs, rosctrs):
                name = S7_FUNCTIONS.get(fcode, f"Unknown (0x{fcode:02X})")
                if kind == 1:
                    extra["s7_job_functions_by_src_ip"][src_ip][name] += 1
                elif kind == 3:
                    extra["s7_response_functions_by_src_ip"][src_ip][name] += 1
        else:
            extra["s7_ambiguous_field_frames"] += 1
    extra["enip_commands"].update(ENIP_COMMANDS.get(n, f"Command 0x{n:04X}") for n in _values(enip_raw))
    extra["dnp3_functions"].update(f"Function 0x{n:02X}" for n in _values(dnp_raw))
    extra["modbus_unit_ids"].update(_values(unit_raw))


def analyze_with_tshark(pcap_path, tshark_path=None, progress_callback=None):
    """Stream exact Wireshark-dissected field occurrences without RAM-heavy JSON.

    Raises RuntimeError if TShark failed. The caller must not overwrite its
    own counts with a partial/failed reference result.
    """
    exe = tshark_path or find_tshark()
    if not exe:
        raise FileNotFoundError(
            "TShark not found. Install Wireshark with the TShark component, "
            "or set OT_PACKET_LENS_TSHARK to the full tshark.exe path."
        )
    procver = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20)
    if procver.returncode:
        raise RuntimeError("Could not read TShark version: " + procver.stderr[:300])
    version = (procver.stdout or "").splitlines()[0].strip()
    command = [exe, "-n", "-r", os.path.abspath(pcap_path), "-T", "fields"]
    for field in TSHARK_FIELDS:
        command.extend(("-e", field))
    command.extend(("-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"))
    classes = Counter()
    counts = Counter()
    mb_functions = Counter()
    s7_functions = Counter()
    n = 0
    extra = {"modbus_exception_codes": Counter(), "modbus_exception_source_ips": Counter(),
             "modbus_exception_frames": 0, "s7_rosctr": Counter(), "enip_commands": Counter(),
             "dnp3_functions": Counter(), "modbus_unit_ids": Counter(),
             "outer_transport_packet_counts": Counter(),
             "s7_job_functions_by_src_ip": {}, "s7_response_functions_by_src_ip": {},
             "s7_ambiguous_field_frames": 0}
    from collections import defaultdict
    extra["s7_job_functions_by_src_ip"] = defaultdict(Counter)
    extra["s7_response_functions_by_src_ip"] = defaultdict(Counter)
    # Avoid PIPE stderr deadlocks on captures containing numerous malformed frames.
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                   text=True, encoding="utf-8", errors="replace", bufsize=1)
        try:
            for line in process.stdout:
                _summarize_line(line, classes, counts, mb_functions, s7_functions, extra)
                n += 1
                if progress_callback and n % 50000 == 0:
                    progress_callback(n, os.path.getsize(pcap_path), f"Wireshark dissection: {n:,} frames...")
        finally:
            process.stdout.close()
        rc = process.wait()
        if rc:
            errors.seek(0)
            raise RuntimeError(f"TShark failed (exit {rc}): {errors.read(1200)}")
    return {
        "source": "Wireshark/TShark dissector",
        "version": version,
        "packet_count": n,
        "packet_classifications": dict(classes.most_common()),
        "display_filter_packet_counts": dict(counts.most_common()),
        "outer_transport_packet_counts": dict(extra["outer_transport_packet_counts"].most_common()),
        "function_code_occurrences": {
            "Modbus/TCP": dict(mb_functions.most_common()),
            "S7comm": dict(s7_functions.most_common()),
        },
        "decoded_insights": {
            "modbus_exception_codes": dict(extra["modbus_exception_codes"].most_common()),
            "modbus_exception_source_ips": dict(extra["modbus_exception_source_ips"].most_common()),
            "modbus_exception_frames": extra["modbus_exception_frames"],
            "s7_rosctr": dict(extra["s7_rosctr"].most_common()),
            "s7_job_functions_by_src_ip": {ip: dict(v) for ip, v in extra["s7_job_functions_by_src_ip"].items()},
            "s7_response_functions_by_src_ip": {ip: dict(v) for ip, v in extra["s7_response_functions_by_src_ip"].items()},
            "s7_ambiguous_field_frames": extra["s7_ambiguous_field_frames"],
            "enip_commands": dict(extra["enip_commands"].most_common()),
            "dnp3_functions": dict(extra["dnp3_functions"].most_common()),
            "modbus_unit_ids": sorted(extra["modbus_unit_ids"]),
        },
        "comparison_note": (
            "Exclusive chart classes choose one protocol per frame. Display-filter "
            "counts overlap; the first decoded outer transport in frame.protocols "
            "does not include inner UDP inside ICMP. Function codes count decoded "
            "field occurrences, not distinct network packets or guaranteed "
            "successfully executed operations."
        ),
    }
