"""
Fast MAC OUI Vendor Lookup Module
Contains an extensive dictionary of industrial OT and enterprise IT MAC OUI prefixes.
"""

# Dictionary of MAC prefixes (normalized 6-hex uppercase without colons) -> Vendor Name
KNOWN_OUIS = {
    # Industrial Automation - Siemens
    "001C06": "Siemens AG",
    "286336": "Siemens AG",
    "000E8C": "Siemens AG",
    "080006": "Siemens AG",
    "001B1B": "Siemens AG",
    "000EC6": "Siemens AG",
    "001F34": "Siemens AG",
    "0002A5": "Siemens AG",
    "000874": "Rockwell Automation",
    "0000BC": "Rockwell Automation",
    "001D9C": "Rockwell Automation",
    "0080F4": "Rockwell Automation / Schneider",
    "002046": "Rockwell Automation",
    "0005CD": "Rockwell Automation",
    "001A84": "Schneider Electric",
    "000054": "Schneider Electric",
    "0000A3": "Schneider Electric",
    "000C29": "Schneider Electric / VMware",
    "00077C": "Westermo Network Technologies AB",
    "0090E8": "Moxa Technologies Inc.",
    "000A35": "Moxa Technologies Inc.",
    "000ADC": "Hirschmann Automation and Control GmbH",
    "008063": "Hirschmann Automation and Control GmbH",
    "000105": "Beckhoff Automation GmbH",
    "0030D6": "Beckhoff Automation GmbH",
    "00A045": "Phoenix Contact",
    "000CF0": "Phoenix Contact",
    "00000A": "Omron Corporation",
    "000D61": "Omron Corporation",
    "0030DE": "WAGO Kontakttechnik GmbH",
    "0000E2": "Yokogawa Electric Corp.",
    "00802A": "Yokogawa Electric Corp.",
    "00024B": "GE Energy",
    "000749": "GE Fanuc Automation",
    "000C68": "ABB Automation",
    "002494": "ABB Industrial Systems",
    "000070": "Mitsubishi Electric",
    "002692": "Mitsubishi Electric",
    "0000F6": "Honeywell",
    "00107B": "Honeywell",
    "000B32": "Advantech Co., Ltd.",
    "00D0C9": "Advantech Co., Ltd.",
    "000C88": "Red Lion Controls",
    "001859": "Belden",
    "001272": "B&R Industrial Automation",
    "002161": "Turck Multiprox",
    "000E4F": "Pilz GmbH & Co. KG",
    "000518": "Eaton Corporation",
    "001C6B": "Emerson Process Management",
    "000130": "Extreme Networks",
    
    # IT Hardware & Enterprise Vendors
    "54EE75": "Wistron InfoComm (Kunshan) Co., Ltd.",
    "7071BC": "Pegatron Corporation",
    "002354": "Pegatron Corporation",
    "0026B9": "Dell Inc.",
    "180373": "Dell Inc.",
    "D4BED9": "Dell Inc.",
    "001438": "Hewlett-Packard",
    "3C5282": "HP Inc.",
    "28CFE9": "Apple Inc.",
    "A483E7": "Apple Inc.",
    "BC9FEF": "Apple Inc.",
    "ACBC32": "Apple Inc.",
    "00000C": "Cisco Systems",
    "000142": "Cisco Systems",
    "000C29": "VMware, Inc.",
    "000569": "VMware, Inc.",
    "005056": "VMware, Inc.",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU / KVM Virtual Machine",
    "00155D": "Microsoft Hyper-V",
    "001A2B": "Intel Corporate",
    "001B21": "Intel Corporate",
    "E4B97A": "Intel Corporate",
    "00E04C": "Realtek Semiconductor Corp.",
    "0018E7": "Cameo Communications (D-Link)",
    "000D88": "D-Link Corporation",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Trading",
    "240AC4": "Espressif Systems",
    "A4CF12": "Espressif Systems",
}

def normalize_mac(mac: str) -> str:
    """Normalize MAC address string into lowercase colon-separated hex."""
    if not mac:
        return ""
    clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac.lower()

def get_vendor(mac: str) -> str:
    """Lookup MAC vendor from OUI."""
    if not mac:
        return "Unknown"
    norm = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(norm) < 6:
        return "Unknown"
    prefix = norm[:6]
    return KNOWN_OUIS.get(prefix, "Unknown / Generic")
