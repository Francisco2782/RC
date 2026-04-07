from datetime import datetime

from scapy.all import ARP, DHCP, DNS, ICMP, IP, TCP, UDP, Ether

from .models import PacketEvent


_DHCP_MESSAGE_TYPES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "Ack",
    6: "Nak",
    7: "Release",
    8: "Inform",
}


def _format_timestamp(raw_ts: float) -> str:
    return datetime.fromtimestamp(raw_ts).isoformat(timespec="milliseconds")


def _extract_dhcp_message(packet) -> str:
    if DHCP not in packet:
        return ""

    options = packet[DHCP].options
    for option in options:
        if isinstance(option, tuple) and option[0] == "message-type":
            value = option[1]
            if isinstance(value, str):
                return value.capitalize()
            return _DHCP_MESSAGE_TYPES.get(int(value), str(value))
    return ""


def parse_packet(packet, interface: str) -> PacketEvent:
    protocol = "UNKNOWN"
    summary = "Unknown packet"

    src_mac = "-"
    dst_mac = "-"
    src_ip = "-"
    dst_ip = "-"

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if ARP in packet:
        protocol = "ARP"
        op = packet[ARP].op
        summary = "ARP request" if op == 1 else "ARP reply" if op == 2 else f"ARP op={op}"
    elif DHCP in packet:
        protocol = "DHCP"
        msg_type = _extract_dhcp_message(packet)
        summary = f"DHCP {msg_type}" if msg_type else "DHCP"
    elif DNS in packet:
        protocol = "DNS"
        summary = "DNS query" if packet[DNS].qr == 0 else "DNS response"
    elif ICMP in packet:
        protocol = "ICMP"
        icmp_type = packet[ICMP].type
        if icmp_type == 8:
            summary = "ICMP echo request"
        elif icmp_type == 0:
            summary = "ICMP echo reply"
        else:
            summary = f"ICMP type={icmp_type}"
    elif TCP in packet:
        protocol = "TCP"
        flags = packet[TCP].sprintf("%TCP.flags%")
        summary = f"TCP {packet[TCP].sport} -> {packet[TCP].dport} flags={flags}"
    elif UDP in packet:
        protocol = "UDP"
        summary = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
    elif IP in packet:
        protocol = "IPv4"
        summary = "IPv4 packet"
    elif Ether in packet:
        protocol = "Ethernet"
        summary = "Ethernet frame"

    return PacketEvent(
        timestamp=_format_timestamp(float(packet.time)),
        interface=interface,
        protocol=protocol,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        size=len(bytes(packet)),
        summary=summary,
    )
