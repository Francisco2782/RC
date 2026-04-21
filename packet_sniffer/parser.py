from datetime import datetime

from scapy.all import ARP, BOOTP, DHCP, DNS, ICMP, IP, TCP, UDP, Ether

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


def _extract_flow_metadata(packet, protocol: str, src_ip: str, dst_ip: str, src_mac: str, dst_mac: str) -> tuple[str, str]:
    if protocol == "DNS" and DNS in packet and UDP in packet:
        transaction_id = int(packet[DNS].id)
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

        if packet[DNS].qr == 0:
            return "request", f"DNS:{src_ip}:{src_port}>{dst_ip}:{dst_port}:{transaction_id}"
        return "reply", f"DNS:{dst_ip}:{dst_port}>{src_ip}:{src_port}:{transaction_id}"

    if protocol == "ICMP" and ICMP in packet:
        icmp_id = int(getattr(packet[ICMP], "id", 0) or 0)
        icmp_seq = int(getattr(packet[ICMP], "seq", 0) or 0)
        if packet[ICMP].type == 8:
            return "request", f"ICMP:{src_ip}>{dst_ip}:{icmp_id}:{icmp_seq}"
        if packet[ICMP].type == 0:
            return "reply", f"ICMP:{dst_ip}>{src_ip}:{icmp_id}:{icmp_seq}"

    if protocol == "ARP" and ARP in packet:
        if packet[ARP].op == 1:
            return "request", f"ARP:{packet[ARP].psrc}>{packet[ARP].pdst}"
        if packet[ARP].op == 2:
            return "reply", f"ARP:{packet[ARP].pdst}>{packet[ARP].psrc}"

    if protocol == "DHCP" and BOOTP in packet:
        xid = int(packet[BOOTP].xid)
        msg_type = _extract_dhcp_message(packet)
        request_types = {"Discover", "Request", "Decline", "Release", "Inform"}
        reply_types = {"Offer", "Ack", "Nak"}

        if msg_type in request_types:
            return "request", f"DHCP:{src_mac}:{xid}"
        if msg_type in reply_types:
            return "reply", f"DHCP:{dst_mac}:{xid}"

    return "other", ""


def parse_packet(packet, interface: str) -> tuple[PacketEvent, str, str]:
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
    elif Ether in packet:
        src_ip = src_mac
        dst_ip = dst_mac

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

    message_type, correlation_key = _extract_flow_metadata(packet, protocol, src_ip, dst_ip, src_mac, dst_mac)

    event = PacketEvent(
        capture_id=0,
        timestamp=_format_timestamp(float(packet.time)),
        interface=interface,
        protocol=protocol,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        size=len(bytes(packet)),
        summary=summary,
        reply_to_id=None,
    )

    return event, message_type, correlation_key
