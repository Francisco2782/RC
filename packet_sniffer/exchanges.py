from datetime import datetime

from scapy.all import ICMP, IP, TCP


class ExchangeTracker:
    def __init__(self):
        self._tcp_states: dict[tuple[str, int, str, int], str] = {}
        self._icmp_requests: dict[tuple[str, str, int, int], datetime] = {}

    def detect(self, packet) -> str:
        if IP in packet and TCP in packet:
            message = self._detect_tcp_handshake(packet)
            if message:
                return message

        if IP in packet and ICMP in packet:
            message = self._detect_icmp_pair(packet)
            if message:
                return message

        return ""

    def _detect_tcp_handshake(self, packet) -> str:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        flags = packet[TCP].sprintf("%TCP.flags%")

        direct_key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)

        if "S" in flags and "A" not in flags:
            self._tcp_states[direct_key] = "SYN"
            return ""

        if "S" in flags and "A" in flags:
            if reverse_key in self._tcp_states and self._tcp_states[reverse_key] == "SYN":
                self._tcp_states[reverse_key] = "SYN-ACK"
            return ""

        if "A" in flags and "S" not in flags:
            if direct_key in self._tcp_states and self._tcp_states[direct_key] == "SYN-ACK":
                del self._tcp_states[direct_key]
                return (
                    "TCP handshake completo "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )

        return ""

    def _detect_icmp_pair(self, packet) -> str:
        icmp_type = int(packet[ICMP].type)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        icmp_id = int(getattr(packet[ICMP], "id", 0))
        icmp_seq = int(getattr(packet[ICMP], "seq", 0))

        key = (src_ip, dst_ip, icmp_id, icmp_seq)
        reverse_key = (dst_ip, src_ip, icmp_id, icmp_seq)

        if icmp_type == 8:
            self._icmp_requests[key] = datetime.now()
            return ""

        if icmp_type == 0 and reverse_key in self._icmp_requests:
            del self._icmp_requests[reverse_key]
            return (
                "ICMP request/reply completo "
                f"{dst_ip} <-> {src_ip} id={icmp_id} seq={icmp_seq}"
            )

        return ""