from argparse import Namespace
import re
from typing import Any

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether

from .models import PacketEvent


def _parse_literal(token: str) -> Any:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    if re.fullmatch(r"\d+", token):
        return int(token)
    return token


def _coerce_comparable(left: Any, right: Any) -> tuple[Any, Any]:
    if isinstance(left, bool):
        left = int(left)
    if isinstance(right, bool):
        right = int(right)

    if isinstance(left, int) and isinstance(right, int):
        return left, right

    return str(left).lower(), str(right).lower()


def _extract_field(packet, event: PacketEvent, field: str) -> Any:
    key = field.lower()

    mapping = {
        "frame.len": event.size,
        "frame.interface": event.interface,
        "eth.src": event.src_mac,
        "eth.dst": event.dst_mac,
        "ip.src": event.src_ip,
        "ip.dst": event.dst_ip,
        "tcp.srcport": event.src_port if event.l4_protocol == "TCP" else None,
        "tcp.dstport": event.dst_port if event.l4_protocol == "TCP" else None,
        "udp.srcport": event.src_port if event.l4_protocol == "UDP" else None,
        "udp.dstport": event.dst_port if event.l4_protocol == "UDP" else None,
        "arp.op": int(packet[ARP].op) if ARP in packet else None,
        "icmp.type": int(packet[ICMP].type) if ICMP in packet else None,
        "icmp.code": int(packet[ICMP].code) if ICMP in packet else None,
        "dns.id": int(packet[DNS].id) if DNS in packet else None,
        "dns.qr": int(packet[DNS].qr) if DNS in packet else None,
        "dns.opcode": int(packet[DNS].opcode) if DNS in packet else None,
        "l2": event.l2_protocol,
        "l3": event.l3_protocol,
        "l4": event.l4_protocol,
        "proto": event.protocol,
    }

    if key in mapping:
        return mapping[key]

    if key == "tcp" or key == "tcp.present":
        return TCP in packet
    if key == "udp" or key == "udp.present":
        return UDP in packet
    if key == "icmp" or key == "icmp.present":
        return ICMP in packet
    if key == "dns" or key == "dns.present":
        return DNS in packet
    if key == "arp" or key == "arp.present":
        return ARP in packet
    if key == "ip" or key == "ip.present":
        return IP in packet
    if key == "eth" or key == "eth.present":
        return Ether in packet

    return None


def _tokenize(expression: str) -> list[str]:
    pattern = r'\s*(>=|<=|==|!=|>|<|\(|\)|&&|\|\||!|"[^"]*"|\'[^\']*\'|[^\s()><=!&|]+)\s*'
    tokens = re.findall(pattern, expression)
    return [token for token in tokens if token.strip()]


class _HeaderExprParser:
    def __init__(self, tokens: list[str], packet, event: PacketEvent):
        self.tokens = tokens
        self.position = 0
        self.packet = packet
        self.event = event

    def _peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position]

    def _consume(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("Expressão incompleta")
        self.position += 1
        return token

    def _match(self, *values: str) -> bool:
        token = self._peek()
        if token is None:
            return False
        if token.lower() in values:
            self.position += 1
            return True
        return False

    def parse(self) -> bool:
        result = self._parse_or()
        if self._peek() is not None:
            raise ValueError(f"Token inesperado: {self._peek()}")
        return result

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while self._match("or", "||"):
            result = result or self._parse_and()
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while self._match("and", "&&"):
            result = result and self._parse_not()
        return result

    def _parse_not(self) -> bool:
        if self._match("not", "!"):
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        if self._match("("):
            result = self._parse_or()
            if not self._match(")"):
                raise ValueError("Falta ')' na expressão")
            return result
        return self._parse_comparison_or_presence()

    def _parse_comparison_or_presence(self) -> bool:
        field = self._consume()
        if field in {")", "(", "and", "or", "&&", "||"}:
            raise ValueError(f"Campo inválido: {field}")

        operator = self._peek()
        if operator in {"==", "!=", ">", "<", ">=", "<="}:
            self._consume()
            right_token = self._consume()
            right_value = _parse_literal(right_token)
            left_value = _extract_field(self.packet, self.event, field)

            if left_value is None:
                return False

            left_cmp, right_cmp = _coerce_comparable(left_value, right_value)

            if operator == "==":
                return left_cmp == right_cmp
            if operator == "!=":
                return left_cmp != right_cmp
            if operator == ">":
                return left_cmp > right_cmp
            if operator == "<":
                return left_cmp < right_cmp
            if operator == ">=":
                return left_cmp >= right_cmp
            if operator == "<=":
                return left_cmp <= right_cmp

        value = _extract_field(self.packet, self.event, field)
        return value is not None and value != "-" and value != ""


def _matches_header_filter(packet, event: PacketEvent, expression: str) -> bool:
    tokens = _tokenize(expression)
    if not tokens:
        return True
    parser = _HeaderExprParser(tokens, packet, event)
    return parser.parse()


def matches_filters(packet, event: PacketEvent, args: Namespace) -> bool:
    if args.proto and event.protocol.upper() != args.proto.upper():
        return False

    if args.ip and args.ip not in (event.src_ip, event.dst_ip):
        return False

    if args.mac:
        mac = args.mac.lower()
        if mac not in (event.src_mac.lower(), event.dst_mac.lower()):
            return False

    if args.hfilter:
        try:
            if not _matches_header_filter(packet, event, args.hfilter):
                return False
        except ValueError as error:
            raise RuntimeError(f"Filtro de cabeçalho inválido: {error}") from error

    return True
