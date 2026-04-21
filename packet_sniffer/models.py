from dataclasses import asdict, dataclass


@dataclass
class PacketEvent:
    capture_id: int
    timestamp: str
    interface: str
    protocol: str
    used_level: int
    l2_protocol: str
    l3_protocol: str
    l4_protocol: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    size: int
    summary: str
    reply_to_id: int | None

    def to_dict(self) -> dict:
        return asdict(self)
