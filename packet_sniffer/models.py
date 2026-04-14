from dataclasses import asdict, dataclass


@dataclass
class PacketEvent:
    timestamp: str
    interface: str
    protocol: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    size: int
    summary: str
    exchange: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
