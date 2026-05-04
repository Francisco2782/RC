from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class PacketEvent:
    capture_id: int
    packet_time: float
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
    src_port: Optional[int]
    dst_port: Optional[int]
    size: int
    summary: str
    reply_to_id: Optional[int]
    rtt_ms: Optional[float]

    def to_dict(self) -> dict:
        return asdict(self)

        
