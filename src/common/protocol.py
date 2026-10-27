from dataclasses import dataclass
from typing import Any

@dataclass
class Packet:
    message_type: str
    payload: dict[str, Any]
    message_id: str | None = None

def encode_packet(packet: Packet) -> bytes:
    "Convert a packet into bytes."
    raise NotImplementedError

def decode_packet(data: bytes) -> Packet:
    "Convert bytes into a packet."
    raise NotImplementedError