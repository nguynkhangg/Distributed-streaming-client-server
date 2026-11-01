import struct
import json
from dataclasses import dataclass
from typing import Tuple
from .constants import MAGIC, VERSION, HEADER_SIZE, MAX_PAYLOAD_SIZE, PacketType, PacketFlag, PACKET_TYPE_NAME
from .exceptions import PacketError, MalformedPacketError, UnknownPacketTypeError

@dataclass
class CCPPacket:
    packet_type: int
    payload: bytes = b""
    flags: int = 0
    connection_id: int = 0
    packet_number: int = 1

    def is_final(self) -> bool:
        return bool(self.flags & PacketFlag.FIN)

    def is_encrypted(self) -> bool:
        return bool(self.flags & PacketFlag.ENC)

    def type_name(self) -> str:
        return PACKET_TYPE_NAME.get(self.packet_type, f"UNKNOWN(0x{self.packet_type:02X})")

class CCPCodec:
    @staticmethod
    def encode(packet: CCPPacket) -> bytes:
        if packet.packet_type not in PACKET_TYPE_NAME:
            raise UnknownPacketTypeError(f"Invalid packet type: {packet.packet_type}")
        if len(packet.payload) > MAX_PAYLOAD_SIZE:
            raise MalformedPacketError("Payload too large")
        header = struct.pack("!HBBBBIIH", MAGIC, VERSION, packet.packet_type, packet.flags, 0, packet.connection_id, packet.packet_number, len(packet.payload))
        return header + packet.payload

    @staticmethod
    def decode(data: bytes) -> CCPPacket:
        if len(data) < HEADER_SIZE:
            raise MalformedPacketError(f"Packet too short: {len(data)} < {HEADER_SIZE}")
        try:
            magic, version, pkt_type, flags, reserved, conn_id, pkt_num, payload_len = struct.unpack("!HBBBBIIH", data[:HEADER_SIZE])
        except struct.error as e:
            raise MalformedPacketError(f"Header unpack failed: {e}")
        if magic != MAGIC:
            raise MalformedPacketError(f"Invalid magic: 0x{magic:04X} != 0x{MAGIC:04X}")
        if version != VERSION:
            raise MalformedPacketError("Unsupported protocol version")
        if payload_len > MAX_PAYLOAD_SIZE:
            raise MalformedPacketError("Payload too large")
        expected_size = HEADER_SIZE + payload_len
        if len(data) != expected_size:
            raise MalformedPacketError("Invalid packet length")
        payload = data[HEADER_SIZE:expected_size]
        return CCPPacket(packet_type=pkt_type, payload=payload, flags=flags, connection_id=conn_id, packet_number=pkt_num)

class JSONMessageCodec:
    @staticmethod
    def encode(message_type: str, **kwargs) -> bytes:
        payload = {"type": message_type, **kwargs}
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")
    @staticmethod
    def decode(data: bytes) -> Tuple[str, dict]:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PacketError(f"Failed to decode JSON: {e}")
        message_type = payload.pop("type", None)
        if not message_type:
            raise PacketError("Missing type field")
        return message_type, payload
