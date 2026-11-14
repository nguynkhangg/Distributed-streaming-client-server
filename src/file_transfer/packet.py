import struct
from dataclasses import dataclass

MAGIC = 0xA5C3
VERSION = 1

HEADER_SIZE = 16
MAX_DATAGRAM_SIZE = 1200
MAX_DATA_BYTES = 1000

HEADER_STRUCT = struct.Struct("!HBBBBIIH") #Magic 2b, version 1b, type 1b, flag 1b, reserved 1b, connection_id 4b, packet_num 4b, payload_length 2b

TYPE_HELLO = 0x01
TYPE_HELLO_ACK = 0x02
TYPE_DATA = 0x03
TYPE_ACK = 0x04
TYPE_PING = 0x05
TYPE_PONG = 0x06
TYPE_CLOSE = 0x07
KNOWN_TYPES = {TYPE_HELLO, TYPE_HELLO_ACK, TYPE_DATA, TYPE_ACK, TYPE_PING, TYPE_PONG, TYPE_CLOSE}

FLAG_FIN = 0x01
FLAG_ENC = 0x02

AEAD_TAG_SIZE = 16 #AES-GCM tag added to encrypted payloads
MAX_ACK_RANGES = (MAX_DATAGRAM_SIZE - HEADER_SIZE - AEAD_TAG_SIZE - 9) // 8
@dataclass(frozen=True)
class PacketHeader:
    packet_type: int
    flags: int
    connection_id: int
    packet_number: int
    payload_length: int
    version: int = VERSION
    magic: int = MAGIC
    reserved: int = 0
    def encode(self) -> bytes:
        """
        Convert PacketHeader to 16 bytes
        """

        if not 0 <= self.connection_id <= 0xFFFFFFFF:
            raise ValueError("connection_id out of range")

        if not 0 <= self.packet_number <= 0xFFFFFFFF:
            raise ValueError("packet_number out of range")

        if not 0 <= self.payload_length <= 0xFFFF:
            raise ValueError("payload_length out of range")

        if not 0 <= self.packet_type <= 0xFF:
            raise ValueError("packet_type out of range")

        if not 0 <= self.flags <= 0xFF:
            raise ValueError("flags out of range")

        if self.magic != MAGIC:
            raise ValueError("Invalid magic")

        if self.version != VERSION:
            raise ValueError("Unsupported version")

        if self.reserved != 0:
            raise ValueError("Reserved field must be zero")

        return HEADER_STRUCT.pack(
            self.magic,
            self.version,
            self.packet_type,
            self.flags,
            self.reserved,
            self.connection_id,
            self.packet_number,
            self.payload_length
        )

    @classmethod
    def decode(cls, raw: bytes) -> "PacketHeader":
        """
        Decode HEADER 16 bytes 
        """

        if len(raw) < HEADER_SIZE:
            raise ValueError("Datagram shorter than 16-byte header")

        values = HEADER_STRUCT.unpack(raw[:HEADER_SIZE])

        header = cls(
            magic=values[0],
            version=values[1],
            packet_type=values[2],
            flags=values[3],
            reserved=values[4],
            connection_id=values[5],
            packet_number=values[6],
            payload_length=values[7]
        )

        if header.magic != MAGIC:
            raise ValueError("Invalid magic")

        if header.version != VERSION:
            raise ValueError("Unsupported protocol version")

        if header.reserved != 0:
            raise ValueError("Reserved field must be zero")

        if len(raw) != HEADER_SIZE + header.payload_length:
            raise ValueError("Payload length does not match datagram")

        if len(raw) > MAX_DATAGRAM_SIZE:
            raise ValueError("Datagram exceeds 1200-byte limit")
        
        if header.packet_type not in KNOWN_TYPES:
            raise ValueError("Unknown packet type")

        if header.flags & ~(FLAG_FIN | FLAG_ENC):
            raise ValueError("Unknown flag bits set")

        if header.flags & FLAG_FIN and header.packet_type != TYPE_DATA:
            raise ValueError("FIN flag is only valid on DATA packets")

        if header.flags & FLAG_ENC and header.packet_type in (TYPE_HELLO, TYPE_HELLO_ACK):
            raise ValueError("HELLO/HELLO_ACK must not be encrypted")
        return header

def encode_data_payload(stream_id: int,offset: int,data: bytes) -> bytes:
    """
    Encode DATA payload:
    stream_id: 4 bytes
    offset: 8 bytes
    data: max1000 bytes
    """

    if not 0 <= stream_id <= 0xFFFFFFFF:
        raise ValueError("stream_id out of range")

    if not 0 <= offset <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("offset out of range")

    if len(data) > MAX_DATA_BYTES:
        raise ValueError("DATA segment exceeds 1000 bytes")

    return struct.pack("!IQ", stream_id, offset) + data


def decode_data_payload( payload: bytes ) -> tuple[int, int, bytes]:
    """
    Decode DATA payload
    """

    if len(payload) < 12:
        raise ValueError("DATA payload shorter than 12 bytes")

    stream_id, offset = struct.unpack(
        "!IQ",
        payload[:12]
    )

    data = payload[12:]

    if len(data) > MAX_DATA_BYTES:
        raise ValueError("DATA segment exceeds 1000 bytes")

    return stream_id, offset, data

def encode_ack_payload(largest_acked: int,recv_window: int,ranges: list[tuple[int, int]]) -> bytes:
    """
    Encode ACK payload:
    largest_acked: 4 bytes
    recv_window: 4 bytes
    range_count: 1 byte
    ranges: 8 bytes/range
    """

    if not 0 <= largest_acked <= 0xFFFFFFFF:
        raise ValueError("largest_acked out of range")

    if not 0 <= recv_window <= 0xFFFFFFFF:
        raise ValueError("recv_window out of range")

    # if len(ranges) > MAX_ACK_RANGES:
    #     raise ValueError("Too many ACK ranges")
    ranges = sorted(ranges, reverse=True)[:MAX_ACK_RANGES]

    output = bytearray(
        struct.pack(
            "!IIB",
            largest_acked,
            recv_window,
            len(ranges)
        )
    )

    for start, end in ranges:

        if not 0 <= start <= end <= 0xFFFFFFFF:
            raise ValueError("Invalid ACK range")

        output.extend(
            struct.pack("!II", start, end)
        )

    return bytes(output)

def decode_ack_payload(payload: bytes) -> tuple[int, int, list[tuple[int, int]]]:
    """
    Decode ACK payload
    """

    if len(payload) < 9:
        raise ValueError("ACK payload shorter than 9 bytes")

    largest_acked, recv_window, range_count = struct.unpack(
        "!IIB",
        payload[:9]
    )

    expected_length = 9 + range_count * 8

    if len(payload) != expected_length:
        raise ValueError("ACK range_count does not match payload")

    ranges = []

    for i in range(range_count):

        start, end = struct.unpack(
            "!II",
            payload[9 + i * 8 : 17 + i * 8]
        )

        if start > end:
            raise ValueError("Invalid ACK range")

        ranges.append((start, end))

    return largest_acked, recv_window, ranges

def build_packet(header: PacketHeader,payload: bytes) -> bytes:
    """
    Combine header and payload to packet
    """

    if len(payload) != header.payload_length:
        raise ValueError("Header payload_length does not match payload")

    datagram = header.encode() + payload

    if len(datagram) > MAX_DATAGRAM_SIZE:
        raise ValueError("Datagram exceeds 1200-byte limit")

    return datagram