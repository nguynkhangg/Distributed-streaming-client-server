import unittest
import struct
from src.common.constants import MAGIC, VERSION, HEADER_SIZE, MAX_PAYLOAD_SIZE, PacketType, PacketFlag
from src.common.exceptions import MalformedPacketError, UnknownPacketTypeError, PacketError
from src.common.protocol import CCPPacket, CCPCodec, JSONMessageCodec

class TestHeaderStructure(unittest.TestCase):
    def test_header_format_size(self):
        fmt = "!HBBBBIIH"
        size = struct.calcsize(fmt)
        self.assertEqual(size, 16, f"Format should be 16 bytes, got {size}")

class TestCCPPacketEncode(unittest.TestCase):
    def test_encode_empty_payload(self):
        pkt = CCPPacket(packet_type=PacketType.HELLO, payload=b"")
        encoded = CCPCodec.encode(pkt)
        self.assertEqual(len(encoded), HEADER_SIZE)

    def test_encode_with_payload(self):
        payload = b"test_data"
        pkt = CCPPacket(packet_type=PacketType.AUTH, payload=payload, connection_id=1, packet_number=2)
        encoded = CCPCodec.encode(pkt)
        expected_size = HEADER_SIZE + len(payload)
        self.assertEqual(len(encoded), expected_size)
        self.assertEqual(encoded[HEADER_SIZE:], payload)

    def test_encode_header_structure(self):
        pkt = CCPPacket(packet_type=PacketType.MSG, payload=b"hello", flags=PacketFlag.FIN, connection_id=123, packet_number=456)
        encoded = CCPCodec.encode(pkt)
        magic, version, pkt_type, flags, reserved, conn_id, pkt_num, payload_len = struct.unpack("!HBBBBIIH", encoded[:HEADER_SIZE])
        self.assertEqual(magic, MAGIC)
        self.assertEqual(version, VERSION)
        self.assertEqual(pkt_type, PacketType.MSG)
        self.assertEqual(payload_len, 5)

    def test_encode_payload_too_large(self):
        large_payload = b"x" * (MAX_PAYLOAD_SIZE + 1)
        pkt = CCPPacket(packet_type=PacketType.FILE_DATA, payload=large_payload)
        with self.assertRaises(MalformedPacketError):
            CCPCodec.encode(pkt)

class TestCCPPacketDecode(unittest.TestCase):
    def test_decode_roundtrip(self):
        original = CCPPacket(packet_type=PacketType.FILE_DATA, payload=b"data", flags=PacketFlag.FIN, connection_id=123, packet_number=456)
        encoded = CCPCodec.encode(original)
        decoded = CCPCodec.decode(encoded)
        self.assertEqual(decoded.packet_type, original.packet_type)
        self.assertEqual(decoded.payload, original.payload)
        self.assertEqual(decoded.flags, original.flags)
        self.assertEqual(decoded.connection_id, original.connection_id)
        self.assertEqual(decoded.packet_number, original.packet_number)

    def test_decode_validates_magic(self):
        wrong_magic = 0x1234
        header = struct.pack("!HBBBBIIH", wrong_magic, VERSION, PacketType.HELLO, 0, 0, 0, 1, 0)
        with self.assertRaises(MalformedPacketError):
            CCPCodec.decode(header)

    def test_decode_validates_version(self):
        wrong_version = 99
        header = struct.pack("!HBBBBIIH", MAGIC, wrong_version, PacketType.HELLO, 0, 0, 0, 1, 0)
        with self.assertRaises(MalformedPacketError):
            CCPCodec.decode(header)

class TestJSONMessageCodec(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        encoded = JSONMessageCodec.encode("AUTH_REQ", username="alice", password="secret")
        msg_type, fields = JSONMessageCodec.decode(encoded)
        self.assertEqual(msg_type, "AUTH_REQ")
        self.assertEqual(fields["username"], "alice")

if __name__ == "__main__":
    unittest.main()
