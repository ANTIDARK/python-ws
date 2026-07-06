import struct
import unittest

from app import parse_vless_header


class ParseVlessHeaderTest(unittest.TestCase):
    def setUp(self):
        self.uuid = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_parse_ipv4_header(self):
        """Test parsing VLESS header with IPv4 address."""
        payload = (
            b"\x00"  # VER
            + self.uuid
            + b"\x01"  # CMD: TCP
            + b"\x00"  # ADD: no addons
            + b"\x01"  # ATYP: IPv4
            + b"\x7f\x00\x00\x01"  # 127.0.0.1
            + struct.pack("!H", 80)  # PORT: 80
        )

        host, port, cmd, residual = parse_vless_header(payload, self.uuid)

        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 80)
        self.assertEqual(cmd, 0x01)
        self.assertEqual(residual, b"")

    def test_parse_domain_header(self):
        """Test parsing VLESS header with domain address."""
        domain = b"example.com"
        payload = (
            b"\x00"  # VER
            + self.uuid
            + b"\x01"  # CMD: TCP
            + b"\x00"  # ADD: no addons
            + b"\x02"  # ATYP: Domain
            + bytes([len(domain)])
            + domain
            + struct.pack("!H", 443)  # PORT: 443
        )

        host, port, cmd, residual = parse_vless_header(payload, self.uuid)

        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(cmd, 0x01)
        self.assertEqual(residual, b"")

    def test_parse_ipv6_header(self):
        """Test parsing VLESS header with IPv6 address."""
        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")
        payload = (
            b"\x00"  # VER
            + self.uuid
            + b"\x01"  # CMD: TCP
            + b"\x00"  # ADD: no addons
            + b"\x03"  # ATYP: IPv6
            + ipv6_bytes
            + struct.pack("!H", 80)  # PORT: 80
        )

        host, port, cmd, residual = parse_vless_header(payload, self.uuid)

        self.assertEqual(host, "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(port, 80)
        self.assertEqual(cmd, 0x01)

    def test_parse_with_payload(self):
        """Test parsing VLESS header with residual payload data."""
        payload_data = b"GET / HTTP/1.1\r\n"
        domain = b"example.com"
        payload = (
            b"\x00"  # VER
            + self.uuid
            + b"\x01"  # CMD: TCP
            + b"\x00"  # ADD: no addons
            + b"\x02"  # ATYP: Domain
            + bytes([len(domain)])
            + domain
            + struct.pack("!H", 80)  # PORT: 80
            + payload_data
        )

        host, port, cmd, residual = parse_vless_header(payload, self.uuid)

        self.assertEqual(residual, payload_data)

    def test_invalid_version(self):
        """Test that invalid version raises error."""
        payload = b"\x01" + self.uuid + b"\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 80)

        with self.assertRaises(ValueError) as ctx:
            parse_vless_header(payload, self.uuid)
        self.assertIn("version", str(ctx.exception))

    def test_uuid_mismatch(self):
        """Test that UUID mismatch raises error."""
        wrong_uuid = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        payload = b"\x00" + wrong_uuid + b"\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 80)

        with self.assertRaises(ValueError) as ctx:
            parse_vless_header(payload, self.uuid)
        self.assertIn("uuid", str(ctx.exception))

    def test_unsupported_cmd(self):
        """Test that unsupported CMD raises error."""
        payload = (
            b"\x00"
            + self.uuid
            + b"\x99"  # Invalid CMD
            + b"\x00"
            + b"\x01"
            + b"\x7f\x00\x00\x01"
            + struct.pack("!H", 80)
        )

        with self.assertRaises(ValueError) as ctx:
            parse_vless_header(payload, self.uuid)
        self.assertIn("CMD", str(ctx.exception))

    def test_cmd_udp(self):
        """Test parsing UDP command."""
        payload = (
            b"\x00"  # VER
            + self.uuid
            + b"\x02"  # CMD: UDP
            + b"\x00"  # ADD: no addons
            + b"\x01"  # ATYP: IPv4
            + b"\x7f\x00\x00\x01"  # 127.0.0.1
            + struct.pack("!H", 53)  # PORT: 53 (DNS)
        )

        host, port, cmd, residual = parse_vless_header(payload, self.uuid)

        self.assertEqual(cmd, 0x02)


if __name__ == "__main__":
    unittest.main()
