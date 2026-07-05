import struct
import unittest

from app import parse_vless_header


class ParseVlessHeaderTest(unittest.TestCase):
    def test_parse_ipv4_header(self):
        uuid = bytes.fromhex('00112233445566778899aabbccddeeff')
        payload = b'\x00' + uuid + b'\x00' + struct.pack('!H', 80) + b'\x01' + b'\x01\x02\x03\x04'

        host, port, residual = parse_vless_header(payload, uuid)

        self.assertEqual(host, '1.2.3.4')
        self.assertEqual(port, 80)
        self.assertEqual(residual, b'')

    def test_parse_domain_header(self):
        uuid = bytes.fromhex('00112233445566778899aabbccddeeff')
        domain = b'example.com'
        payload = b'\x00' + uuid + b'\x00' + struct.pack('!H', 443) + b'\x02' + bytes([len(domain)]) + domain

        host, port, residual = parse_vless_header(payload, uuid)

        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)
        self.assertEqual(residual, b'')


if __name__ == '__main__':
    unittest.main()
