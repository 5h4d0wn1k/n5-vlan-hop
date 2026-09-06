#!/usr/bin/env python3
"""Offline unit tests for the N5 VLAN-hop tag construction engine."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

import vlan_hop  # noqa: E402
import vlan_utils  # noqa: E402


class TestVLANTag(unittest.TestCase):
    def test_to_bytes_vlan10(self):
        t = vlan_utils.VLANTag(10)
        self.assertEqual(t.to_bytes(), b'\x81\x00\x00\x0a')

    def test_tci_bits(self):
        t = vlan_utils.VLANTag(100, priority=5, cfi=1)
        # pri<<13 (0xA000) | cfi<<12 (0x1000) | vlan 100 (0x64) = 0xB064
        self.assertEqual(t.to_bytes(), b'\x81\x00\xb0\x64')

    def test_from_bytes_roundtrip(self):
        t = vlan_utils.VLANTag.from_bytes(b'\x81\x00\x00\x14')
        self.assertEqual(t.vlan_id, 20)

    def test_rejects_non_8021q(self):
        with self.assertRaises(ValueError):
            vlan_utils.VLANTag.from_bytes(b'\x08\x00\x00\x14')


class TestDoubleTag(unittest.TestCase):
    def test_double_tag_bytes(self):
        dt = vlan_utils.DoubleTag(vlan_utils.VLANTag(10),
                                  vlan_utils.VLANTag(20))
        self.assertEqual(dt.to_bytes(),
                         b'\x81\x00\x00\x0a\x81\x00\x00\x14')

    def test_from_bytes_roundtrip(self):
        dt = vlan_utils.DoubleTag.from_bytes(
            b'\x81\x00\x00\x0a\x81\x00\x00\x14')
        self.assertEqual(dt.outer.vlan_id, 10)
        self.assertEqual(dt.inner.vlan_id, 20)


class TestDoubleTagFrame(unittest.TestCase):
    """Build an actual frame and check every byte against a hand-written
    reference (independent of the builder)."""

    def setUp(self):
        self.frame = vlan_hop.DoubleTagPacket(
            '00:11:22:33:44:55', '00:22:33:44:55:66',
            10, 20, b'VLANHOP').build()

    def test_reference_vector(self):
        payload = b'VLANHOP'
        expect = (bytes.fromhex('002233445566')
                  + bytes.fromhex('001122334455')
                  + b'\x81\x00' + bytes([0x00, 0x0A])
                  + b'\x81\x00' + bytes([0x00, 0x14])
                  + b'\x08\x00' + payload)
        expect += b'\x00' * (64 - len(expect))
        self.assertEqual(self.frame, expect)

    def test_mac_positions(self):
        self.assertEqual(self.frame[0:6], bytes.fromhex('002233445566'))
        self.assertEqual(self.frame[6:12], bytes.fromhex('001122334455'))

    def test_tags(self):
        self.assertEqual(self.frame[12:14], b'\x81\x00')
        self.assertEqual(self.frame[14:16], bytes([0x00, 0x0A]))
        self.assertEqual(self.frame[16:18], b'\x81\x00')
        self.assertEqual(self.frame[18:20], bytes([0x00, 0x14]))
        self.assertEqual(self.frame[20:22], b'\x08\x00')

    def test_payload_and_padding(self):
        self.assertEqual(self.frame[22:29], b'VLANHOP')
        self.assertEqual(len(self.frame), 64)
        self.assertEqual(self.frame[29:], b'\x00' * 35)


class TestVLANScannerPacketTag(unittest.TestCase):
    def test_single_tagged_arp_frame(self):
        frame = vlan_utils.VLANScanner.generate_packet_tag(
            100, '00:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff')
        self.assertEqual(len(frame), 64)
        self.assertEqual(frame[12:14], b'\x81\x00')
        self.assertEqual(frame[14:16], bytes([0x00, 0x64]))
        self.assertEqual(frame[16:18], b'\x08\x06')  # ARP ethertype


class TestDTPSpooferFrame(unittest.TestCase):
    def test_dtp_letters(self):
        dtp = vlan_utils.DTPNegotiator().build_frame()
        self.assertEqual(dtp[:8], b'\x01' * 8)

    def test_dtp_frame_from_vlan_hop(self):
        f = vlan_hop.DTPPacket('00:11:22:33:44:55', mode='auto').build()
        self.assertEqual(f[0:6], bytes.fromhex('01000ccccc00'))
        self.assertEqual(f[12:14], b'\x01\x42')  # DTP ethertype
        self.assertEqual(len(f), 64)


class TestHelpers(unittest.TestCase):
    def test_is_valid_vlan(self):
        self.assertTrue(vlan_utils.is_valid_vlan(1))
        self.assertTrue(vlan_utils.is_valid_vlan(4094))
        self.assertFalse(vlan_utils.is_valid_vlan(0))
        self.assertFalse(vlan_utils.is_valid_vlan(4095))

    def test_vlan_name(self):
        self.assertEqual(vlan_utils.vlan_name(1), 'Default')
        self.assertEqual(vlan_utils.vlan_name(42), 'VLAN-42')


if __name__ == '__main__':
    unittest.main()