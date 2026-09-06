# N5 — VLAN Hopping (tag engine + gated live injection)

Constructs genuine 802.1Q double- and single-tagged Ethernet frames and DTP
frames. The core tag-construction engine runs fully offline and is verified
byte-for-byte; real frame injection is gated behind `--live`/`--interface`.

## Overview

This project implements the packet-construction side of VLAN-hopping
techniques — double-tagging (802.1Q-in-802.1Q) and DTP frame building — for
authorized lab testing of switch trunk/VLAN handling.

**Components:**
- `VLANTag` / `DoubleTag` (vlan_utils) — 802.1Q tag bytes with correct TPID and
  TCI bit packing, parse-back round-trip.
- `DoubleTagPacket` — full Ethernet frame with two 802.1Q tags.
- `DTPNegotiator` / `DTPPacket` — DTP frame header + TLVs.
- Live injectors (`double-tag`, `dtp`, `enum`) — gated behind `--live` (root,
  AF_PACKET raw sockets).

## What Works

- **Offline byte-for-byte check (`check`)** — builds a double-tagged frame and
  compares it field-by-field against a hand-written reference vector.
- **Tag library round-trips** — `DoubleTag.from_bytes`/`to_bytes`.
- **Live mode gating** — `double-tag`, `dtp`, `enum` refuse to run without
  `--live`; the offline engine is the default path.

## Usage

```bash
# Offline tag-construction check (no privileges, deterministic)
python3 vlan_hop.py check

# Build a reference double-tagged frame and show it
python3 vlan_hop.py check

# Live double-tag injection (root): explicit --live required
sudo python3 vlan_hop.py --live double-tag --interface eth0 \
      --src-mac 00:11:22:33:44:55 --outer-vlan 10 --inner-vlan 20

# Live DTP spoof / VLAN enumeration (root): --live required
sudo python3 vlan_hop.py --live dtp --interface eth0 --src-mac 00:11:22:33:44:55
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, 00:11:22:33:44:55).

1. On a lab switch with a native VLAN 10 access port and a trunk, run
   `sudo python3 vlan_hop.py --live double-tag --interface <lab-iface> --src-mac 00:11:22:33:44:55 --outer-vlan 10 --inner-vlan 20`.
2. Sniff the lab link with tcpdump and confirm frames carry `vlan 10` and
   `vlan 20` tags and the correct source MAC.
3. On another lab machine, confirm traffic with inner VLAN 20 reaches the
   target segment (double-tagging demo).
4. Run `dtp` and confirm DTP frames are visible on the trunk candidate port.

## Metrics

Core offline check is deterministic and unit-tested:

- Double-tag frame equals hand-built reference vector byte-for-byte: PASS
- VLANTag/DoubleTag bytes + round-trip: PASS (3 tests)
- Frame field positions (MACs, TPIDs, TCIs, ethertype, padding): PASS
- Single-tagged ARP probe frame header: PASS
- DTP frame letters: PASS (15 tests total)
- Exit code: `0` on successful check, `1` on failure

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT