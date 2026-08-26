# N5 — VLAN Hopping Attack Tool

VLAN security testing via double-tagging and DTP spoofing attacks.

## Overview

This project implements VLAN hopping attack techniques for authorized security testing of network infrastructure. VLAN hopping is a network attack that exploits misconfigured trunk links to access unauthorized VLANs.

**Attack techniques implemented:**
- **Double-Tagging (802.1Q-in-802.1Q)**: Frames with two VLAN tags
- **DTP Spoofing**: Negotiating trunk links via Dynamic Trunking Protocol
- **VLAN Enumeration**: Discovering active VLANs on a network segment

**Use cases:**
- Network infrastructure security testing
- VLAN misconfiguration detection
- Trunk link vulnerability assessment
- Security hardening validation

## Features

- **Double-Tagging Attack**: Craft frames with nested VLAN tags
- **DTP Spoofing**: Send DTP frames to negotiate trunk links
- **VLAN Enumeration**: Scan and discover active VLANs
- **Packet Crafting**: Full control over VLAN tags and payloads
- **Statistics Tracking**: Monitor attack progress and results

## Architecture

```
Attacker                    Trunk Link                    Target
    |                           |                           |
    |-- Double-tagged frame --->|                           |
    |   (Outer: Native VLAN)    |                           |
    |   (Inner: Target VLAN)   |                           |
    |                           |-- Frame to Target VLAN -->|
    |                           |                           |
```

## Installation

```bash
# Clone and install
git clone https://github.com/yourorg/n5-vlan-hop.git
cd n5-vlan-hop/firmware
pip install -r requirements.txt

# Or install directly
pip install pycryptodome scapy
```

### Dependencies

```bash
pip install pycryptodome scapy
```

## Usage

### Double-Tagging Attack

```bash
# Basic double-tag attack
sudo python3 vlan_hop.py double-tag \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --outer-vlan 1 \
    --inner-vlan 100

# With packet count
sudo python3 vlan_hop.py double-tag \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --outer-vlan 1 \
    --inner-vlan 100 \
    --count 50
```

### DTP Spoofing

```bash
# Send DTP frames to negotiate trunk
sudo python3 vlan_hop.py dtp \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --mode auto

# Continuous DTP spoofing
sudo python3 vlan_hop.py dtp \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --mode trunk \
    --count 20 \
    --interval 2.0
```

### VLAN Enumeration

```bash
# Scan default VLAN range (1-100)
sudo python3 vlan_hop.py enum \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff

# Scan specific range
sudo python3 vlan_hop.py enum \
    --interface eth0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --start-vlan 100 \
    --end-vlan 200
```

### Example Output

```
=== Double-Tagging Attack ===
Outer VLAN: 1
Inner VLAN: 100
Target VLAN: 100
[SENT] 10/50 packets
[SENT] 20/50 packets
[SENT] 30/50 packets
[SENT] 40/50 packets
[SENT] 50/50 packets
[DONE] 50 packets sent
```

## Command Reference

### `double-tag` Command
| Flag | Description | Default |
|------|-------------|---------|
| `--interface, -i` | Network interface | (required) |
| `--src-mac` | Source MAC address | (required) |
| `--outer-vlan` | Outer VLAN tag | (required) |
| `--inner-vlan` | Inner VLAN tag | (required) |
| `--count` | Packet count | 10 |
| `--interval` | Interval (s) | 0.1 |

### `dtp` Command
| Flag | Description | Default |
|------|-------------|---------|
| `--interface, -i` | Network interface | (required) |
| `--src-mac` | Source MAC address | (required) |
| `--mode` | DTP mode | auto |
| `--count` | Frame count | 10 |
| `--interval` | Interval (s) | 1.0 |

### `enum` Command
| Flag | Description | Default |
|------|-------------|---------|
| `--interface, -i` | Network interface | (required) |
| `--src-mac` | Source MAC address | (required) |
| `--start-vlan` | Start VLAN ID | 1 |
| `--end-vlan` | End VLAN ID | 100 |

## How It Works

### Double-Tagging Attack
1. Attacker sends frame with two 802.1Q tags
2. Outer tag matches native VLAN (e.g., VLAN 1)
3. Switch strips outer tag, forwards on native VLAN
4. Inner tag remains, switches forward to target VLAN
5. Frame reaches target on unauthorized VLAN

### DTP Spoofing
1. Attacker sends DTP frames advertising trunk capability
2. Switch responds and negotiates trunk link
3. Trunk link allows traffic on all VLANs
4. Attacker gains access to all VLANs

## Mitigation

1. **Disable DTP** on all access ports: `switchport nonegotiate`
2. **Set native VLAN** to unused VLAN ID
3. **Filter VLANs** on trunk links
4. **Use VLAN ACLs** for inter-VLAN traffic
5. **Monitor trunk formation** with IDS/IPS

## Security Considerations

- Requires root/sudo privileges for raw socket access
- Only works against misconfigured switches
- Modern switches may have protections against these attacks
- Test in lab environments before production networks

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
