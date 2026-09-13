"""Cisco IOS/IOS-XE and NX-OS MAC, ARP, neighbor, and interface observations."""

from ..observations import parse_batch as _parse_batch


COMMANDS = {
    "mac": ("show mac address-table", "show mac-address-table"),
    "arp": ("show ip arp",),
    "trunks": ("show interfaces trunk",),
    "port_channels": ("show etherchannel summary",),
    "cdp": ("show cdp neighbors detail",),
    "lldp": ("show lldp neighbors detail",),
    "interfaces": ("show interfaces",),
}

MOCK_OUTPUTS = {
    "mac": """          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  20    0011.2233.4455    DYNAMIC     Gi1/0/18
  20    00aa.bbcc.ddee    DYNAMIC     Gi1/0/48""",
    "arp": """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.20.0.45             2   0011.2233.4455  ARPA   Vlan20""",
    "trunks": "Gi1/0/48    on               802.1q  trunking      1",
    "port_channels": "",
    "cdp": """Device ID: DIST-SW1
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): GigabitEthernet1/0/1""",
    "lldp": "",
    "interfaces": """GigabitEthernet1/0/18 is up, line protocol is up
  Description: User endpoint
  Full-duplex, 1000Mb/s
  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  0 output errors, 0 collisions, 0 interface resets
GigabitEthernet1/0/48 is up, line protocol is up
  Description: Uplink
  Full-duplex, 1000Mb/s
  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  0 output errors, 0 collisions, 0 interface resets""",
}


def parse_observations(outputs, family="cisco_ios"):
    return _parse_batch(outputs, family)
