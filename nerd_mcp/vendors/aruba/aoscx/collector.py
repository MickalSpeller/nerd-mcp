"""Aruba AOS-CX observation commands, fixtures, and parser entrypoint."""

from ...observations import parse_batch as _parse_batch

COMMANDS = {
    "mac": ("show mac-address-table",),
    "arp": ("show arp",),
    "trunks": ("show interface lag",),
    "lldp": ("show lldp neighbor", "show lldp neighbors"),
    "interfaces": ("show interface",),
}
MOCK_OUTPUTS = {
    "mac": "20 00:11:22:33:44:55 dynamic 1/1/18",
    "arp": "10.20.0.45 00:11:22:33:44:55 dynamic 1/1/18",
    "trunks": "1/1/48 trunk",
    "lldp": "System Name: DIST-SW1\nLocal Port: 1/1/48",
    "interfaces": "1/1/18 is up, line protocol is up",
}


def parse_observations(outputs):
    return _parse_batch(outputs, "aruba_aoscx")
