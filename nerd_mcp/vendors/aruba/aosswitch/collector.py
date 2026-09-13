"""Aruba AOS-Switch observation commands, fixtures, and parser entrypoint."""

from ...observations import parse_batch as _parse_batch

COMMANDS = {
    "mac": ("show mac-address",),
    "arp": ("show arp",),
    "trunks": ("show trunks",),
    "lldp": ("show lldp info remote-device",),
    "interfaces": ("show interfaces",),
}
MOCK_OUTPUTS = {
    "mac": "001122-334455 18 20\n00aabb-ccddee 48 20",
    "arp": "10.20.0.45 001122-334455 dynamic 18",
    "trunks": "48 Trk1 trunk",
    "lldp": "System Name: DIST-SW1\nLocal Port: 48",
    "interfaces": "18 is up, line protocol is up",
}


def parse_observations(outputs):
    return _parse_batch(outputs, "aruba_osswitch")
