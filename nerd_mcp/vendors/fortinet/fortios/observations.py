"""FortiOS MAC/ARP observation commands, fixtures, and parser entrypoint."""

import re

from ...commands import command_error

from ...observations import parse_batch as _parse_batch

COMMANDS = {
    "bridges": ("diagnose netlink brctl list",),
    "arp": ("get system arp", "diagnose ip arp list"),
    "interfaces": ("get system interface physical",),
}
MOCK_OUTPUTS = {
    "bridges": "1. dmz fdb:",
    "mac": "3 8 dmz 00:11:22:33:44:55 194",
    "arp": "10.20.0.45 0 00:11:22:33:44:55 dmz",
    "interfaces": "",
}


def parse_observations(outputs):
    return _parse_batch(outputs, "fortinet")


def followup_commands(outputs):
    """Return validated bridge-table reads derived from FortiOS bridge output."""
    bridges = outputs.get("bridges", "")
    if command_error(bridges):
        return ()
    return tuple(
        ("mac", f"diagnose netlink brctl name host {bridge}")
        for bridge in re.findall(
            r"(?im)^\s*\d+\.\s+([A-Za-z0-9_.:-]{1,64})\s+fdb:", bridges
        )
    )
