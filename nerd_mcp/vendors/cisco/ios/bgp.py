"""Cisco IOS/IOS-XE BGP summary collection and parsing."""

from __future__ import annotations

import ipaddress
import re
from types import MappingProxyType

from ....domain.models import BgpNeighbor, BgpStatus
from ...commands import command_error

COMMANDS = MappingProxyType({"summary": "show ip bgp summary"})
MOCK_OUTPUTS = MappingProxyType({
    "summary": """BGP router identifier 1.1.1.1, local AS number 65001
Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down  State/PfxRcd
2.2.2.2         4 65002     100     101      5   0    0 1d02h              8
192.0.2.3       4 65003       0       0      1   0    0 00:04:31       Active""",
})


def _ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return str(address) if address.version == 4 else ""


def parse_status(outputs: dict[str, str]) -> BgpStatus:
    """Parse the common IOS/FRR BGP summary table without inventing missing state."""
    output = outputs.get("summary", "")
    warnings: list[str] = []
    if not output.strip() or command_error(output):
        return BgpStatus(None, None, None, (), False, (
            "BGP summary was unsupported, not permitted, or returned no output.",
        ))
    inactive = bool(re.search(
        r"(?im)(?:BGP|routing process).*(?:not configured|not enabled|not running|does not exist)",
        output,
    ))
    identity = re.search(
        r"(?im)BGP router identifier\s+(\d{1,3}(?:\.\d{1,3}){3}),\s*local AS number\s+(\d+)",
        output,
    )
    router_id = _ipv4(identity.group(1)) if identity else None
    local_as = int(identity.group(2)) if identity else None
    neighbors: list[BgpNeighbor] = []
    unparsed_rows = 0
    in_table = False
    for line in output.splitlines():
        if re.search(r"(?i)^\s*Neighbor\s+.*Up/Down\s+State/PfxRcd", line):
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        parts = line.split()
        address = _ipv4(parts[0]) if parts else ""
        if not address:
            continue
        if len(parts) < 4:
            unparsed_rows += 1
            continue
        try:
            remote_as = int(parts[2])
        except (ValueError, IndexError):
            remote_as = None
        up_down = parts[-2]
        state_value = parts[-1]
        prefixes = int(state_value) if state_value.isdigit() else None
        state = "Established" if prefixes is not None else state_value
        neighbors.append(BgpNeighbor(
            neighbor=address, remote_as=remote_as, state=state,
            established=prefixes is not None, up_down=up_down,
            prefixes_received=prefixes,
        ))
    if unparsed_rows:
        warnings.append(f"{unparsed_rows} BGP neighbor row(s) could not be parsed.")
    if not inactive and not identity and not in_table:
        warnings.append("BGP output was returned, but its summary format was not recognized.")
    running = False if inactive else True if identity or in_table else None
    return BgpStatus(
        router_id, local_as, running, tuple(neighbors),
        running is not None and not warnings, tuple(warnings),
    )
