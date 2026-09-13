"""Pure parsing shared by vendor observation adapters."""

from dataclasses import asdict
import ipaddress
import re

from ..domain.models import (
    ArpObservation,
    InterfaceHealthObservation,
    MacObservation,
    NeighborObservation,
    ObservationBatch,
)
from ..domain.normalization import (
    IPV4_RE,
    MAC_RE,
    interface_key,
    normalize_mac,
    safe_address,
    safe_label,
    valid_interface,
)
from ..domain.errors import InventoryError


MAX_MAC_ENTRIES_PER_DEVICE = 50000


def _mac_in_line(line: str):
    match = MAC_RE.search(line)
    if not match:
        return None
    try:
        return normalize_mac(match.group()), match
    except InventoryError:
        return None


def parse_macs(output: str, family: str) -> tuple[MacObservation, ...]:
    entries = []
    for line in output.splitlines():
        found = _mac_in_line(line)
        if not found:
            continue
        mac, match = found
        before = line[:match.start()].split()
        after = line[match.end():].split()
        vlan = ""
        interface = ""
        entry_type = "dynamic"
        if family in {"cisco_ios", "cisco_nxos", "aruba_aoscx"}:
            vlan = next((token for token in reversed(before) if token.isdigit()), "")
            type_index = next((index for index, token in enumerate(after)
                               if token.casefold() in {"dynamic", "static", "secure", "system", "self"}), None)
            if type_index is not None:
                entry_type = after[type_index].casefold()
            candidates = after[(type_index + 1) if type_index is not None else 0:]
            interface = valid_interface(candidates[-1]) if candidates else ""
        elif family == "aruba_osswitch":
            interface = valid_interface(after[0]) if after else ""
            vlan = next((token for token in reversed(after[1:]) if token.isdigit()), "")
        elif family == "fortinet":
            interface = valid_interface(before[-1]) if before else ""
            attributes = " ".join(after[1:]).casefold() if after else ""
            entry_type = "static" if "static" in attributes or "local" in attributes else "dynamic"
        if not interface or interface.casefold() in {"ports", "port", "interface"}:
            continue
        entries.append(MacObservation(mac, vlan, interface, entry_type))
        if len(entries) > MAX_MAC_ENTRIES_PER_DEVICE:
            raise InventoryError(
                f"MAC table exceeds the per-device limit of {MAX_MAC_ENTRIES_PER_DEVICE} entries."
            )
    return tuple(entries)


def parse_arps(output: str) -> tuple[ArpObservation, ...]:
    entries = []
    for line in output.splitlines():
        found = _mac_in_line(line)
        ip_match = IPV4_RE.search(line)
        if not found or not ip_match:
            continue
        try:
            ip = str(ipaddress.ip_address(ip_match.group()))
        except ValueError:
            continue
        mac, mac_match = found
        after = line[mac_match.end():].split()
        interface = valid_interface(after[-1]) if after else ""
        if interface.casefold() in {"arpa", "dynamic", "static"}:
            interface = ""
        entries.append(ArpObservation(mac, ip, interface))
    return tuple(entries)


def _parse_neighbors(output: str, protocol: str) -> tuple[NeighborObservation, ...]:
    records = []
    current = {}
    in_remote_management = False

    def flush():
        nonlocal current
        if current.get("interface") and (current.get("neighbor") or current.get("neighbor_address")):
            records.append(NeighborObservation(
                current["interface"],
                current.get("neighbor") or current.get("neighbor_address", ""),
                current.get("neighbor_address", ""),
                current.get("remote_interface", ""),
                protocol,
            ))
        current = {}

    for line in output.splitlines():
        if re.match(r"^\s*-{5,}\s*$", line):
            flush()
            in_remote_management = False
            continue
        if re.match(r"(?i)^\s*Remote Management Address\s*$", line):
            in_remote_management = True
            continue
        name = re.search(
            r"(?i)^\s*(?:Device ID|System Name|SysName|Neighbor Chassis-Name)\s*:\s*(\S+)", line
        )
        if name:
            if current.get("neighbor") and current.get("interface"):
                flush()
            current["neighbor"] = safe_label(name.group(1))
        local = re.search(
            r"(?i)^\s*(?:Interface|Local (?:Port|Intf|Interface)|Port)\s*:\s*([^,\s]+)", line
        )
        if local:
            if current.get("interface") and current.get("neighbor"):
                flush()
            current["interface"] = valid_interface(local.group(1))
        remote = re.search(
            r"(?i)(?:Port ID \(outgoing port\)|Remote (?:Port|Intf|Interface)|"
            r"Neighbor Port-ID|PortId|Port id)\s*:\s*([^,\s]+)", line
        )
        if remote:
            current["remote_interface"] = valid_interface(remote.group(1))
        address = re.search(
            r"(?i)^\s*(?:IP(?:v4)? address|Management Address|"
            r"Neighbor Management-Address)\s*:\s*([^\s,]+)", line
        )
        if not address and in_remote_management:
            address = re.search(r"(?i)^\s*Address\s*:\s*([^\s,]+)", line)
        if address:
            current["neighbor_address"] = safe_address(address.group(1))
            in_remote_management = False
    flush()
    return tuple(records)


def parse_uplink_observations(outputs: dict[str, str], family: str):
    uplinks = set()
    neighbors = []
    for line in outputs.get("trunks", "").splitlines():
        parts = line.split()
        if not parts:
            continue
        candidate = valid_interface(parts[0])
        if candidate and ("trunk" in line.casefold() or family.startswith("aruba")):
            uplinks.add(candidate)
    for line in outputs.get("port_channels", "").splitlines():
        for token in re.findall(r"(?:Po|Port-channel|Gi|Te|Fa|Eth)\S+", line, re.IGNORECASE):
            candidate = valid_interface(re.sub(r"\([^)]*\)$", "", token))
            if candidate:
                uplinks.add(candidate)
    for protocol in ("cdp", "lldp"):
        for neighbor in _parse_neighbors(outputs.get(protocol, ""), protocol):
            uplinks.add(neighbor.interface)
            neighbors.append(neighbor)
    return frozenset(uplinks), tuple(neighbors)


def parse_interface_health_observations(output: str):
    records = []
    current = None
    for line in output.splitlines():
        heading = re.match(r"^(\S+) is ([^,]+), line protocol is (\S+)", line, re.IGNORECASE)
        if heading:
            interface = valid_interface(heading.group(1))
            current = {
                "interface": interface,
                "status": heading.group(2).strip(),
                "protocol": heading.group(3).strip(),
                "description": "", "input_errors": 0, "crc_errors": 0,
                "output_errors": 0, "speed": "", "duplex": "",
            }
            if interface:
                records.append(current)
            continue
        if current is None:
            continue
        description = re.search(r"(?i)^\s*Description:\s*(.+)$", line)
        if description:
            current["description"] = description.group(1).strip()[:200]
        duplex_speed = re.search(
            r"(?i)\b((?:half|full|auto)[ -]?duplex)\b.*?\b(\d+(?:\.\d+)?\s*[KMG]b/s)\b", line
        )
        if duplex_speed:
            current["duplex"], current["speed"] = duplex_speed.group(1), duplex_speed.group(2)
        for field, pattern in (
            ("input_errors", r"\b(\d+)\s+input errors\b"),
            ("crc_errors", r"\b(\d+)\s+CRC\b"),
            ("output_errors", r"\b(\d+)\s+output errors\b"),
        ):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                current[field] = int(match.group(1))
    return tuple(InterfaceHealthObservation(**record) for record in records)


def parse_batch(outputs: dict[str, str], family: str) -> ObservationBatch:
    uplinks, neighbors = parse_uplink_observations(outputs, family)
    return ObservationBatch(
        macs=parse_macs(outputs.get("mac", ""), family),
        arps=parse_arps(outputs.get("arp", "")),
        neighbors=neighbors,
        interfaces=parse_interface_health_observations(outputs.get("interfaces", "")),
        uplinks=uplinks,
    )


# Compatibility serializers retained for existing callers and tests.
def legacy_macs(output: str, family: str):
    return [
        {key: value for key, value in asdict(row).items() if key != "role"}
        for row in parse_macs(output, family)
    ]


def legacy_arps(output: str):
    return [asdict(row) for row in parse_arps(output)]


def legacy_uplinks(outputs: dict[str, str], family: str):
    uplinks, neighbors = parse_uplink_observations(outputs, family)
    return set(uplinks), [asdict(row) for row in neighbors]


def legacy_interface_health(output: str):
    return [asdict(row) for row in parse_interface_health_observations(output)]
