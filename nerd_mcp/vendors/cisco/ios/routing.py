"""Cisco IOS/IOS-XE route and detailed OSPF evidence parsing."""

from __future__ import annotations

import ipaddress
import re
from types import MappingProxyType

from ....domain.models import (
    OspfDatabaseEvidence,
    OspfNeighbor,
    OspfNeighborDetail,
    OspfProcess,
    OspfStatus,
    RouteDetail,
    RouteNextHop,
)
from ...commands import command_error


ROUTE_COMMAND = "show ip route {destination}"
NEIGHBOR_COMMAND = "show ip ospf neighbor detail"
DATABASE_COMMAND = "show ip ospf database {kind} {key}"
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"

MOCK_ROUTE_OUTPUT = """Routing entry for 2.2.2.2/32
  Known via "ospf 1", distance 110, metric 11, type intra area
  Last update from 192.0.2.2 on GigabitEthernet1/0/1, 00:00:12 ago
  Routing Descriptor Blocks:
  * 192.0.2.2, from 2.2.2.2, 00:00:12 ago, via GigabitEthernet1/0/1
      Route metric is 11, traffic share count is 1"""
MOCK_OSPF_NEIGHBORS = """Neighbor 2.2.2.2, interface address 192.0.2.2
    In the area 0 via interface GigabitEthernet1/0/1
    Neighbor priority is 1, State is FULL, 6 state changes"""
MOCK_OSPF_DATABASE = """OSPF Router with ID (1.1.1.1) (Process ID 1)
            Router Link States (Area 0)
  LS age: 100
  LS Type: Router Links
  Link State ID: 2.2.2.2
  Advertising Router: 2.2.2.2"""


def valid_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return str(address) if address.version == 4 else ""


def _safe_interface(value: str) -> str:
    value = value.strip().strip(",")
    return value if re.fullmatch(r"[A-Za-z0-9_.:/-]{1,96}", value) else ""


def _safe_evidence(line: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", line).strip()[:500]


def parse_route_detail(output: str, destination: str) -> dict[str, object]:
    result: dict[str, object] = {
        "found": False, "prefix": "", "protocol": "", "distance": None,
        "metric": None, "route_type": "", "next_hops": [],
        "route_source_router_ids": [], "evidence": [],
    }
    if re.search(r"(?im)(?:network|subnet|route).*(?:not in table|not found)", output):
        return result
    entry = re.search(r"(?im)^\s*Routing entry for\s+(\S+)", output)
    if entry:
        result["found"] = True
        result["prefix"] = entry.group(1).rstrip(",")
        result["evidence"].append(_safe_evidence(entry.group(0)))
    known = re.search(
        r'(?im)^\s*Known via\s+"([^"]+)"(?:,\s*distance\s+(\d+))?'
        r'(?:,\s*metric\s+(\d+))?(?:,\s*type\s+([^\r\n]+))?',
        output,
    )
    if known:
        result["protocol"] = known.group(1).strip()
        result["distance"] = int(known.group(2)) if known.group(2) else None
        result["metric"] = int(known.group(3)) if known.group(3) else None
        result["route_type"] = (known.group(4) or "").strip()
        result["evidence"].append(_safe_evidence(known.group(0)))

    next_hops: list[dict[str, object]] = []
    source_ids: set[str] = set()
    descriptor = re.compile(
        rf"(?im)^\s*\*?\s*({IPV4_PATTERN})(?:,\s*from\s+({IPV4_PATTERN}))?"
        rf"[^\r\n]*?,\s*via\s+([A-Za-z0-9_.:/-]+)"
    )
    for match in descriptor.finditer(output):
        address = valid_ipv4(match.group(1))
        source = valid_ipv4(match.group(2) or "")
        interface = _safe_interface(match.group(3))
        if not address or not interface:
            continue
        next_hops.append({
            "address": address, "interface": interface,
            "route_source_router_id": source or None,
        })
        if source and source != "0.0.0.0":
            source_ids.add(source)
        result["evidence"].append(_safe_evidence(match.group(0)))

    if not next_hops:
        compact = re.compile(
            rf"(?im)^\s*(O(?:\s+(?:IA|E1|E2|N1|N2|EX))?)[*\s]+(\S+)\s+"
            rf"\[(\d+)/(\d+)\]\s+via\s+({IPV4_PATTERN})(?:,.*?,\s*([A-Za-z0-9_.:/-]+))?"
        )
        for match in compact.finditer(output):
            address = valid_ipv4(match.group(5))
            interface = _safe_interface(match.group(6) or "")
            if not address:
                continue
            result.update({
                "found": True, "prefix": match.group(2).rstrip(","),
                "protocol": match.group(1).strip(),
                "distance": int(match.group(3)), "metric": int(match.group(4)),
            })
            next_hops.append({
                "address": address, "interface": interface,
                "route_source_router_id": None,
            })
            result["evidence"].append(_safe_evidence(match.group(0)))

    if not result["found"] and re.search(
        rf"(?m)^.*\b{re.escape(destination)}(?:/\d+)?\b", output
    ):
        result["found"] = True
        result["prefix"] = destination
    result["next_hops"] = next_hops
    result["route_source_router_ids"] = sorted(
        source_ids, key=ipaddress.ip_address
    )
    result["evidence"] = result["evidence"][:8]
    return result


def parse_ospf_neighbors(output: str) -> list[dict[str, object]]:
    neighbors: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in output.splitlines():
        heading = re.search(
            rf"(?i)^\s*Neighbor\s+({IPV4_PATTERN}),\s*interface address\s+({IPV4_PATTERN})",
            line,
        )
        if heading:
            if current:
                neighbors.append(current)
            current = {
                "router_id": valid_ipv4(heading.group(1)),
                "address": valid_ipv4(heading.group(2)),
                "interface": "", "area": "", "state": "",
            }
            continue
        if current is None:
            continue
        area = re.search(
            r"(?i)In the area\s+(\S+)\s+via interface\s+(\S+)", line
        )
        if area:
            current["area"] = area.group(1).strip(",")
            current["interface"] = _safe_interface(area.group(2))
        state = re.search(r"(?i)\bState is\s+([^,\s]+)", line)
        if state:
            current["state"] = state.group(1)
    if current:
        neighbors.append(current)

    if neighbors:
        return [row for row in neighbors if row["router_id"] and row["address"]]
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        router_id = valid_ipv4(parts[0])
        address = valid_ipv4(parts[-2])
        interface = _safe_interface(parts[-1])
        if router_id and address and interface:
            neighbors.append({
                "router_id": router_id, "address": address,
                "interface": interface, "area": "", "state": parts[2],
            })
    return neighbors


def parse_database_router(
    output: str, expected_router_id: str
) -> dict[str, object]:
    advertising = sorted({
        address for value in re.findall(
            rf"(?im)^\s*Advertising Router\s*:\s*({IPV4_PATTERN})", output
        ) if (address := valid_ipv4(value))
    }, key=ipaddress.ip_address)
    link_state_ids = sorted({
        address for value in re.findall(
            rf"(?im)^\s*Link State ID\s*:\s*({IPV4_PATTERN})", output
        ) if (address := valid_ipv4(value))
    }, key=ipaddress.ip_address)
    return {
        "verified": (
            expected_router_id in advertising
            or expected_router_id in link_state_ids
        ),
        "advertising_router_ids": advertising,
        "link_state_ids": link_state_ids,
    }


def parse_route_detail_model(output: str, destination: str) -> RouteDetail:
    parsed = parse_route_detail(output, destination)
    return RouteDetail(
        found=bool(parsed["found"]), prefix=str(parsed["prefix"]),
        protocol=str(parsed["protocol"]), distance=parsed["distance"],
        metric=parsed["metric"], route_type=str(parsed["route_type"]),
        next_hops=tuple(RouteNextHop(**row) for row in parsed["next_hops"]),
        route_source_router_ids=tuple(parsed["route_source_router_ids"]),
        evidence=tuple(parsed["evidence"]),
    )


def parse_ospf_neighbors_model(
    output: str,
) -> tuple[OspfNeighborDetail, ...]:
    return tuple(OspfNeighborDetail(**row) for row in parse_ospf_neighbors(output))


def parse_database_router_model(
    output: str, expected_router_id: str
) -> OspfDatabaseEvidence:
    parsed = parse_database_router(output, expected_router_id)
    return OspfDatabaseEvidence(
        verified=bool(parsed["verified"]),
        advertising_router_ids=tuple(parsed["advertising_router_ids"]),
        link_state_ids=tuple(parsed["link_state_ids"]),
    )
STATUS_COMMANDS = MappingProxyType({
    "process": "show ip ospf",
    "neighbors": "show ip ospf neighbor",
})
MOCK_STATUS = MappingProxyType({
    "process": 'Routing Process "ospf 1" with ID 192.0.2.1\nSupports only single TOS(TOS0) routes',
    "neighbors": "1.1.1.1 1 FULL/DR 00:00:31 192.0.2.2 GigabitEthernet1/0/1",
})


def parse_status(outputs: dict[str, str]) -> OspfStatus:
    """Parse IOS-style OSPF process and adjacency output."""
    process_output = outputs.get("process", "")
    neighbor_output = outputs.get("neighbors", "")
    warnings: list[str] = []
    inactive = bool(re.search(
        r"(?im)(?:%\s*)?(?:OSPF|routing process).*\b(?:not enabled|not running|not active|does not exist)\b",
        process_output,
    ))
    process_error = not process_output.strip() or command_error(process_output)
    processes = tuple(
        OspfProcess(match.group(1), match.group(2))
        for match in re.finditer(
            r'(?im)^\s*Routing Process\s+"ospf\s+([^"\s]+)"\s+with ID\s+(\S+)',
            process_output,
        )
    )
    if inactive:
        running: bool | None = False
    elif process_error:
        running = None
        warnings.append("show ip ospf was unsupported, not permitted, or returned no output.")
    elif processes:
        running = True
    else:
        running = True
        warnings.append("OSPF output was returned, but process details were not recognized.")

    neighbors: list[OspfNeighbor] = []
    neighbor_error = bool(neighbor_output.strip() and command_error(neighbor_output))
    if neighbor_error:
        warnings.append("show ip ospf neighbor was unsupported or not permitted.")
    else:
        for line in neighbor_output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]):
                neighbors.append(OspfNeighbor(
                    neighbor_id=parts[0], state=parts[2],
                    address=parts[-2], interface=parts[-1],
                ))
    return OspfStatus(
        running=running, processes=processes, neighbors=tuple(neighbors),
        complete=running is not None and not warnings and not neighbor_error,
        warnings=tuple(warnings),
    )
