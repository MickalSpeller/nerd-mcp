"""Fixed IOS health commands and pure operational-output parsing."""

import re

from ....domain.health import assess_health, cpu_severity, finding, memory_severity
from ....domain.models import HealthFinding, HealthMetrics
from ...commands import command_error


COMMANDS = {
    "version": "show version",
    "interfaces": "show ip interface brief",
    "interface_counters": "show interfaces",
    "routes": "show ip route",
    "ospf_neighbors": "show ip ospf neighbor",
    "bgp_summary": "show ip bgp summary",
    "cpu": "show processes cpu sorted",
    "memory": "show processes memory sorted",
}

MOCK_OUTPUTS = {
    "version": "mock-device uptime is 2 weeks\nLast reload reason: Reload Command",
    "interfaces": (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet1/0/1    192.0.2.1       YES manual up                    up\n"
        "GigabitEthernet1/0/2    unassigned      YES unset  administratively down down"
    ),
    "interface_counters": (
        "GigabitEthernet1/0/1 is up, line protocol is up\n"
        "  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n"
        "  0 output errors, 0 collisions, 0 interface resets\n"
        "GigabitEthernet1/0/2 is administratively down, line protocol is down\n"
        "  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n"
        "  0 output errors, 0 collisions, 0 interface resets"
    ),
    "routes": (
        "Gateway of last resort is 192.0.2.254 to network 0.0.0.0\n"
        "S* 0.0.0.0/0 [1/0] via 192.0.2.254\n"
        "C  192.0.2.0/24 is directly connected, GigabitEthernet1/0/1"
    ),
    "ospf_neighbors": (
        "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
        "192.0.2.2         1   FULL/DR         00:00:34    192.0.2.2       GigabitEthernet1/0/1"
    ),
    "bgp_summary": (
        "BGP router identifier 192.0.2.1, local AS number 65001\n"
        "Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down  State/PfxRcd\n"
        "192.0.2.2       4 65002     100     100      5   0    0 1d02h              8"
    ),
    "cpu": "CPU utilization for five seconds: 5%/1%; one minute: 4%; five minutes: 3%",
    "memory": "Processor Pool Total: 100000000 Used: 40000000 Free: 60000000",
}


def _compact_names(names: list[str], limit: int = 10) -> str:
    shown = names[:limit]
    suffix = f" and {len(names) - limit} more" if len(names) > limit else ""
    return ", ".join(shown) + suffix


def parse_health(outputs: dict[str, str], device_type: str = ""):
    """Parse IOS output into a typed assessment without transport concerns."""
    checks: list[HealthFinding] = []
    metrics: dict[str, object] = {
        "interfaces_total": None,
        "interfaces_up": None,
        "interfaces_down": None,
        "interfaces_admin_down": None,
        "routes": None,
        "default_route": None,
        "ospf_neighbors": None,
        "ospf_not_full": None,
        "bgp_neighbors": None,
        "bgp_not_established": None,
        "cpu_five_minute_percent": None,
        "memory_free_percent": None,
        "uptime": None,
    }

    def unavailable(key: str, category: str) -> bool:
        output = outputs.get(key, "")
        inactive_protocol = (
            key == "ospf_neighbors"
            and re.search(r"(?im)^\s*%.*OSPF.*(?:not enabled|not running|not active)", output)
        ) or (
            key == "bgp_summary"
            and re.search(r"(?im)^\s*%.*BGP.*(?:not enabled|not running|not active)", output)
        )
        if not output.strip() or command_error(output) or inactive_protocol:
            checks.append(finding(
                f"{key}_unavailable", category, "info",
                f"{COMMANDS[key]} was unsupported, not permitted, or returned no output.",
            ))
            return True
        return False

    if not unavailable("version", "system"):
        uptime = re.search(r"(?im)^\S+\s+uptime is\s+(.+?)\s*$", outputs["version"])
        if uptime:
            metrics["uptime"] = uptime.group(1).strip()
            checks.append(finding("uptime", "system", "ok", f"Device uptime is {metrics['uptime']}."))
        else:
            checks.append(finding(
                "version_unparsed", "system", "info",
                "Version output was returned but device uptime was not recognized.",
            ))

    if not unavailable("interfaces", "interfaces"):
        interfaces = []
        for line in outputs["interfaces"].splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0].casefold() == "interface":
                continue
            if parts[2].casefold() not in {"yes", "no", "nvrm"}:
                continue
            interfaces.append((parts[0], " ".join(parts[4:-1]).casefold(), parts[-1].casefold()))
        if interfaces:
            admin_down = [name for name, state, _protocol in interfaces if "administratively" in state]
            mismatched = [name for name, state, protocol in interfaces if (state == "up") != (protocol == "up")]
            down = [name for name, state, _protocol in interfaces if state != "up" and "administratively" not in state]
            up = [name for name, state, protocol in interfaces if state == "up" and protocol == "up"]
            metrics.update({
                "interfaces_total": len(interfaces),
                "interfaces_up": len(up),
                "interfaces_down": len(down),
                "interfaces_admin_down": len(admin_down),
            })
            checks.append(finding(
                "interface_summary", "interfaces", "ok",
                f"{len(up)} of {len(interfaces)} IP interfaces are up/up; {len(admin_down)} are administratively down.",
            ))
            if mismatched:
                checks.append(finding(
                    "interface_protocol_mismatch", "interfaces", "critical",
                    "Interface and line-protocol states disagree: " + _compact_names(mismatched) + ".",
                ))
            if down:
                checks.append(finding(
                    "interfaces_down", "interfaces", "warning",
                    "Interfaces are operationally down without an administrative shutdown: "
                    + _compact_names(down) + ".",
                ))
        else:
            checks.append(finding(
                "interfaces_unparsed", "interfaces", "info",
                "Interface state output was returned but its format was not recognized.",
            ))

    if not unavailable("interface_counters", "interfaces"):
        current = ""
        affected: dict[str, int] = {}
        totals = {"input errors": 0, "CRC": 0, "output errors": 0}
        for line in outputs["interface_counters"].splitlines():
            heading = re.match(r"^(\S+) is .+?, line protocol is\s+\S+", line, re.IGNORECASE)
            if heading:
                current = heading.group(1)
                continue
            for label, pattern in (
                ("input errors", r"\b(\d+)\s+input errors\b"),
                ("CRC", r"\b(\d+)\s+CRC\b"),
                ("output errors", r"\b(\d+)\s+output errors\b"),
            ):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    value = int(match.group(1))
                    totals[label] += value
                    if current and value:
                        affected[current] = affected.get(current, 0) + value
        if any(totals.values()):
            checks.append(finding(
                "interface_errors", "interfaces", "warning",
                "Nonzero cumulative interface errors were found on "
                + (_compact_names(sorted(affected)) or "one or more interfaces")
                + f" (input {totals['input errors']}, CRC {totals['CRC']}, output {totals['output errors']}).",
            ))
        elif re.search(r"\b(?:input|output) errors\b", outputs["interface_counters"], re.IGNORECASE):
            checks.append(finding(
                "interface_errors", "interfaces", "ok",
                "No interface input, CRC, or output errors were reported.",
            ))
        else:
            checks.append(finding(
                "interface_counters_unparsed", "interfaces", "info",
                "Interface counters were returned but their format was not recognized.",
            ))

    if not unavailable("routes", "routing"):
        route_lines = [line for line in outputs["routes"].splitlines() if re.match(
            r"^\s*(?:[A-Z][A-Z0-9*+ ]*|L|C|S|R|M|B|D|O|E|i|o)\s+\d{1,3}(?:\.\d{1,3}){3}/\d+\b",
            line,
        )]
        has_default = bool(re.search(r"(?m)^\s*\S.*\b0\.0\.0\.0/0\b", outputs["routes"]))
        no_default = bool(re.search(r"(?im)^Gateway of last resort is not set", outputs["routes"]))
        metrics["routes"] = len(route_lines)
        metrics["default_route"] = has_default if has_default or no_default else None
        if not route_lines:
            checks.append(finding(
                "routing_table", "routing", "warning",
                "No IPv4 routes were recognized in the default routing table.",
            ))
        else:
            checks.append(finding("routing_table", "routing", "ok", f"{len(route_lines)} IPv4 routes were recognized."))
        if no_default and device_type.casefold() in {"router", "firewall"}:
            checks.append(finding(
                "default_route", "routing", "warning",
                f"No default IPv4 route is installed on this inventoried {device_type.casefold()}.",
            ))
        elif no_default:
            checks.append(finding("default_route", "routing", "info", "No default IPv4 route is installed."))
        elif has_default:
            checks.append(finding("default_route", "routing", "ok", "A default IPv4 route is installed."))

    if not unavailable("ospf_neighbors", "routing protocols"):
        neighbors = []
        for line in outputs["ospf_neighbors"].splitlines():
            parts = line.split()
            if len(parts) >= 6 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]):
                neighbors.append((parts[0], parts[2]))
        metrics["ospf_neighbors"] = len(neighbors)
        not_full = [neighbor for neighbor, state in neighbors if not state.upper().startswith("FULL")]
        metrics["ospf_not_full"] = len(not_full)
        if not_full:
            checks.append(finding(
                "ospf_neighbors", "routing protocols", "critical",
                "OSPF neighbors are not FULL: " + _compact_names(not_full) + ".",
            ))
        elif neighbors:
            checks.append(finding(
                "ospf_neighbors", "routing protocols", "ok",
                f"All {len(neighbors)} OSPF neighbors are FULL.",
            ))
        else:
            checks.append(finding(
                "ospf_neighbors_unparsed", "routing protocols", "info",
                "No OSPF neighbor rows were recognized; no expected-neighbor baseline is configured.",
            ))

    if not unavailable("bgp_summary", "routing protocols"):
        peers = []
        for line in outputs["bgp_summary"].splitlines():
            parts = line.split()
            if len(parts) >= 9 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]):
                peers.append((parts[0], parts[-1]))
        metrics["bgp_neighbors"] = len(peers)
        down = [neighbor for neighbor, state in peers if not state.isdigit()]
        metrics["bgp_not_established"] = len(down)
        if down:
            checks.append(finding(
                "bgp_neighbors", "routing protocols", "critical",
                "BGP peers are not established: " + _compact_names(down) + ".",
            ))
        elif peers:
            checks.append(finding(
                "bgp_neighbors", "routing protocols", "ok",
                f"All {len(peers)} BGP peers are established.",
            ))
        else:
            checks.append(finding(
                "bgp_summary_unparsed", "routing protocols", "info",
                "No BGP peer rows were recognized; no expected-peer baseline is configured.",
            ))

    if not unavailable("cpu", "resources"):
        cpu = re.search(
            r"CPU utilization for five seconds:\s*(\d+)%/\d+%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
            outputs["cpu"], re.IGNORECASE,
        )
        if cpu:
            five_seconds, one_minute, five_minutes = map(int, cpu.groups())
            metrics["cpu_five_minute_percent"] = five_minutes
            checks.append(finding(
                "cpu", "resources", cpu_severity(five_minutes),
                f"CPU utilization is {five_seconds}% (5 sec), {one_minute}% (1 min), and {five_minutes}% (5 min).",
            ))
        else:
            checks.append(finding(
                "cpu_unparsed", "resources", "info",
                "CPU output was returned but its summary was not recognized.",
            ))

    if not unavailable("memory", "resources"):
        memory = re.search(
            r"Processor Pool Total:\s*([\d,]+)\s+Used:\s*([\d,]+)\s+Free:\s*([\d,]+)",
            outputs["memory"], re.IGNORECASE,
        )
        if memory:
            total, _used, free = (int(value.replace(",", "")) for value in memory.groups())
            if not total:
                checks.append(finding(
                    "memory_unparsed", "resources", "info", "Memory output reported an invalid zero total.",
                ))
                memory = None
            else:
                free_percent = round((free / total) * 100, 1)
        if memory:
            metrics["memory_free_percent"] = free_percent
            checks.append(finding(
                "memory", "resources", memory_severity(free_percent),
                f"Processor memory is {free_percent:.1f}% free.",
            ))
        elif not any(check.id == "memory_unparsed" for check in checks):
            checks.append(finding(
                "memory_unparsed", "resources", "info",
                "Memory output was returned but its summary was not recognized.",
            ))

    return assess_health(HealthMetrics(**metrics), checks, tuple(metrics))
