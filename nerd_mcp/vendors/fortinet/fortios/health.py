"""Fixed FortiOS health commands and pure operational-output parsing."""

import re

from ....domain.health import assess_health, cpu_severity, finding, memory_severity
from ....domain.models import HealthFinding, HealthMetrics
from .collector import MOCK_FORTIOS_OUTPUTS


COMMANDS = {
    "version": "get system status",
    "interfaces": "get system interface physical",
    "interface_counters": "diagnose netlink interface list",
    "routes": "get router info routing-table all",
    "ospf_neighbors": "get router info ospf neighbor",
    "bgp_summary": "get router info bgp summary",
    "performance": "get system performance status",
}

MOCK_OUTPUTS = {
    "version": MOCK_FORTIOS_OUTPUTS["get_device_info"],
    "interfaces": MOCK_FORTIOS_OUTPUTS["get_interfaces"],
    "interface_counters": "if=port1 state=up rx_errors=0 tx_errors=0",
    "routes": MOCK_FORTIOS_OUTPUTS["get_routes"],
    "ospf_neighbors": (
        "Neighbor ID Pri State Dead Time Address Interface\n"
        "192.0.2.2 1 Full/DR 00:00:35 192.0.2.2 port1"
    ),
    "bgp_summary": (
        "Neighbor V AS MsgRcvd MsgSent Up/Down State/PfxRcd\n"
        "198.51.100.2 4 65002 100 100 1d02h 8"
    ),
    "performance": (
        "Uptime: 3 days, 2 hours and 1 minutes\n"
        "CPU states: 5% user 2% system 0% nice 93% idle\n"
        "Memory: 4096MB total, 2048MB used (50.0%), 2048MB free (50.0%)"
    ),
}


def parse_health(outputs: dict[str, str], device_type: str = ""):
    """Parse FortiOS output into a typed assessment without transport concerns."""
    del device_type
    checks: list[HealthFinding] = []
    metrics: dict[str, object] = {
        "interfaces_total": None,
        "interfaces_up": None,
        "interfaces_down": None,
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
    status = outputs.get("version", "")
    performance = outputs.get("performance", "")
    uptime = re.search(r"(?im)^(?:System uptime|Uptime):\s*(.+)$", status + "\n" + performance)
    if uptime:
        metrics["uptime"] = uptime.group(1).strip()
        checks.append(finding("uptime", "system", "ok", f"Device uptime is {metrics['uptime']}."))
    else:
        checks.append(finding(
            "version_unparsed", "system", "info",
            "System status returned without a recognized uptime.",
        ))

    interface_output = outputs.get("interfaces", "")
    interfaces = re.findall(r"(?im)^== \[\s*([^\]]+)\s*\]", interface_output)
    up = len(re.findall(r"(?im)\bstatus:\s*up\b", interface_output))
    if interfaces:
        metrics.update({
            "interfaces_total": len(interfaces),
            "interfaces_up": up,
            "interfaces_down": max(0, len(interfaces) - up),
        })
        severity = "warning" if len(interfaces) - up else "ok"
        checks.append(finding(
            "interface_summary", "interfaces", severity,
            f"{up} of {len(interfaces)} physical interfaces are up.",
        ))
    else:
        checks.append(finding(
            "interfaces_unparsed", "interfaces", "info",
            "Physical interface output was not recognized.",
        ))

    routes = [
        line for line in outputs.get("routes", "").splitlines()
        if re.match(r"^\s*[A-Z][A-Z* ]*\s+\d{1,3}(?:\.\d{1,3}){3}/\d+", line)
    ]
    if routes:
        has_default = any(re.search(r"\b0\.0\.0\.0/0\b", line) for line in routes)
        metrics.update({"routes": len(routes), "default_route": has_default})
        checks.append(finding(
            "routing_table", "routing", "ok", f"{len(routes)} IPv4 routes were recognized.",
        ))
        checks.append(finding(
            "default_route", "routing", "ok" if has_default else "warning",
            "A default IPv4 route is installed." if has_default else "No default IPv4 route is installed.",
        ))
    else:
        checks.append(finding(
            "routes_unparsed", "routing", "info", "Routing-table output was not recognized.",
        ))

    ospf_rows = []
    for line in outputs.get("ospf_neighbors", "").splitlines():
        parts = line.split()
        if len(parts) >= 6 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]):
            ospf_rows.append(parts)
    metrics["ospf_neighbors"] = len(ospf_rows)
    metrics["ospf_not_full"] = sum(not row[2].casefold().startswith("full") for row in ospf_rows)
    checks.append(finding(
        "ospf_neighbors", "routing protocols",
        "critical" if metrics["ospf_not_full"] else "ok",
        f"{len(ospf_rows)} OSPF neighbors were recognized.",
    ))

    bgp_rows = [
        line.split() for line in outputs.get("bgp_summary", "").splitlines()
        if re.match(r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+", line)
    ]
    metrics["bgp_neighbors"] = len(bgp_rows)
    metrics["bgp_not_established"] = sum(not row[-1].isdigit() for row in bgp_rows)
    checks.append(finding(
        "bgp_neighbors", "routing protocols",
        "critical" if metrics["bgp_not_established"] else "ok",
        f"{len(bgp_rows)} BGP peers were recognized.",
    ))

    cpu = re.search(r"(?i)CPU states:\s*(\d+)% user\s+(\d+)% system", performance)
    if cpu:
        used = sum(map(int, cpu.groups()))
        metrics["cpu_five_minute_percent"] = used
        checks.append(finding(
            "cpu", "resources", cpu_severity(used),
            f"Current CPU utilization is approximately {used}%.",
        ))
    else:
        checks.append(finding("cpu_unparsed", "resources", "info", "CPU output was not recognized."))

    memory = re.search(r"(?i)\bfree\s*\((\d+(?:\.\d+)?)%\)", performance)
    if memory:
        free = float(memory.group(1))
        metrics["memory_free_percent"] = free
        checks.append(finding(
            "memory", "resources", memory_severity(free),
            f"System memory is {free:.1f}% free.",
        ))
    else:
        checks.append(finding(
            "memory_unparsed", "resources", "info", "Memory output was not recognized.",
        ))

    return assess_health(HealthMetrics(**metrics), checks, tuple(metrics))
