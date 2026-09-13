"""Fixed vendor commands and pure fact/interface parsers."""
import re
import ipaddress
from types import MappingProxyType

from ....domain.models import Interface
from ....domain.models import OspfNeighbor, OspfProcess, OspfStatus
from ...commands import command_error


FORTIOS_COMMANDS = {
    "get_device_info": "get system status",
    "get_interfaces": "get system interface physical",
    "get_vlans": "show system interface",
    "get_routes": "get router info routing-table all",
    "get_neighbors": "diagnose lldprx neighbor summary",
}

FORTIOS_DISCOVERY_COMMANDS = {
    "global": "show system global",
    "status": "get system status",
}

MOCK_FORTIOS_OUTPUTS = {
    "get_device_info": "Version: FortiGate-100F v7.4.4\nSerial-Number: FG100FTK00000001\nHostname: mock-fortigate",
    "get_interfaces": "== [ port1 ]\nname: port1   mode: static   ip: 192.0.2.1 255.255.255.0   status: up",
    "get_vlans": 'config system interface\n    edit "VLAN10"\n        set interface "port1"\n        set vlanid 10\n    next\nend',
    "get_routes": "S*      0.0.0.0/0 [10/0] via 192.0.2.254, port1\nC       192.0.2.0/24 is directly connected, port1",
    "get_neighbors": "port1  mock-switch  00:11:22:33:44:55",
}

MOCK_FORTIOS_DISCOVERY = {
    "global": 'config system global\n    set hostname "mock-fortigate"\n    set location "Example Lab"\nend',
    "status": "Version: FortiGate-100F v7.4.4\nSerial-Number: FG100FTK00000001\nHostname: mock-fortigate",
}

def parse_fortios_device_facts(outputs: dict[str, str]) -> dict[str, str]:
    """Parse FortiOS system status and global configuration identity fields."""
    combined = "\n".join(outputs.values())
    facts = {"device_hostname": "", "serial_number": "", "model": "", "location": ""}
    hostname = re.search(r'(?im)^\s*(?:Hostname:\s*|set hostname\s+")([^"\r\n]+)', combined)
    serial = re.search(r"(?im)^\s*Serial-Number:\s*(\S+)", combined)
    version = re.search(r"(?im)^\s*Version:\s*FortiGate-([^\s]+)", combined)
    location = re.search(r'(?im)^\s*set location\s+"?([^"\r\n]+)', combined)
    if hostname:
        facts["device_hostname"] = hostname.group(1).strip()
    if serial:
        facts["serial_number"] = serial.group(1).strip()
    if version:
        facts["model"] = "FortiGate-" + version.group(1).split("-v", 1)[0]
    if location:
        facts["location"] = location.group(1).strip()
    return facts

parse_facts = parse_fortios_device_facts


COMMANDS = FORTIOS_COMMANDS
DISCOVERY_COMMANDS = FORTIOS_DISCOVERY_COMMANDS
MOCK_OUTPUTS = MOCK_FORTIOS_OUTPUTS
MOCK_DISCOVERY = MOCK_FORTIOS_DISCOVERY


def parse_interfaces(output):
    """Parse physical interface blocks; absent fields remain unknown."""
    rows, warnings = [], []
    blocks = re.split(r"(?m)^== \[\s*([^\]]+?)\s*\]\s*$", output)
    if len(blocks) == 1:
        return (), ("Interface output was empty or unrecognized.",)
    for index in range(1, len(blocks), 2):
        name, body = blocks[index].strip(), blocks[index + 1]
        if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,96}", name):
            warnings.append("An interface name was not recognized.")
            continue
        ip = re.search(r"\bip:\s*(\S+)", body)
        status = re.search(r"\bstatus:\s*(\S+)", body)
        address, unassigned = None, None
        if ip:
            try:
                address = str(ipaddress.IPv4Address(ip.group(1)))
                unassigned = address == "0.0.0.0"
                if unassigned:
                    address = None
            except ValueError:
                warnings.append("An interface address was not recognized.")
        if not ip or not status:
            warnings.append("Some interface fields were not returned.")
        rows.append(Interface(name, address, status.group(1) if status else None, None, unassigned))
    return tuple(rows), tuple(dict.fromkeys(warnings))
MOCK_CONFIG = 'config system global\n    set hostname "mock-fortigate"\nend\nconfig system admin\n    edit "admin"\n        set password ENC mock-secret\n    next\nend'
OSPF_STATUS_COMMANDS = MappingProxyType({
    "process": "get router info ospf status",
    "neighbors": "get router info ospf neighbor",
})
MOCK_OSPF_STATUS = MappingProxyType({
    "process": 'Routing Process "ospf 0" with ID 192.0.2.1',
    "neighbors": "1.1.1.1 1 FULL/DR 00:00:31 192.0.2.2 port1",
})


def parse_ospf_status(outputs: dict[str, str]) -> OspfStatus:
    """Parse the FortiOS OSPF status shape used by the read-only workflow."""
    process_output = outputs.get("process", "")
    neighbor_output = outputs.get("neighbors", "")
    warnings: list[str] = []
    inactive = bool(re.search(
        r"(?im)(?:OSPF|routing process).*\b(?:not enabled|not running|not active|does not exist)\b",
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
