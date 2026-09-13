"""Fixed vendor commands and pure fact/interface parsers."""
import re
import ipaddress
from ....domain.models import Interface


COMMANDS = {
    "get_device_info": "show version",
    "get_interfaces": "show ip interface brief",
    "get_vlans": "show vlan brief",
    "get_routes": "show ip route",
    "get_neighbors": "show cdp neighbors detail",
}

DISCOVERY_COMMANDS = {
    "hostname": "show running-config | include ^hostname",
    "inventory": "show inventory",
    "location": "show running-config | include ^snmp-server location",
    "version": "show version",
}

MOCK_OUTPUTS = {
    "get_device_info": "Cisco IOS XE Software, Version 17.09.04\nMock device uptime is 2 weeks",
    "get_interfaces": "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet1/0/1    192.0.2.1       YES manual up                    up\nGigabitEthernet1/0/2    unassigned      YES unset  administratively down down",
    "get_vlans": "VLAN Name                             Status    Ports\n1    default                          active    Gi1/0/1\n10   USERS                            active    Gi1/0/2",
    "get_routes": "Gateway of last resort is 192.0.2.254 to network 0.0.0.0\nS* 0.0.0.0/0 [1/0] via 192.0.2.254\nC  192.0.2.0/24 is directly connected, GigabitEthernet1/0/1",
    "get_neighbors": "Device ID: mock-neighbor\nIP address: 192.0.2.2\nPlatform: cisco C9300, Capabilities: Switch\nInterface: GigabitEthernet1/0/1, Port ID (outgoing port): GigabitEthernet1/0/24",
}

MOCK_DISCOVERY = {
    "hostname": "hostname mock-device",
    "inventory": 'NAME: "Chassis", DESCR: "Cisco Catalyst 9300"\nPID: C9300-24T, VID: V02, SN: FOC1234ABCD',
    "location": "snmp-server location Example Lab",
    "version": "mock-device uptime is 2 weeks\nProcessor board ID FOC1234ABCD",
}

def parse_device_facts(outputs: dict[str, str]) -> dict[str, str]:
    """Parse primary chassis identity and configured location from fixed Cisco output."""
    facts = {"device_hostname": "", "serial_number": "", "model": "", "location": ""}
    hostname = re.search(r"(?im)^hostname\s+(\S+)\s*$", outputs.get("hostname", ""))
    if not hostname:
        hostname = re.search(r"(?im)^(\S+)\s+uptime is\b", outputs.get("version", ""))
    if hostname:
        facts["device_hostname"] = hostname.group(1)

    location = re.search(
        r"(?im)^snmp-server\s+location\s+(.+?)\s*$", outputs.get("location", "")
    )
    if location:
        facts["location"] = location.group(1).strip()

    entries = []
    pattern = re.compile(
        r'NAME:\s*"(?P<name>[^"]*)",\s*DESCR:\s*"(?P<description>[^"]*)"'
        r'.*?PID:\s*(?P<model>[^,\r\n]*),\s*VID:[^,\r\n]*,\s*SN:\s*(?P<serial>\S*)',
        re.IGNORECASE | re.DOTALL,
    )
    for order, match in enumerate(pattern.finditer(outputs.get("inventory", ""))):
        values = {key: match.group(key).strip() for key in ("name", "description", "model", "serial")}
        if not values["model"] and not values["serial"]:
            continue
        label = f"{values['name']} {values['description']}".lower()
        priority = 3 if "chassis" in label else 2 if re.search(r"\bswitch\s*1\b", label) else 1
        entries.append((priority, -order, values))
    if entries:
        values = max(entries)[2]
        facts["model"], facts["serial_number"] = values["model"], values["serial"]

    version = outputs.get("version", "")
    if not facts["serial_number"]:
        serial = re.search(r"(?im)^Processor board ID\s+(\S+)", version)
        if serial:
            facts["serial_number"] = serial.group(1)
    if not facts["model"]:
        model = re.search(r"(?im)^Model [Nn]umber\s*:\s*(\S+)", version)
        if not model:
            model = re.search(r"(?im)^cisco\s+(\S+)\s+.*processor", version)
        if model:
            facts["model"] = model.group(1)
    return facts

parse_facts = parse_device_facts


def parse_interfaces(output):
    """Parse IOS brief rows conservatively, retaining unassigned interfaces."""
    rows, warnings = [], []
    recognized = False
    for line in output.splitlines():
        parts = line.split()
        if not parts or line.startswith("[MOCK DATA"):
            continue
        if parts[0] == "Interface" and "IP-Address" in parts:
            recognized = True
            continue
        if len(parts) < 6 or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,96}", parts[0]):
            warnings.append("Some interface output was not recognized.")
            continue
        address, unassigned = None, parts[1].casefold() == "unassigned"
        if not unassigned:
            try:
                address = str(ipaddress.IPv4Address(parts[1]))
            except ValueError:
                unassigned = None
                warnings.append("An interface address was not recognized.")
        rows.append(Interface(parts[0], address, " ".join(parts[4:-1]), parts[-1], unassigned))
        recognized = True
    if not recognized:
        warnings.append("Interface output was empty or unrecognized.")
    return tuple(rows), tuple(dict.fromkeys(warnings))


def parse_interface_addresses(output):
    """Compatibility parser for existing routing callers."""
    addresses = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        interface = parts[0].strip().strip(",")
        if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,96}", interface):
            continue
        try:
            address = str(ipaddress.IPv4Address(parts[1]))
        except ValueError:
            continue
        addresses.append({"interface": interface, "address": address,
                          "status": " ".join(parts[4:-1]) if len(parts) >= 6 else "",
                          "protocol": parts[-1] if len(parts) >= 6 else ""})
    return addresses
MOCK_CONFIG = """version 17.9
hostname mock-device
service password-encryption
enable secret 9 mock-enable-secret
username operator privilege 15 secret 9 mock-user-secret
snmp-server community mock-community RO
interface GigabitEthernet1/0/1
 description Uplink
 ip address 192.0.2.1 255.255.255.0
 no shutdown
router ospf 1
 network 192.0.2.0 0.0.0.255 area 0
line vty 0 4
 password 7 mock-line-password
 login
end"""
