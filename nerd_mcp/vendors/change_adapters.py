"""Deterministic, fail-closed configuration adapters.

Adapters accept typed desired-state operations only.  They deliberately do not
offer an escape hatch for arbitrary CLI text.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from ..domain.changes import CHANGE_KINDS, ChangeOperation, VerificationCheck
from ..domain.errors import InventoryError


SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()@+-]{0,126}$")
BLOCKED_INTERFACES = re.compile(r"(?i)^(?:mgmt|management|oob|wan-management)")
SECRET_WORDS = re.compile(
    r"(?i)\b(?:password|secret|community|private-key|pre-shared|psk|token|aaa|tacacs|radius)\b"
)

COMMON_KINDS = CHANGE_KINDS
OPERATION_FIELDS = {
    "interface_description": {"interface", "description", "present"},
    "interface_admin": {"interface", "enabled"},
    "interface_ipv4": {"interface", "address", "prefix_length", "present"},
    "interface_delete": {"interface"},
    "vlan": {"vlan_id", "name", "present"},
    "access_vlan": {"interface", "vlan_id", "present"},
    "static_route": {"prefix", "next_hop", "present"},
    "ospf_network": {"process_id", "network", "area", "present"},
    "ospf_interface": {"interface", "process_id", "area", "present"},
    "bgp_neighbor": {"local_as", "neighbor", "remote_as", "update_source", "present"},
    "bgp_network": {"local_as", "prefix", "present"},
    "bgp_interface_network": {"interface", "present"},
    "acl_rule": {"acl_name", "sequence", "action", "protocol", "source", "destination", "present"},
    "acl_attach": {"interface", "acl_name", "direction", "present"},
    "ntp_server": {"address", "present"},
    "dns_server": {"address", "present"},
    "syslog_server": {"address", "present"},
}


def _required(values: dict[str, Any], *names: str) -> None:
    missing = [name for name in names if name not in values]
    if missing:
        raise InventoryError("Missing change value(s): " + ", ".join(missing))


def _name(value: Any, label: str) -> str:
    text = str(value).strip()
    if not SAFE_NAME.fullmatch(text) or SECRET_WORDS.search(text):
        raise InventoryError(f"Invalid or unsafe {label}.")
    return text


def _text(value: Any, label: str) -> str:
    text = str(value).strip()
    if not SAFE_TEXT.fullmatch(text) or SECRET_WORDS.search(text):
        raise InventoryError(f"Invalid or unsafe {label}.")
    return text


def _interface(value: Any) -> str:
    interface = _name(value, "interface")
    if BLOCKED_INTERFACES.match(interface):
        raise InventoryError("Management and out-of-band interfaces cannot be changed.")
    return interface


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise InventoryError("Invalid IP address in change operation.") from exc


def _network(value: Any) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value), strict=False)
    except ValueError as exc:
        raise InventoryError("Invalid IPv4 network in change operation.") from exc
    if network.version != 4:
        raise InventoryError("Only IPv4 configuration changes are currently supported.")
    return network


def _integer(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise InventoryError(f"Invalid {label}.")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryError(f"Invalid {label}.") from exc
    if not low <= number <= high:
        raise InventoryError(f"{label} must be between {low} and {high}.")
    return number


def _present(values: dict[str, Any]) -> bool:
    value = values.get("present", True)
    if not isinstance(value, bool):
        raise InventoryError("present must be true or false.")
    return value


@dataclass(frozen=True)
class RenderedOperation:
    commands: tuple[str, ...]
    expected: tuple[str, ...]
    excluded: tuple[str, ...]
    impact: str


@dataclass(frozen=True)
class ChangeAdapter:
    platform: str
    capabilities: frozenset[str]
    preflight_commands: tuple[str, ...]
    save_commands: tuple[str, ...]
    checkpoint_supported: bool
    immediate_persistence: bool = False

    def checkpoint(self, change_id: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        token = re.sub(r"[^A-Za-z0-9_-]", "", change_id)[:24]
        if self.platform == "cisco_ios":
            path = f"flash:nerd-{token}.cfg"
            return ((f"copy running-config {path}",), (f"configure replace {path} force",), (f"delete /force {path}",))
        if self.platform == "cisco_nxos":
            name = f"nerd-{token}"
            return ((f"checkpoint {name}",), (f"rollback running-config checkpoint {name}",), (f"no checkpoint {name}",))
        if self.platform == "aruba_aoscx":
            name = f"nerd-{token}"
            return ((f"checkpoint create {name}",), (f"checkpoint rollback {name}",), (f"checkpoint delete {name}",))
        if self.platform == "aruba_osswitch":
            name = f"nerd-{token}"
            return ((f"copy running-config config {name}",), (f"copy config {name} running-config",), (f"erase config {name}",))
        return ((), (), ())

    def render(self, operation: ChangeOperation) -> RenderedOperation:
        if operation.kind not in self.capabilities:
            raise InventoryError(
                f"{operation.kind} is not supported on platform {self.platform}."
            )
        unexpected = set(operation.values) - OPERATION_FIELDS[operation.kind]
        if unexpected:
            raise InventoryError(
                f"{operation.kind} contains unsupported value(s): "
                + ", ".join(sorted(unexpected))
            )
        if self.platform == "fortinet":
            return _render_fortios(operation)
        return _render_network_cli(operation, self.platform)


def _render_network_cli(op: ChangeOperation, platform: str) -> RenderedOperation:
    v, kind = op.values, op.kind
    present = _present(v)
    expected_override = excluded_override = None
    if kind == "interface_description":
        _required(v, "interface", "description")
        interface, description = _interface(v["interface"]), _text(v["description"], "description")
        line = f"description {description}"
        commands = (f"interface {interface}", line if present else "no description")
    elif kind == "interface_admin":
        _required(v, "interface", "enabled")
        interface = _interface(v["interface"])
        if not isinstance(v["enabled"], bool):
            raise InventoryError("enabled must be true or false.")
        line = "no shutdown" if v["enabled"] else "shutdown"
        commands = (f"interface {interface}", line)
        expected_override = () if v["enabled"] else ("shutdown",)
        excluded_override = ("shutdown",) if v["enabled"] else ()
    elif kind == "interface_ipv4":
        _required(v, "interface", "address", "prefix_length")
        interface = _interface(v["interface"]); address = _ip(v["address"])
        prefix = _integer(v["prefix_length"], "prefix_length", 0, 32)
        mask = str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
        line = f"ip address {address}/{prefix}" if platform == "aruba_aoscx" else f"ip address {address} {mask}"
        commands = (f"interface {interface}", line if present else f"no {line}")
    elif kind == "interface_delete":
        _required(v, "interface")
        interface = _interface(v["interface"])
        if not re.fullmatch(r"(?i)Loopback\d+", interface):
            raise InventoryError("Only numbered Loopback interfaces can currently be deleted.")
        line = f"interface {interface}"
        commands = (f"no {line}",)
        expected_override = ()
        excluded_override = (line,)
    elif kind == "vlan":
        _required(v, "vlan_id")
        vlan = _integer(v["vlan_id"], "vlan_id", 1, 4094)
        if not present:
            commands, line = (f"no vlan {vlan}",), f"vlan {vlan}"
        else:
            commands = (f"vlan {vlan}",)
            if v.get("name"):
                commands += (f"name {_text(v['name'], 'VLAN name')}",)
            line = f"vlan {vlan}"
    elif kind == "access_vlan":
        _required(v, "interface", "vlan_id")
        interface = _interface(v["interface"]); vlan = _integer(v["vlan_id"], "vlan_id", 1, 4094)
        line = f"switchport access vlan {vlan}"
        commands = (f"interface {interface}", "switchport mode access", line if present else f"no {line}")
    elif kind == "static_route":
        _required(v, "prefix", "next_hop")
        network, next_hop = _network(v["prefix"]), _ip(v["next_hop"])
        line = f"ip route {network.network_address} {network.netmask} {next_hop}"
        commands = (line if present else f"no {line}",)
    elif kind == "ospf_network":
        _required(v, "process_id", "network", "area")
        pid = _integer(v["process_id"], "process_id", 1, 65535); network = _network(v["network"])
        area = _integer(v["area"], "area", 0, 4294967295)
        wildcard = str(ipaddress.IPv4Address(int(network.hostmask)))
        line = f"network {network.network_address} {wildcard} area {area}"
        commands = (f"router ospf {pid}", line if present else f"no {line}")
    elif kind == "ospf_interface":
        _required(v, "interface", "process_id", "area")
        interface = _interface(v["interface"]); pid = _integer(v["process_id"], "process_id", 1, 65535)
        area = _integer(v["area"], "area", 0, 4294967295); line = f"ip ospf {pid} area {area}"
        commands = (f"interface {interface}", line if present else f"no {line}")
    elif kind == "bgp_neighbor":
        _required(v, "local_as", "neighbor", "remote_as")
        local_as = _integer(v["local_as"], "local_as", 1, 4294967295); neighbor = _ip(v["neighbor"])
        remote_as = _integer(v["remote_as"], "remote_as", 1, 4294967295)
        line = f"neighbor {neighbor} remote-as {remote_as}"
        update_source = (
            f"neighbor {neighbor} update-source {_interface(v['update_source'])}"
            if v.get("update_source") else None
        )
        if present:
            commands = (f"router bgp {local_as}", line)
            if update_source:
                commands += (update_source,)
            expected_override = tuple(item for item in (line, update_source) if item)
        else:
            commands = (f"router bgp {local_as}", f"no neighbor {neighbor}")
            expected_override = ()
            excluded_override = tuple(item for item in (line, update_source) if item)
    elif kind == "bgp_network":
        _required(v, "local_as", "prefix")
        local_as = _integer(v["local_as"], "local_as", 1, 4294967295); network = _network(v["prefix"])
        line = f"network {network.network_address} mask {network.netmask}"
        commands = (f"router bgp {local_as}", line if present else f"no {line}")
    elif kind == "acl_rule":
        _required(v, "acl_name", "sequence", "action", "protocol", "source", "destination")
        acl = _name(v["acl_name"], "ACL name"); sequence = _integer(v["sequence"], "sequence", 1, 4294967295)
        action = str(v["action"]).casefold(); protocol = _name(v["protocol"], "protocol")
        if action not in {"permit", "deny"}: raise InventoryError("ACL action must be permit or deny.")
        source = _name(v["source"], "ACL source"); destination = _name(v["destination"], "ACL destination")
        line = f"{sequence} {action} {protocol} {source} {destination}"
        commands = (f"ip access-list extended {acl}", line if present else f"no {sequence}")
    elif kind == "acl_attach":
        _required(v, "interface", "acl_name", "direction")
        interface, acl = _interface(v["interface"]), _name(v["acl_name"], "ACL name")
        direction = str(v["direction"]).casefold()
        if direction not in {"in", "out"}: raise InventoryError("ACL direction must be in or out.")
        line = f"ip access-group {acl} {direction}"
        commands = (f"interface {interface}", line if present else f"no {line}")
    elif kind in {"ntp_server", "dns_server", "syslog_server"}:
        _required(v, "address"); address = _ip(v["address"])
        prefix = {"ntp_server": "ntp server", "dns_server": "ip name-server", "syslog_server": "logging host"}[kind]
        line = f"{prefix} {address}"; commands = (line if present else f"no {line}",)
    else:
        raise InventoryError(f"Unsupported change operation: {kind}.")
    expected = expected_override if expected_override is not None else ((line,) if present else ())
    excluded = excluded_override if excluded_override is not None else (() if expected else (line,))
    return RenderedOperation(commands, expected, excluded, kind.replace("_", " "))


def _render_fortios(op: ChangeOperation) -> RenderedOperation:
    # FortiOS is deliberately restricted until a supported transaction is detected.
    v, kind = op.values, op.kind
    present = _present(v)
    if kind in {"ntp_server", "dns_server", "syslog_server"}:
        _required(v, "address"); address = _ip(v["address"])
        section = {"ntp_server": "system ntp", "dns_server": "system dns", "syslog_server": "log syslogd setting"}[kind]
        field = {"ntp_server": "server", "dns_server": "primary", "syslog_server": "server"}[kind]
        commands = (f"config {section}", f"set {field} {address}" if present else f"unset {field}", "end")
        line = f"set {field} {address}"
        return RenderedOperation(commands, (line,) if present else (), () if present else (line,), kind.replace("_", " "))
    raise InventoryError(f"{kind} is not supported by the FortiOS change adapter.")


ADAPTERS = {
    "cisco_ios": ChangeAdapter("cisco_ios", COMMON_KINDS,
        ("show version", "show running-config", "show startup-config"), ("write memory",), True),
    # These platforms remain diagnostic-only until their command, checkpoint,
    # verification, and rollback contracts pass separate live-lab validation.
    "cisco_nxos": ChangeAdapter("cisco_nxos", frozenset(),
        ("show version", "show running-config", "show startup-config"), ("copy running-config startup-config",), True),
    "aruba_aoscx": ChangeAdapter("aruba_aoscx", frozenset(),
        ("show version", "show running-config", "show startup-config"), ("write memory",), True),
    "aruba_osswitch": ChangeAdapter("aruba_osswitch", frozenset(),
        ("show version", "show running-config", "show config"), ("write memory",), True),
    "fortinet": ChangeAdapter("fortinet", frozenset(),
        ("get system status", "show"), (), False, True),
}


def adapter_for_platform(platform) -> ChangeAdapter:
    adapter = ADAPTERS.get(platform.name)
    if adapter is None:
        raise InventoryError("This platform has no configuration change adapter.")
    return adapter
