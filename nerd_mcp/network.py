"""Compatibility exports for application-owned device inspection."""

import logging

from netmiko import ConnectHandler

from .application.inspection import (
    CONFIG_PAGE_CHARS as _DEFAULT_CONFIG_PAGE_CHARS,
    MAX_OUTPUT as _DEFAULT_MAX_OUTPUT,
    NetworkWorkflow as _ApplicationNetworkWorkflow,
    sanitize_configuration,
)
from .application.serialization import bgp_status_legacy, health_legacy, ospf_status_legacy
from .domain.ports import DeviceTransportPort, InventoryReader
from .transport.errors import safe_device_error
from .transport.netmiko import NetmikoTransport
from .vendors.commands import command_error
from .vendors.registry import CAPABILITIES
from .vendors.cisco.ios import collector as ios
from .vendors.cisco.ios import health as ios_health
from .vendors.cisco.ios import routing as ios_routing
from .vendors.cisco.ios import bgp as ios_bgp
from .vendors.fortinet.fortios import collector as fortios
from .vendors.fortinet.fortios import health as fortios_health
from .vendors.fortinet.fortios import vpn as fortios_vpn
from .vendors.fortinet.fortios import bgp as fortios_bgp

COMMANDS = ios.COMMANDS
DISCOVERY_COMMANDS = ios.DISCOVERY_COMMANDS
MOCK_OUTPUTS = ios.MOCK_OUTPUTS
MOCK_DISCOVERY = ios.MOCK_DISCOVERY
FORTIOS_COMMANDS = fortios.COMMANDS
FORTIOS_DISCOVERY_COMMANDS = fortios.DISCOVERY_COMMANDS
MOCK_FORTIOS_OUTPUTS = fortios.MOCK_OUTPUTS
MOCK_FORTIOS_DISCOVERY = fortios.MOCK_DISCOVERY
HEALTH_COMMANDS = ios_health.COMMANDS
MOCK_HEALTH = ios_health.MOCK_OUTPUTS
FORTIOS_HEALTH_COMMANDS = fortios_health.COMMANDS
MOCK_FORTIOS_HEALTH = fortios_health.MOCK_OUTPUTS
CONFIG_COMMANDS = {"running": "show running-config", "startup": "show startup-config"}
FORTIOS_CONFIG_COMMANDS = {"running": "show"}
OSPF_STATUS_COMMANDS = dict(ios_routing.STATUS_COMMANDS)
FORTIOS_OSPF_STATUS_COMMANDS = dict(fortios.OSPF_STATUS_COMMANDS)
MOCK_CONFIG = ios.MOCK_CONFIG
MOCK_FORTIOS_CONFIG = fortios.MOCK_CONFIG
MOCK_OSPF_STATUS = {
    "process": ios_routing.MOCK_STATUS["process"],
    "neighbors": ios_health.MOCK_OUTPUTS["ospf_neighbors"],
}
MOCK_FORTIOS_OSPF_STATUS = {
    "process": fortios.MOCK_OSPF_STATUS["process"],
    "neighbors": fortios_health.MOCK_OUTPUTS["ospf_neighbors"],
}
BGP_STATUS_COMMANDS = dict(ios_bgp.COMMANDS)
MOCK_BGP_STATUS = dict(ios_bgp.MOCK_OUTPUTS)
FORTIOS_BGP_STATUS_COMMANDS = dict(fortios_bgp.COMMANDS)
MOCK_FORTIOS_BGP_STATUS = dict(fortios_bgp.MOCK_OUTPUTS)
MAX_OUTPUT = _DEFAULT_MAX_OUTPUT
CONFIG_PAGE_CHARS = _DEFAULT_CONFIG_PAGE_CHARS
LOG = logging.getLogger("nerd_mcp.operations")

parse_device_facts = ios.parse_device_facts
parse_fortios_device_facts = fortios.parse_fortios_device_facts
parse_ospf_status_model = ios_routing.parse_status


def inspection_family(device):
    return CAPABILITIES.require(device, "inspection").driver


def parse_health_outputs(outputs: dict[str, str], device_type: str = "") -> dict[str, object]:
    return health_legacy(ios_health.parse_health(outputs, device_type))


def parse_fortios_health_outputs(outputs: dict[str, str], device_type: str = "") -> dict[str, object]:
    return health_legacy(fortios_health.parse_health(outputs, device_type))


def parse_ospf_status(outputs: dict[str, str]) -> dict[str, object]:
    parsed = parse_ospf_status_model(outputs)
    return {
        "running": parsed.running,
        "process_count": len(parsed.processes),
        "processes": [
            {"process_id": row.process_id, "router_id": row.router_id}
            for row in parsed.processes
        ],
        "neighbor_count": len(parsed.neighbors),
        "neighbors": [
            {
                "neighbor_id": row.neighbor_id, "state": row.state,
                "address": row.address, "interface": row.interface,
            }
            for row in parsed.neighbors
        ],
        "complete": parsed.complete,
        "warnings": list(parsed.warnings),
    }


class NetworkWorkflow(_ApplicationNetworkWorkflow):
    """Historical constructor over the application-owned workflow."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 transport: DeviceTransportPort, capability_provider=CAPABILITIES):
        super().__init__(
            inventory, mock, transport, capability_provider,
            safe_device_error, command_error, MAX_OUTPUT, CONFIG_PAGE_CHARS,
        )

    def get_configuration(self, name: str, source: str, cursor: int, revision: str):
        self.config_page_chars = CONFIG_PAGE_CHARS
        return super().get_configuration(name, source, cursor, revision)


class Network(NetworkWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryReader, mock: bool = False, connector=None,
                 connection_pool=None,
                 transport: DeviceTransportPort | None = None):
        self.connector = connector or ConnectHandler
        self.connection_pool = connection_pool
        super().__init__(
            inventory, mock,
            transport or NetmikoTransport(
                self.connector, self.connection_pool, LOG
            ),
        )
