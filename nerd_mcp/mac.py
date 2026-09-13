"""Compatibility exports for the application-owned MAC workflow."""

from netmiko import ConnectHandler

from .application.mac import MacWorkflow as _ApplicationMacWorkflow
from .domain.inventory import Device
from .domain.normalization import interface_key as _interface_key
from .domain.normalization import normalize_interface, normalize_mac
from .domain.ports import DeviceTransportPort, InventoryPort, ObservationRepositoryPort
from .storage.observations_sqlite import ObservationRepository
from .transport.errors import safe_device_error
from .transport.netmiko import NetmikoTransport
from .vendors.commands import command_error
from .vendors.observations import (
    legacy_arps as parse_arp_table,
    legacy_interface_health as parse_interface_health,
    legacy_macs as parse_mac_table,
    legacy_uplinks as parse_uplinks,
)
from .vendors.registry import (
    CAPABILITIES,
    ObservationAdapter as Adapter,
)
from .vendors.cisco import observations as cisco_observations
from .vendors.aruba.aoscx import collector as aoscx_observations
from .vendors.aruba.aosswitch import collector as aosswitch_observations
from .vendors.fortinet.fortios import observations as fortinet_observations

MAX_COMMAND_OUTPUT_CHARS = 5_000_000
CISCO_COMMANDS = cisco_observations.COMMANDS
ARUBA_CX_COMMANDS = aoscx_observations.COMMANDS
ARUBA_OS_COMMANDS = aosswitch_observations.COMMANDS
FORTINET_COMMANDS = fortinet_observations.COMMANDS
MOCK_CISCO_OUTPUTS = cisco_observations.MOCK_OUTPUTS
MOCK_ARUBA_CX_OUTPUTS = aoscx_observations.MOCK_OUTPUTS
MOCK_ARUBA_OS_OUTPUTS = aosswitch_observations.MOCK_OUTPUTS
MOCK_FORTINET_OUTPUTS = fortinet_observations.MOCK_OUTPUTS
MacIndex = ObservationRepository


def adapter_for(device: Device) -> Adapter | None:
    return CAPABILITIES.observation_adapter_for(device)


class MacWorkflow(_ApplicationMacWorkflow):
    """Historical constructor over the application-owned workflow."""

    def __init__(self, inventory: InventoryPort, mock: bool,
                 repository: ObservationRepositoryPort,
                 transport: DeviceTransportPort, capability_provider=CAPABILITIES):
        super().__init__(
            inventory, mock, repository, transport, capability_provider,
            safe_device_error, command_error, MAX_COMMAND_OUTPUT_CHARS,
        )


class MacService(MacWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryPort, mock: bool = False, connector=None,
                 connection_pool=None,
                 repository: ObservationRepositoryPort | None = None,
                 transport: DeviceTransportPort | None = None):
        self.connector = connector or ConnectHandler
        self.connection_pool = connection_pool
        super().__init__(
            inventory, mock, repository or MacIndex(inventory),
            transport or NetmikoTransport(self.connector, self.connection_pool),
        )
