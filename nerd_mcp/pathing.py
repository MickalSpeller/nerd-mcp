"""Compatibility exports for application-owned MAC path inference."""

from .application.pathing import MacPathWorkflow
from .domain.ports import InventoryReader
from .mac import MacService
from .topology import TopologyService


class MacPathService(MacPathWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryReader, mock: bool = False,
                 mac_service=None, topology_service=None):
        compatibility_mac = mac_service or MacService(inventory, mock)
        super().__init__(
            inventory, mock, compatibility_mac,
            topology_service or TopologyService(
                inventory, mock, compatibility_mac
            ),
        )
