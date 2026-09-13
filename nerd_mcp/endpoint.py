"""Compatibility exports for application-owned endpoint resolution."""

from .application.endpoint import EndpointWorkflow, MAX_MAC_CANDIDATES
from .domain.ports import InventoryReader
from .mac import MacService
from .pathing import MacPathService


class EndpointService(EndpointWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryReader, mock: bool = False,
                 mac_service=None, path_service=None):
        compatibility_mac = mac_service or MacService(inventory, mock)
        super().__init__(
            inventory, mock, compatibility_mac,
            path_service or MacPathService(
                inventory, mock, compatibility_mac
            ),
        )
