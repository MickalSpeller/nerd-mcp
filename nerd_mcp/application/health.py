"""Collect ordered fleet health results without presentation or persistence."""

from ..domain.errors import InventoryError
from ..domain.ports import InventoryReader, NetworkPort


class FleetHealthService:
    def __init__(self, inventory: InventoryReader, network: NetworkPort):
        self.inventory = inventory
        self.network = network

    def check(self, target: str) -> list[dict]:
        names = ([d.name for d in self.inventory.list()]
                 if target.casefold() == "all" else [target])
        if not names:
            raise InventoryError("No devices are inventoried.")
        return [self.network.health(name) for name in names]
