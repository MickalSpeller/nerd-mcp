"""Collect and persist inventory facts through injected dependencies."""

from dataclasses import asdict

from ..domain.ports import InventoryPort, NetworkPort


class InventoryRefreshService:
    def __init__(self, inventory: InventoryPort, network: NetworkPort):
        self.inventory = inventory
        self.network = network
        self.successful_discoveries = 0

    def refresh(self, target: str) -> list[dict]:
        """Refresh sequentially, retaining failures and existing write semantics.

        successful_discoveries describes the current call even if persistence
        raises, allowing adapters to report collection provenance accurately.
        """
        self.successful_discoveries = 0
        names = ([d.name for d in self.inventory.list()]
                 if target.casefold() == "all" else [target])
        results = []
        for name in names:
            discovered = self.network.discover_inventory(name)
            if discovered["status"] == "success":
                self.successful_discoveries += 1
                discovered["record"] = asdict(
                    self.inventory.update_facts(name, discovered["facts"])
                )
            results.append(discovered)
        return results
