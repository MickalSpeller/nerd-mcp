"""Compatibility imports for inventory domain types and SQLite storage."""

from .domain.errors import InventoryError
from .domain.inventory import Device, valid_host
from .storage.inventory_sqlite import (
    Inventory,
    InventoryRepository,
)

__all__ = ["Device", "Inventory", "InventoryError", "InventoryRepository", "valid_host"]
