"""Shared NERD errors with no adapter or infrastructure dependencies."""


class NerdError(ValueError):
    """Base class for errors that can be reported safely to an operator."""


class InventoryError(NerdError):
    """Inventory input, lookup, or supported-operation error."""


class UnsupportedCapability(InventoryError):
    """The selected device platform does not support an operation."""


class MissingBaselineError(InventoryError):
    """A requested configuration baseline does not exist."""
