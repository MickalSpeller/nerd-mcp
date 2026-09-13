"""Compatibility exports for application-owned configuration baselines."""

from .application.baseline_workflow import (
    BASELINE_PAGE_CHARS as _DEFAULT_BASELINE_PAGE_CHARS,
    DEFAULT_BASELINE_MAX_AGE_DAYS,
    DIFF_PAGE_CHARS as _DEFAULT_DIFF_PAGE_CHARS,
    MAX_BASELINE_CHARS as _DEFAULT_MAX_BASELINE_CHARS,
    VOLATILE_CONFIGURATION_LINES,
    ConfigurationBaselineWorkflow as _ApplicationConfigurationBaselineWorkflow,
    normalize_configuration,
)
from .domain.errors import InventoryError, MissingBaselineError
from .domain.ports import BaselineRepositoryPort, InventoryPort, NetworkPort
from .network import Network
from .storage.baselines_sqlite import BaselineRepository
from .transport.errors import safe_device_error

BASELINE_PAGE_CHARS = _DEFAULT_BASELINE_PAGE_CHARS
DIFF_PAGE_CHARS = _DEFAULT_DIFF_PAGE_CHARS
MAX_BASELINE_CHARS = _DEFAULT_MAX_BASELINE_CHARS


class ConfigurationBaselineWorkflow(_ApplicationConfigurationBaselineWorkflow):
    """Historical constructor over the application-owned workflow."""

    def __init__(self, inventory: InventoryPort, mock: bool,
                 network: NetworkPort, repository: BaselineRepositoryPort):
        super().__init__(
            inventory, mock, network, repository, safe_device_error,
            BASELINE_PAGE_CHARS, DIFF_PAGE_CHARS, MAX_BASELINE_CHARS,
        )


class ConfigurationBaselines(ConfigurationBaselineWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryPort, mock: bool = False,
                 network: NetworkPort | None = None,
                 repository: BaselineRepositoryPort | None = None):
        super().__init__(
            inventory, mock, network or Network(inventory, mock),
            repository or BaselineRepository(inventory),
        )
